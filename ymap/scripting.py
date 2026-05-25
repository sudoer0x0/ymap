"""
scripting.py — CVE / Vulnerability Lookup for Ymap v1.0.0

NVD API key: session-only, never stored to disk, set via --add-nvd-api-key.
All HTTPS traffic uses TLS with certificate verification (verify=True).
"""

import time
import re
import ssl
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Session-only API key
# ---------------------------------------------------------------------------

_SESSION_KEY: Optional[str] = None


def set_session_api_key(key: str) -> None:
    """Store NVD API key for this process only. Never written to disk."""
    global _SESSION_KEY
    key = key.strip()
    if not key:
        raise ValueError("API key must not be empty.")
    if len(key) < 20:
        raise ValueError("API key looks too short. Please check and try again.")
    _SESSION_KEY = key


def get_session_api_key() -> Optional[str]:
    return _SESSION_KEY


def clear_session_api_key() -> None:
    global _SESSION_KEY
    _SESSION_KEY = None


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_SV_FORBIDDEN = re.compile(r'[;\|&`\$><!\{\}\[\]\(\)\\/~^*?]')


def validate_service_version(sv: str) -> str:
    sv = sv.strip()
    if not sv:
        raise ValueError("Service/version string must not be empty.")
    if len(sv) > 120:
        raise ValueError(f"Service/version string too long ({len(sv)} chars, max 120).")
    if _SV_FORBIDDEN.search(sv):
        bad = _SV_FORBIDDEN.search(sv).group()
        raise ValueError(f"Invalid character {bad!r} in service/version input.")
    if not re.search(r'[a-zA-Z]', sv):
        raise ValueError("Service/version must include a service name (letters required).")
    cleaned = re.sub(r'[^a-zA-Z0-9 .\-_]', '', sv)
    if not cleaned:
        raise ValueError("Service/version string is empty after sanitisation.")
    return cleaned


def parse_manual_cve_input(raw: str) -> List[str]:
    """Parse comma/semicolon-separated service version strings. Each is validated."""
    items = re.split(r',', raw)   # only comma — semicolons already rejected by validate
    validated: List[str] = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        validated.append(validate_service_version(item))
    if not validated:
        raise ValueError("No valid service/version entries found in input.")
    return validated


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_version: Optional[str]
    severity: Optional[str]
    url: str = ""

    def __post_init__(self):
        self.url = f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


class CVELookupError(Exception):
    pass


class RateLimitError(CVELookupError):
    """NVD returned HTTP 429."""
    pass


class InvalidKeyError(CVELookupError):
    """NVD returned HTTP 403 (bad/expired key) or returned no data with a key set."""
    pass


class NetworkError(CVELookupError):
    """Network error prevented the lookup."""
    pass


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: Optional[float], version: str = "3") -> str:
    if score is None:
        return "UNKNOWN"
    if version.startswith("2"):
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# NVD API
# ---------------------------------------------------------------------------

_NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT      = 15
_NO_KEY_DELAY = 6.5
_KEY_DELAY    = 0.7
_MAX_RESULTS  = 10
_CACHE_TTL    = 3600

_CACHE: Dict[str, Tuple[float, List[CVEResult]]] = {}
_last_req: float = 0.0

# Track consecutive empty responses when key is set
# NVD sometimes returns 200+empty for invalid keys instead of 403
_consecutive_empty_with_key: int = 0
_EMPTY_KEY_THRESHOLD = 3  # after 3 empty results with a key, warn user


def _parse_response(data: Dict[str, Any]) -> List[CVEResult]:
    out: List[CVEResult] = []
    for vuln in data.get("vulnerabilities", []):
        node  = vuln.get("cve", {})
        cid   = node.get("id", "CVE-????-????")
        desc  = ""
        for d in node.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        desc = desc[:300] + ("…" if len(desc) > 300 else "")
        score: Optional[float] = None
        ver:   Optional[str]   = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = node.get("metrics", {}).get(key, [])
            if entries:
                cd = entries[0].get("cvssData", {})
                raw = cd.get("baseScore")
                if raw is not None:
                    score = float(raw)
                    ver   = cd.get("version", "3.1")
                break
        out.append(CVEResult(
            cve_id=cid, description=desc,
            cvss_score=score, cvss_version=ver,
            severity=_cvss_to_severity(score, ver or "3"),
        ))
    out.sort(key=lambda c: c.cvss_score or 0, reverse=True)
    return out[:_MAX_RESULTS]


def _nvd_request(keyword: str, api_key: Optional[str]) -> List[CVEResult]:
    """
    Make a single NVD API request over HTTPS (TLS verified).
    Raises:
      RateLimitError  — HTTP 429
      InvalidKeyError — HTTP 403 or repeated empty results with key set
      NetworkError    — connection / timeout failures
    Returns empty list for genuine no-results.
    """
    global _last_req, _consecutive_empty_with_key

    if not REQUESTS_AVAILABLE:
        raise NetworkError("requests library not installed.")

    cache_key = keyword.lower().strip()
    if cache_key in _CACHE:
        ts, cached = _CACHE[cache_key]
        if time.time() - ts < _CACHE_TTL:
            return cached

    delay = _KEY_DELAY if api_key else _NO_KEY_DELAY
    wait  = delay - (time.time() - _last_req)
    if wait > 0:
        time.sleep(wait)

    headers: Dict[str, str] = {"User-Agent": "Ymap/1.0.0"}
    if api_key:
        headers["apiKey"] = api_key   # never in URL — always in header

    params: Dict[str, Any] = {
        "keywordSearch":  keyword,
        "resultsPerPage": _MAX_RESULTS,
        "startIndex":     0,
    }

    try:
        resp = _requests.get(
            _NVD_BASE,
            params=params,
            headers=headers,
            timeout=_TIMEOUT,
            verify=True,        # enforce TLS certificate verification — always
        )
        _last_req = time.time()

        if resp.status_code == 403:
            clear_session_api_key()
            raise InvalidKeyError(
                "NVD API key rejected (HTTP 403). "
                "Possible causes:\n"
                "  • The key is invalid or mistyped\n"
                "  • The key is not yet activated (NVD keys take up to 24 hours)\n"
                "  • The key has expired\n"
                "The key has been cleared from this session. "
                "Get a new key at: https://nvd.nist.gov/developers/request-an-api-key"
            )

        if resp.status_code == 429:
            raise RateLimitError(
                "NVD API rate limit reached (HTTP 429). "
                "Free tier: 5 requests / 30 seconds. "
                "Add a free API key with: ymap --add-nvd-api-key  "
                "Get a key at: https://nvd.nist.gov/developers/request-an-api-key"
            )

        if resp.status_code != 200:
            # Other HTTP errors — don't crash, treat as network error
            raise NetworkError(
                f"NVD API returned unexpected status: HTTP {resp.status_code}. "
                "This may be a temporary outage. Please try again later."
            )

        content_type = resp.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            raise NetworkError(
                f"NVD API returned unexpected content type: {content_type!r}. "
                "Expected JSON. This may be a temporary issue."
            )

        data    = resp.json()
        results = _parse_response(data)

        # Detect likely-invalid key: NVD sometimes returns 200 + 0 results 
        # for keys that exist but have no query access (wrong environment, etc.)
        if api_key and not results:
            _consecutive_empty_with_key += 1
            if _consecutive_empty_with_key >= _EMPTY_KEY_THRESHOLD:
                _consecutive_empty_with_key = 0
                raise InvalidKeyError(
                    f"Your NVD API key returned no results for {_consecutive_empty_with_key + _EMPTY_KEY_THRESHOLD} "
                    "consecutive queries. The key may be invalid, inactive, or restricted. "
                    "NVD keys can take up to 24 hours to activate after registration. "
                    "To continue without the key, restart ymap without --add-nvd-api-key. "
                    "Get a verified key at: https://nvd.nist.gov/developers/request-an-api-key"
                )
        else:
            _consecutive_empty_with_key = 0  # reset on any successful result

        _CACHE[cache_key] = (time.time(), results)
        return results

    except (RateLimitError, InvalidKeyError, NetworkError):
        raise   # propagate to caller for proper display
    except _requests.exceptions.SSLError as e:
        raise NetworkError(
            "TLS certificate verification failed for NVD API. "
            "Possible causes:\n"
            "  • Network proxy or VPN intercepting HTTPS traffic\n"
            "  • Corporate firewall performing SSL inspection\n"
            "  • Potential man-in-the-middle attack\n"
            "CVE lookups are disabled until the connection is secure."
        )
    except _requests.exceptions.ConnectionError:
        raise NetworkError(
            "Cannot connect to NVD API (api.nvd.nist.gov). "
            "Possible causes:\n"
            "  • No internet connection\n"
            "  • DNS resolution failure\n"
            "  • NVD API is temporarily down\n"
            "Please check your internet connection and try again."
        )
    except _requests.exceptions.Timeout:
        raise NetworkError(
            f"NVD API request timed out after {_TIMEOUT}s. "
            "The server may be temporarily unavailable. Please try again."
        )
    except Exception as e:
        # Never let unknown errors surface as "no CVEs found"
        raise NetworkError(
            f"Unexpected error during NVD API request: {type(e).__name__}. "
            "Please try again or report this issue."
        )


def _build_keyword(service: str, version: Optional[str], precise: bool) -> str:
    keyword = service.strip()
    if precise and version and version not in ("—", "-", "unknown", "None", ""):
        ver_num = re.sub(r"[^0-9.]", "", version.split()[0])
        if ver_num:
            keyword = f"{keyword} {ver_num}"
    return re.sub(r"[^a-zA-Z0-9 .\-]", "", keyword)[:100]


# ---------------------------------------------------------------------------
# Public lookup functions
# ---------------------------------------------------------------------------

def cve_lookup_broad(service: str, version: Optional[str] = None) -> List[CVEResult]:
    """Broad CVE lookup by service name. Raises CVELookupError subclasses."""
    if not service or service in ("unknown", "-", "—"):
        return []
    keyword = _build_keyword(service, version, precise=False)
    return _nvd_request(keyword, get_session_api_key())


def cve_lookup_precise(service: str, version: str) -> List[CVEResult]:
    """Precise CVE lookup by service + version. Raises CVELookupError subclasses."""
    if not service or service in ("unknown", "-", "—"):
        return []
    if not version or version in ("—", "-", "unknown", "None", ""):
        return []
    keyword = _build_keyword(service, version, precise=True)
    return _nvd_request(keyword, get_session_api_key())


def cve_lookup_manual(service_version: str) -> List[CVEResult]:
    """Manual CVE lookup. service_version must be pre-validated."""
    keyword = re.sub(r"[^a-zA-Z0-9 .\-]", "", service_version)[:100]
    if not keyword:
        return []
    return _nvd_request(keyword, get_session_api_key())


def bulk_cve_lookup(
    services: List[Dict[str, Optional[str]]],
    precise: bool = False,
) -> Dict[str, List[CVEResult]]:
    """
    Run CVE lookups for a list of {service, version} dicts.
    Raises RateLimitError, InvalidKeyError, or NetworkError on problems.
    """
    results: Dict[str, List[CVEResult]] = {}
    for entry in services:
        svc = entry.get("service") or ""
        ver = entry.get("version")
        if not svc or svc == "unknown":
            continue
        key = f"{svc}:{ver}" if (ver and ver not in ("—", "-", "None")) else svc
        if key in results:
            continue
        if precise:
            results[key] = cve_lookup_precise(svc, ver or "")
        else:
            results[key] = cve_lookup_broad(svc, ver)
    return results
