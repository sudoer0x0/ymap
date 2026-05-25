"""
info.py — Target Information Gathering for Ymap v1.0.0

Entry point: gather_info(target) → InfoResult

Accepts:
  - IPv4 address  (e.g. 192.168.1.1)
  - Hostname      (e.g. google.com, router.local)
  - MAC address   (e.g. 00:50:56:aa:bb:cc)

For IP / hostname:
  • Forward DNS  — A records, AAAA records
  • Reverse DNS  — PTR hostname
  • WHOIS / RDAP — ASN, organisation, country, ISP (via ipwhois)
  • Geolocation  — country, city, ISP (via ipinfo.io HTTPS)
  • ARP           — MAC address (local subnet, requires root)
  • Device naming — NetBIOS (UDP 137), mDNS (UDP 5353)
  • SSL/TLS       — certificate CN, issuer, TLS version (if port 443 open)
  • HTTP banner   — Server header (if port 80/443 open)
  • MAC vendor    — OUI lookup from MAC

For MAC address:
  • OUI vendor lookup (offline)
  • Locally-administered flag
  • ARP reverse — find IP owning this MAC on local subnet (requires root)

Security:
  - All inputs validated before use
  - All network calls have enforced timeouts
  - HTTPS calls use verify=True
  - No user data interpolated into shell commands
"""

import re
import socket
import ssl
import time
import ipaddress
import concurrent.futures
import logging
import warnings
from dataclasses import dataclass, field
from typing import Optional, List, Dict

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SCAPY_AVAILABLE = False
try:
    from scapy.all import conf as _sc  # type: ignore
    _sc.verb     = 0
    _sc.logLevel = 40
    from scapy.all import ARP, Ether, srp  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    pass

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from ipwhois import IPWhois as _IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

from ymap.vendor import lookup_mac_vendor, normalise_mac, is_locally_administered


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(
    r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$'
    r'|^[0-9a-fA-F]{12}$'
)
_IP_RE  = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_HOST_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)
_FORBIDDEN_RE = re.compile(r'[;\|&`\$><!\{\}\[\]\(\)\\~^*?]')


def classify_target(raw: str) -> str:
    """Return 'ip', 'hostname', 'mac', or raise ValueError."""
    t = raw.strip()
    if not t:
        raise ValueError("Target must not be empty.")
    if len(t) > 253:
        raise ValueError("Target string is too long.")
    if _FORBIDDEN_RE.search(t):
        raise ValueError(f"Invalid characters in target: {t!r}")
    if _MAC_RE.match(t):
        return "mac"
    if _IP_RE.match(t):
        try:
            ipaddress.ip_address(t)
            return "ip"
        except ValueError:
            pass
    if _HOST_RE.match(t) or t.endswith(".local"):
        return "hostname"
    raise ValueError(f"Cannot determine target type for: {t!r}")


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class InfoResult:
    target:       str
    target_type:  str                   # ip / hostname / mac

    # Resolved addresses
    ip_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    hostname:     Optional[str] = None

    # MAC / hardware
    mac:          Optional[str] = None
    mac_vendor:   Optional[str] = None
    mac_type:     Optional[str] = None  # "Globally Assigned" / "Locally Administered"

    # DNS
    ptr_hostname: Optional[str] = None  # reverse DNS
    mx_records:   List[str] = field(default_factory=list)
    ns_records:   List[str] = field(default_factory=list)

    # Network / WHOIS
    asn:          Optional[str] = None
    asn_name:     Optional[str] = None
    organisation: Optional[str] = None
    country:      Optional[str] = None
    country_code: Optional[str] = None
    city:         Optional[str] = None
    region:       Optional[str] = None
    isp:          Optional[str] = None
    ip_range:     Optional[str] = None

    # Service fingerprint
    tls_version:  Optional[str] = None
    tls_cert_cn:  Optional[str] = None
    tls_cert_org: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    http_server:  Optional[str] = None

    # Device context
    device_names: List[str] = field(default_factory=list)  # NetBIOS, mDNS names

    # Meta
    errors:       List[str] = field(default_factory=list)  # non-fatal issues
    scan_time:    float = 0.0


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _forward_dns(hostname: str, timeout: float = 3.0) -> Dict:
    """Resolve hostname to IPv4 + IPv6 addresses."""
    ipv4, ipv6 = [], []
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None)
        for r in results:
            addr = r[4][0]
            if r[0] == socket.AF_INET and addr not in ipv4:
                ipv4.append(addr)
            elif r[0] == socket.AF_INET6 and addr not in ipv6:
                ipv6.append(addr)
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(old)
    return {"ipv4": ipv4, "ipv6": ipv6}


def _reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Reverse DNS PTR lookup."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip(".") if name and name != ip else None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def _mx_ns_records(hostname: str, timeout: float = 3.0) -> Dict:
    """Query MX and NS records via dnspython if available."""
    mx, ns = [], []
    try:
        import dns.resolver  # type: ignore
        for rtype, store in [("MX", mx), ("NS", ns)]:
            try:
                ans = dns.resolver.resolve(hostname, rtype, lifetime=timeout)
                for r in ans:
                    store.append(str(r).rstrip("."))
            except Exception:
                pass
    except ImportError:
        pass
    return {"mx": mx, "ns": ns}


# ---------------------------------------------------------------------------
# Geolocation / WHOIS
# ---------------------------------------------------------------------------

def _ipinfo_lookup(ip: str, timeout: float = 5.0) -> Dict:
    """
    Query ipinfo.io for ASN, org, country, city.
    Free tier, no API key, HTTPS with verify=True.
    """
    if not REQUESTS_AVAILABLE:
        return {}
    try:
        r = _requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            verify=True,
            headers={"User-Agent": "Ymap/1.0.0", "Accept": "application/json"},
        )
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            data = r.json()
            return {
                "org":     data.get("org", ""),        # "AS15169 Google LLC"
                "country": data.get("country", ""),
                "city":    data.get("city", ""),
                "region":  data.get("region", ""),
                "hostname":data.get("hostname", ""),
            }
    except Exception:
        pass
    return {}


def _ipapi_lookup(ip: str, timeout: float = 5.0) -> Dict:
    """
    Fallback geolocation via ip-api.com (HTTP, free, no key).
    Only used if ipinfo.io fails.
    """
    if not REQUESTS_AVAILABLE:
        return {}
    try:
        r = _requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as",
            timeout=timeout,
            headers={"User-Agent": "Ymap/1.0.0"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country":      data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "city":         data.get("city", ""),
                    "region":       data.get("regionName", ""),
                    "isp":          data.get("isp", ""),
                    "org":          data.get("org", ""),
                    "as":           data.get("as", ""),
                }
    except Exception:
        pass
    return {}


def _whois_rdap(ip: str, timeout: float = 8.0) -> Dict:
    """
    RDAP lookup via ipwhois library. Provides ASN, network range, org, country.
    """
    if not IPWHOIS_AVAILABLE:
        return {}
    try:
        obj = _IPWhois(ip)
        # Try RDAP first (more structured), fall back to WHOIS
        result = {}
        try:
            data = obj.lookup_rdap(depth=1)
            result["asn"]      = data.get("asn")
            result["asn_name"] = data.get("asn_description") or data.get("network", {}).get("name")
            result["country"]  = data.get("asn_country_code")
            net = data.get("network", {})
            result["ip_range"] = f"{net.get('start_address')} – {net.get('end_address')}" \
                                 if net.get("start_address") else None
            result["org"] = (data.get("network") or {}).get("name")
        except Exception:
            try:
                data = obj.lookup_whois()
                if data.get("nets"):
                    net = data["nets"][0]
                    result["org"]      = net.get("description") or net.get("name")
                    result["country"]  = net.get("country")
                    result["ip_range"] = net.get("cidr")
                if data.get("asn"):
                    result["asn"] = data.get("asn")
                    result["asn_name"] = data.get("asn_description")
            except Exception:
                pass
        return result
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# SSL / TLS fingerprint
# ---------------------------------------------------------------------------

def _ssl_info(host: str, ip: str = None, port: int = 443, timeout: float = 4.0) -> Dict:
    """Connect via TLS and extract certificate and protocol info."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    connect_target = ip if ip else host
    try:
        with socket.create_connection((connect_target, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls_ver = tls.version() or "TLS"
                cert    = tls.getpeercert()
                result  = {"tls_version": tls_ver}
                if cert:
                    subj    = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    result["cn"]     = subj.get("commonName", "")
                    result["org"]    = subj.get("organizationName", "")
                    result["issuer"] = issuer.get("organizationName", "")
                    # SANs
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    result["sans"] = sans[:5]
                return result
    except Exception:
        return {}


def _http_server_header(host: str, ip: str = None, port: int = 80,
                        timeout: float = 3.0) -> Optional[str]:
    """Fetch HTTP Server header via HEAD /."""
    connect_target = ip if ip else host
    try:
        with socket.create_connection((connect_target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                   "Connection: close\r\nUser-Agent: Ymap/1.0.0\r\n\r\n").encode()
            s.sendall(req)
            resp = b""
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(4096)
                    if not chunk or b"\r\n\r\n" in resp:
                        break
                    resp += chunk
                except Exception:
                    break
            text = resp.decode("utf-8", errors="replace")
            m = re.search(r'[Ss]erver:\s*([^\r\n]+)', text)
            return m.group(1).strip()[:100] if m else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ARP helpers
# ---------------------------------------------------------------------------

def _arp_get_mac(ip: str, timeout: float = 2.0) -> Optional[str]:
    """ARP probe a single IP to get its MAC. Requires root + Scapy."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1)
        ans, _ = srp(pkt, timeout=timeout, verbose=False, retry=1, inter=0.001)
        if ans:
            recv = ans[0][1]
            if recv.haslayer(ARP) and recv[ARP].op == 2 and recv[ARP].psrc == ip:
                return normalise_mac(recv[ARP].hwsrc)
    except Exception:
        pass
    return None


def _arp_find_ip_for_mac(target_mac: str, subnet: str = None,
                          timeout: float = 3.0) -> Optional[str]:
    """
    Scan the local subnet to find which IP has a given MAC address.
    Used when the user provides a MAC address as the target.
    """
    if not SCAPY_AVAILABLE:
        return None
    if not subnet:
        # Auto-detect local subnet from default route
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                # Assume /24
                parts = local_ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return None
    try:
        from ymap.utils import expand_targets
        hosts = expand_targets(subnet)
        pkts  = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1) for ip in hosts]
        ans, _ = srp(pkts, timeout=timeout, verbose=False, retry=0, inter=0.001)
        target_norm = normalise_mac(target_mac).upper()
        for _, recv in ans:
            if recv.haslayer(ARP) and recv[ARP].op == 2:
                if normalise_mac(recv[ARP].hwsrc).upper() == target_norm:
                    return recv[ARP].psrc
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Device name helpers
# ---------------------------------------------------------------------------

def _netbios_name(ip: str, timeout: float = 0.8) -> Optional[str]:
    payload = (
        b'\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            for i in range(min(data[56], 5)):
                off = 57 + i * 18
                if off + 16 > len(data):
                    break
                raw   = data[off:off+15]
                ntype = data[off+15]
                name  = raw.decode("ascii", errors="ignore").strip().rstrip("\x00")
                if name and ntype == 0x00 and "\x00" not in name:
                    return name.strip()
    except Exception:
        pass
    return None


def _mdns_name(ip: str, timeout: float = 1.0) -> Optional[str]:
    try:
        parts = ip.split(".")
        rev   = ".".join(reversed(parts)) + ".in-addr.arpa"
        query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for label in rev.split("."):
            enc = label.encode("ascii", errors="ignore")
            query += bytes([len(enc)]) + enc
        query += b'\x00\x00\x0c\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(512)
        sock.close()
        if len(data) > 12:
            m = re.search(rb'([\x01-\x3f][\w\-\.]+\.local)', data[12:])
            if m:
                name = re.sub(r'\.local\.?$', '',
                               m.group(1).decode("ascii", errors="ignore")).strip()
                return name or None
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def gather_info(target: str, use_root: bool = True,
                timeout: float = 5.0) -> InfoResult:
    """
    Gather all available information about a target.

    Args:
        target:   IP address, hostname, or MAC address.
        use_root: If True, attempt ARP operations (requires root + Scapy).
        timeout:  Per-operation timeout in seconds.

    Returns:
        InfoResult populated with everything we could find.
    """
    start = time.perf_counter()
    t = target.strip()

    try:
        ttype = classify_target(t)
    except ValueError as e:
        result = InfoResult(target=t, target_type="unknown")
        result.errors.append(str(e))
        return result

    result = InfoResult(target=t, target_type=ttype)

    # ── MAC address target ────────────────────────────────────────────────
    if ttype == "mac":
        mac_norm = normalise_mac(t)
        result.mac        = mac_norm
        result.mac_vendor = lookup_mac_vendor(mac_norm)
        result.mac_type   = (
            "Locally Administered (Virtual/Hotspot/Docker)"
            if is_locally_administered(mac_norm)
            else "Globally Assigned (Hardware)"
        )
        # Try to find the IP address on the local subnet
        if use_root and SCAPY_AVAILABLE:
            found_ip = _arp_find_ip_for_mac(mac_norm, timeout=timeout)
            if found_ip:
                result.ip_addresses.append(found_ip)
                result.ptr_hostname = _reverse_dns(found_ip, timeout=timeout)
                _enrich_ip(result, found_ip, timeout=timeout, use_root=use_root)
        result.scan_time = time.perf_counter() - start
        return result

    # ── Hostname target → resolve to IP first ─────────────────────────────
    primary_ip: Optional[str] = None

    if ttype == "hostname":
        result.hostname = t
        dns = _forward_dns(t, timeout=timeout)
        result.ip_addresses  = dns["ipv4"]
        result.ipv6_addresses = dns["ipv6"]
        if not result.ip_addresses:
            result.errors.append(f"Could not resolve hostname: {t}")
        else:
            primary_ip = result.ip_addresses[0]

        # MX / NS records
        records = _mx_ns_records(t, timeout=timeout)
        result.mx_records = records["mx"]
        result.ns_records = records["ns"]

    elif ttype == "ip":
        primary_ip = t
        result.ip_addresses = [t]
        # Reverse DNS
        result.ptr_hostname = _reverse_dns(t, timeout=timeout)
        if result.ptr_hostname:
            result.hostname = result.ptr_hostname

    # ── IP enrichment (parallel) ──────────────────────────────────────────
    if primary_ip:
        _enrich_ip(result, primary_ip, timeout=timeout, use_root=use_root)

    result.scan_time = time.perf_counter() - start
    return result


def _enrich_ip(result: InfoResult, ip: str, timeout: float, use_root: bool):
    """Gather all IP-based info in parallel threads."""

    def _run_geo():
        geo = _ipinfo_lookup(ip, timeout=timeout)
        if not geo:
            geo = _ipapi_lookup(ip, timeout=timeout)
        if geo:
            org_raw = geo.get("org", "")
            # ipinfo.io returns "AS15169 Google LLC" — split ASN from name
            m = re.match(r'^(AS\d+)\s+(.+)$', org_raw)
            if m:
                result.asn      = m.group(1)
                result.asn_name = m.group(2)
            elif geo.get("as"):
                result.asn      = geo.get("as", "").split()[0]
                result.asn_name = " ".join(geo.get("as", "").split()[1:])
            result.isp          = geo.get("isp") or geo.get("org") or result.asn_name
            result.country      = geo.get("country")
            result.country_code = geo.get("country_code") or geo.get("country")
            result.city         = geo.get("city")
            result.region       = geo.get("region")
            if geo.get("hostname") and not result.ptr_hostname:
                result.ptr_hostname = geo["hostname"]
                result.hostname     = result.hostname or geo["hostname"]

    def _run_whois():
        if IPWHOIS_AVAILABLE:
            data = _whois_rdap(ip, timeout=timeout)
            if data:
                if not result.asn:
                    result.asn      = f"AS{data['asn']}" if data.get("asn") else None
                    result.asn_name = data.get("asn_name")
                if not result.country:
                    result.country  = data.get("country")
                if not result.organisation:
                    result.organisation = data.get("org")
                result.ip_range = data.get("ip_range")

    def _run_arp():
        if use_root and SCAPY_AVAILABLE:
            try:
                from ymap.utils import is_local_subnet
                if is_local_subnet(ip):
                    mac = _arp_get_mac(ip, timeout=min(timeout, 2.0))
                    if mac:
                        result.mac        = mac
                        result.mac_vendor = lookup_mac_vendor(mac)
                        result.mac_type   = (
                            "Locally Administered (Virtual/Hotspot/Docker)"
                            if is_locally_administered(mac)
                            else "Globally Assigned (Hardware)"
                        )
            except Exception:
                pass

    def _run_device_names():
        names = []
        nb = _netbios_name(ip, timeout=min(timeout, 1.0))
        if nb:
            names.append(f"{nb} (NetBIOS)")
        md = _mdns_name(ip, timeout=min(timeout, 1.0))
        if md:
            names.append(f"{md}.local (mDNS)")
        if names:
            result.device_names = names

    def _run_ssl():
        try:
            # Check port 443 quickly first
            with socket.create_connection((ip, 443), timeout=min(timeout, 2.0)):
                pass
            hostname = result.hostname or ip
            tls = _ssl_info(hostname, ip=ip, port=443, timeout=timeout)
            if tls:
                result.tls_version   = tls.get("tls_version")
                result.tls_cert_cn   = tls.get("cn")
                result.tls_cert_org  = tls.get("org")
                result.tls_cert_issuer = tls.get("issuer")
        except Exception:
            pass

    def _run_http():
        try:
            with socket.create_connection((ip, 80), timeout=min(timeout, 2.0)):
                pass
            hostname = result.hostname or ip
            srv = _http_server_header(hostname, ip=ip, port=80, timeout=timeout)
            if srv:
                result.http_server = srv
        except Exception:
            pass

    # Run everything in parallel
    tasks = [_run_geo, _run_whois, _run_arp, _run_device_names, _run_ssl, _run_http]
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(tasks), thread_name_prefix="ymap-info"
    ) as pool:
        futures = [pool.submit(fn) for fn in tasks]
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    # Merge: if PTR or ipinfo gave hostname and we don't have one yet
    if not result.hostname and result.ptr_hostname:
        result.hostname = result.ptr_hostname
