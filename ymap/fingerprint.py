"""
fingerprint.py — Service Version Detection & OS Fingerprinting for Ymap v1.0.0

Version Detection — per-protocol probes:
  SSH        : read protocol banner directly (always sent first)
  HTTP/HTTPS : HEAD request → Server: / X-Powered-By headers; TLS cert CN
  FTP        : read 220 greeting
  SMTP       : read 220 greeting + EHLO response
  POP3/IMAP  : read server greeting
  MySQL      : parse binary handshake packet (version at fixed offset)
  PostgreSQL : startup rejection message contains version
  Redis      : INFO server command → redis_version:
  Memcached  : stats command → STAT version
  Elasticsearch: GET / → JSON version.number
  MongoDB    : ismaster/hello command response
  RDP        : read initial bytes (NegoReq response)
  VNC        : read protocol version string
  SMB        : already used in discovery for OS; version from negotiate

OS Fingerprinting (multi-method, ordered by reliability):
  1. Scapy ICMP TTL       — root + Scapy
  2. subprocess ping TTL  — no root needed
  3. TCP SYN-ACK window   — root + Scapy
"""

import re
import socket
import ssl
import time
import struct
import json
import subprocess
from typing import Optional, List

try:
    from scapy.all import IP, ICMP, TCP, sr1, RandShort  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean(raw: bytes, limit: int = 512) -> str:
    return _CTRL_RE.sub("", raw.decode("utf-8", errors="replace")).strip()[:limit]


# ---------------------------------------------------------------------------
# TLS banner (HTTPS, IMAPS, SMTPS, etc.)
# ---------------------------------------------------------------------------

def _tls_banner(host: str, port: int, timeout: float) -> Optional[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls_ver = tls.version() or "TLS"
                parts   = []
                cert    = tls.getpeercert()
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    cn   = subj.get("commonName", "")
                    if cn:
                        parts.append(cn)
                # Try HTTP HEAD over TLS
                try:
                    tls.settimeout(1.5)
                    tls.sendall(
                        b"HEAD / HTTP/1.1\r\nHost: localhost\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    resp = b""
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline:
                        try:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                            if b"\r\n\r\n" in resp:
                                break
                        except Exception:
                            break
                    text = resp.decode("utf-8", errors="replace")
                    m = re.search(r'[Ss]erver:\s*([^\r\n]+)', text)
                    if m:
                        parts.insert(0, m.group(1).strip()[:80])
                except Exception:
                    pass
                parts.append(tls_ver)
                return " | ".join(parts) if parts else tls_ver
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Protocol-specific version grabbers
# ---------------------------------------------------------------------------

def _grab_ssh(host: str, port: int, timeout: float) -> Optional[str]:
    """SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1  →  OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()
            if banner.startswith("SSH-"):
                parts = banner.split("-", 2)
                if len(parts) >= 3:
                    return parts[2].strip()
    except Exception:
        pass
    return None


def _grab_http(host: str, port: int, timeout: float) -> Optional[str]:
    """HTTP HEAD → Server header (and X-Powered-By fallback)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (
                f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: Ymap/1.0\r\nConnection: close\r\n\r\n"
            ).encode()
            s.sendall(req)
            resp = b""
            deadline = time.monotonic() + min(timeout, 3)
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp:
                        break
                except socket.timeout:
                    break
            text = resp.decode("utf-8", errors="replace")
            m = re.search(r'[Ss]erver:\s*([^\r\n]+)', text)
            if m:
                return m.group(1).strip()[:100]
            m2 = re.search(r'[Xx]-[Pp]owered-[Bb]y:\s*([^\r\n]+)', text)
            if m2:
                return f"Powered-By: {m2.group(1).strip()[:80]}"
    except Exception:
        pass
    return None


def _grab_ftp(host: str, port: int, timeout: float) -> Optional[str]:
    """220 ProFTPD 1.3.6 Server → ProFTPD 1.3.6 Server"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(512)
            banner = data.decode("utf-8", errors="replace").strip()
            m = re.match(r'^2\d\d[- ](.*)', banner)
            if m:
                return m.group(1).strip()[:100]
    except Exception:
        pass
    return None


def _grab_smtp(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            greeting = s.recv(512).decode("utf-8", errors="replace").strip()
            s.sendall(b"EHLO ymap\r\n")
            time.sleep(0.3)
            ehlo = s.recv(1024).decode("utf-8", errors="replace")
            # Extract version from greeting line
            m = re.match(r'^2\d\d[- ](.*)', greeting)
            if m:
                return m.group(1).strip()[:100]
    except Exception:
        pass
    return None


def _grab_pop3(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256).decode("utf-8", errors="replace").strip()
            if data.startswith("+OK"):
                return data[3:].strip()[:100]
    except Exception:
        pass
    return None


def _grab_imap(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256).decode("utf-8", errors="replace").strip()
            if data.startswith("* OK"):
                return data[4:].strip()[:100]
    except Exception:
        pass
    return None


def _grab_mysql(host: str, port: int, timeout: float) -> Optional[str]:
    """
    MySQL/MariaDB sends a greeting packet where:
    bytes 0-3 = packet length + sequence
    byte 4    = protocol version (10 = v10)
    bytes 5+  = null-terminated version string
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            if len(data) >= 6 and data[4] == 0x0a:
                end = data.find(b'\x00', 5)
                if end > 5:
                    ver = data[5:end].decode("ascii", errors="replace")
                    return f"MySQL/MariaDB {ver}"[:100]
    except Exception:
        pass
    return None


def _grab_redis(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"INFO server\r\n")
            data = s.recv(2048).decode("utf-8", errors="replace")
            m = re.search(r'redis_version:([^\r\n]+)', data)
            if m:
                return f"Redis {m.group(1).strip()}"
    except Exception:
        pass
    return None


def _grab_memcached(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"stats\r\n")
            data = s.recv(2048).decode("utf-8", errors="replace")
            m = re.search(r'STAT version ([^\r\n]+)', data)
            if m:
                return f"Memcached {m.group(1).strip()}"
    except Exception:
        pass
    return None


def _grab_elasticsearch(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (
                f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            s.sendall(req)
            resp = b""
            deadline = time.monotonic() + min(timeout, 3)
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                except socket.timeout:
                    break
            text = resp.decode("utf-8", errors="replace")
            # Find JSON body
            idx = text.find("{")
            if idx >= 0:
                try:
                    data = json.loads(text[idx:])
                    ver  = (data.get("version", {}) or {}).get("number")
                    if ver:
                        return f"Elasticsearch {ver}"
                except Exception:
                    pass
    except Exception:
        pass
    return None


def _grab_vnc(host: str, port: int, timeout: float) -> Optional[str]:
    """VNC sends 'RFB 003.008\n' style banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(64).decode("utf-8", errors="replace").strip()
            if data.startswith("RFB"):
                return f"VNC {data}"[:80]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Dispatcher: routes port → correct protocol grabber
# ---------------------------------------------------------------------------

_PORT_GRABBERS = {
    # FTP
    21:    _grab_ftp,
    # SSH
    22:    _grab_ssh,
    2222:  _grab_ssh,
    # SMTP
    25:    _grab_smtp,
    465:   lambda h, p, t: _tls_banner(h, p, t),
    587:   _grab_smtp,
    # HTTP
    80:    _grab_http,
    81:    _grab_http,
    82:    _grab_http,
    8000:  _grab_http,
    8080:  _grab_http,
    8081:  _grab_http,
    8088:  _grab_http,
    8888:  _grab_http,
    9000:  _grab_http,
    9090:  _grab_http,
    # HTTPS (TLS)
    443:   lambda h, p, t: _tls_banner(h, p, t),
    4443:  lambda h, p, t: _tls_banner(h, p, t),
    8443:  lambda h, p, t: _tls_banner(h, p, t),
    # POP3
    110:   _grab_pop3,
    995:   lambda h, p, t: _tls_banner(h, p, t),
    # IMAP
    143:   _grab_imap,
    993:   lambda h, p, t: _tls_banner(h, p, t),
    # MySQL / MariaDB
    3306:  _grab_mysql,
    # Redis
    6379:  _grab_redis,
    # Memcached
    11211: _grab_memcached,
    # Elasticsearch
    9200:  _grab_elasticsearch,
    9201:  _grab_elasticsearch,
    # VNC
    5900:  _grab_vnc,
    5901:  _grab_vnc,
    # LDAP / LDAPS
    636:   lambda h, p, t: _tls_banner(h, p, t),
    # Various HTTPS-adjacent
    5986:  lambda h, p, t: _tls_banner(h, p, t),
    6443:  lambda h, p, t: _tls_banner(h, p, t),
}

# HTTP port ranges that should use _grab_http
_HTTP_PORT_RANGES = [
    range(8000, 8100),
    range(9000, 9010),
]


def _get_grabber(port: int):
    if port in _PORT_GRABBERS:
        return _PORT_GRABBERS[port]
    for r in _HTTP_PORT_RANGES:
        if port in r:
            return _grab_http
    return None


# ---------------------------------------------------------------------------
# Generic banner grab (fallback for unknown protocols)
# ---------------------------------------------------------------------------

def _generic_banner(host: str, port: int, timeout: float) -> Optional[str]:
    """Connect and read whatever the service sends first."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(min(timeout, 1.5))
            chunks = []
            deadline = time.monotonic() + min(timeout, 2)
            while time.monotonic() < deadline:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if len(b"".join(chunks)) > 2048:
                        break
                except socket.timeout:
                    break
            raw = b"".join(chunks)
            if raw:
                return _clean(raw)[:200]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Version extraction from raw banner text
# ---------------------------------------------------------------------------

_VERSION_PATTERNS = [
    re.compile(r"SSH-[\d.]+-(\S+)"),
    re.compile(r"[Ss]erver:\s*([^\r\n]{2,80})"),
    re.compile(r"^2\d\d[- ](.{5,80})$", re.M),
    re.compile(r"redis_version:([^\r\n]+)"),
    re.compile(r"STAT version ([^\r\n]+)"),
    re.compile(r'"number"\s*:\s*"([^"]+)"'),
    re.compile(r"RFB (\S+)"),
    re.compile(r"(\w[\w\-\.]+)/(\d[\d.]+\w*)"),
    re.compile(r"[Vv]ersion\s*[:/]?\s*(\d[\d.]+\w*)"),
]


def extract_version(banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None
    for pat in _VERSION_PATTERNS:
        m = pat.search(banner)
        if m:
            try:
                raw = m.group(1).strip()
            except IndexError:
                raw = m.group(0).strip()
            if raw and len(raw) >= 2:
                return raw[:100]
    return None


# ---------------------------------------------------------------------------
# Public API: detect_service_version
# ---------------------------------------------------------------------------

def detect_service_version(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Detect service version for a single open port.
    Uses the best protocol-specific probe first; falls back to generic banner.
    Returns a clean version string or None.
    """
    grabber = _get_grabber(port)

    if grabber is not None:
        try:
            result = grabber(host, port, timeout)
            if result:
                return result[:120]
        except Exception:
            pass

    # Fallback: generic banner + regex extraction
    banner = _generic_banner(host, port, timeout)
    if banner:
        ver = extract_version(banner)
        if ver:
            return ver
        # Return first meaningful line of banner
        first_line = banner.split('\n')[0].strip()[:80]
        if first_line:
            return first_line

    return None


# ---------------------------------------------------------------------------
# OS Fingerprinting
# ---------------------------------------------------------------------------

_TTL_OS_TABLE = [
    (240, 260, "Network Device (Cisco/Juniper)", "high"),
    (120, 130, "Windows",                         "high"),
    (60,  70,  "Linux / macOS / Android",         "high"),
    (250, 260, "Solaris / AIX",                   "medium"),
    (30,  60,  "Unknown (low TTL)",               "low"),
    (1,   29,  "Unknown (very low TTL)",          "low"),
]

_TCP_WINDOW_OS = [
    (65535, "Windows",             "medium"),
    (32768, "Linux ≤ 2.6",        "medium"),
    (5840,  "Linux ≥ 3.x",        "medium"),
    (8192,  "Windows XP/2003",    "medium"),
    (16384, "OpenBSD / FreeBSD",  "medium"),
    (65228, "Linux",               "medium"),
    (29200, "Linux",               "medium"),
]


def _ttl_to_os(ttl: int):
    for lo, hi, name, conf in _TTL_OS_TABLE:
        if lo <= ttl <= hi:
            return name, conf
    return "Unknown", "low"


def _os_icmp_scapy(host: str, timeout: float) -> Optional[str]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt  = IP(dst=host) / ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if (resp and resp.haslayer(IP) and resp.haslayer(ICMP)
                and resp[IP].src == host and resp[ICMP].type == 0):
            ttl  = resp[IP].ttl
            name, conf = _ttl_to_os(ttl)
            return f"{name}  [TTL={ttl}, {conf} confidence]"
    except Exception:
        pass
    return None


def _os_ping(host: str, timeout: float) -> Optional[str]:
    try:
        import platform
        is_win = platform.system() == "Windows"
        cmd = (["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
               if is_win else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
        if result.returncode != 0:
            return None
        out = result.stdout + result.stderr
        m = re.search(r'[Tt][Tt][Ll]=(\d+)', out)
        if m:
            ttl  = int(m.group(1))
            name, conf = _ttl_to_os(ttl)
            return f"{name}  [TTL={ttl}, {conf} confidence]"
    except Exception:
        pass
    return None


def _os_tcp_window(host: str, port: int, timeout: float) -> Optional[str]:
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt  = IP(dst=host) / TCP(dport=port, sport=int(RandShort()), flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp and resp.haslayer(TCP) and (resp[TCP].flags & 0x12):
            win = resp[TCP].window
            try:
                rst = IP(dst=host) / TCP(
                    dport=port, sport=resp[TCP].dport,
                    flags="R", seq=resp[TCP].ack)
                sr1(rst, timeout=0.3, verbose=False)
            except Exception:
                pass
            for size, name, conf in _TCP_WINDOW_OS:
                if win == size:
                    return f"{name}  [TCP window={win}, {conf} confidence]"
            return f"Unknown  [TCP window={win}]"
    except Exception:
        pass
    return None


def detect_os(host: str, open_ports: Optional[List[int]] = None,
              timeout: float = 2.5) -> Optional[str]:
    result = _os_icmp_scapy(host, timeout)
    if result:
        return result
    result = _os_ping(host, timeout)
    if result:
        return result
    if open_ports:
        result = _os_tcp_window(host, open_ports[0], timeout)
        if result:
            return result
    return None
