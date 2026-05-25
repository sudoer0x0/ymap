"""
discovery.py — Host Discovery for Ymap v1.0.0

Pure ARP-based discovery (requires root), identical to Nmap -PR.
Without root: exits with a clear message — no unreliable fallback.

Hostname resolution:
  1. Reverse DNS  (socket.gethostbyaddr)
  2. mDNS .local  (send PTR query to device port 5353)
  3. NetBIOS      (UDP 137 NBSTAT request)
  4. LLMNR        (UDP 5355, Windows Link-Local Multicast)
"""

import os
import re
import socket
import ipaddress
import concurrent.futures
import time
import logging
import warnings
from dataclasses import dataclass
from typing import List, Optional

# ── Suppress ALL Scapy output before import ───────────────────────────────────
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

SCAPY_AVAILABLE = False
try:
    from scapy.all import conf as _scapy_conf  # type: ignore
    _scapy_conf.verb     = 0
    _scapy_conf.logLevel = 40
    from scapy.all import ARP, Ether, srp, get_if_hwaddr  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    pass

from ymap.utils import expand_targets, timing_params, is_ip, is_local_subnet
from ymap.vendor import lookup_mac_vendor, normalise_mac


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class HostResult:
    ip:         str
    hostname:   Optional[str] = None
    mac:        Optional[str] = None
    mac_vendor: Optional[str] = None
    latency_ms: Optional[float] = None
    status:     str = "up"
    method:     str = "unknown"


# ---------------------------------------------------------------------------
# 1. resolve_hostname(ip) -> str | None
#    Tries four methods in order. Always returns within timeout.
# ---------------------------------------------------------------------------

def _rdns(ip: str, timeout: float = 1.5) -> Optional[str]:
    """Standard reverse DNS lookup."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        if name and name != ip:
            return name.rstrip(".")    # remove trailing dot
        return None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def _mdns(ip: str, timeout: float = 1.0) -> Optional[str]:
    """
    mDNS PTR query sent directly to the device on UDP port 5353.
    Works for Apple Bonjour (.local hostnames) and Linux Avahi.
    We query the device directly (unicast) rather than multicast so
    it works even on networks that block multicast traffic.
    """
    try:
        parts = ip.split(".")
        rev   = ".".join(reversed(parts)) + ".in-addr.arpa"
        query = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for label in rev.split("."):
            encoded = label.encode("ascii", errors="ignore")
            query  += bytes([len(encoded)]) + encoded
        query += b'\x00\x00\x0c\x00\x01'   # QTYPE=PTR, QCLASS=IN

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(512)
        sock.close()

        if len(data) > 12:
            # Look for a .local label in the answer section
            m = re.search(rb'([\x01-\x3f][\w\-\.]+\.local)', data[12:])
            if m:
                raw = m.group(1).decode("ascii", errors="ignore")
                name = re.sub(r"\.local\.?$", "", raw).strip()
                if name:
                    return name
    except Exception:
        pass
    return None


def _netbios(ip: str, timeout: float = 0.8) -> Optional[str]:
    """
    NetBIOS Node Status Request (UDP 137).
    Returns workstation-unique name (type 0x00) for Windows / Samba hosts.
    """
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
            num = data[56]
            for i in range(min(num, 5)):
                off = 57 + i * 18
                if off + 16 > len(data):
                    break
                raw   = data[off:off + 15]
                ntype = data[off + 15]
                name  = raw.decode("ascii", errors="ignore").strip().rstrip("\x00")
                # type 0x00 = workstation unique name (the actual device name)
                if name and ntype == 0x00 and "\x00" not in name:
                    return name.strip()
    except Exception:
        pass
    return None


def _llmnr(ip: str, timeout: float = 0.8) -> Optional[str]:
    """
    LLMNR reverse PTR query (UDP 5355, RFC 4795).
    Used by Windows Vista+ and Linux for local name resolution.
    Send to the device directly (unicast to port 5355).
    """
    try:
        parts = ip.split(".")
        rev   = ".".join(reversed(parts)) + ".in-addr.arpa"
        # LLMNR header: TxID=1, QR=0 (query), QDCOUNT=1
        query = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        for label in rev.split("."):
            encoded = label.encode("ascii", errors="ignore")
            query  += bytes([len(encoded)]) + encoded
        query += b'\x00\x00\x0c\x00\x01'   # PTR IN

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 5355))
        data, _ = sock.recvfrom(512)
        sock.close()

        if len(data) > 12:
            # Look for a hostname in the answer — find a sequence of labels
            # Skip past the question section (after the null terminator)
            null_pos = data.find(b'\x00', 12)
            if null_pos > 12:
                rest = data[null_pos + 5:]   # skip type+class
                if rest:
                    m = re.search(rb'([\x01-\x3f])([\w\-]+)', rest)
                    if m:
                        name = m.group(2).decode("ascii", errors="ignore").strip()
                        if name and len(name) > 1:
                            return name
    except Exception:
        pass
    return None


def resolve_hostname(ip: str, timeout: float = 1.5) -> Optional[str]:
    """
    Resolve a hostname for the given IP address.
    Tries four methods in order, returns the first successful result.
    Returns None (displayed as —) if all methods fail.

    Methods tried:
      1. Reverse DNS (socket.gethostbyaddr) — works everywhere with DNS PTR records
      2. mDNS .local  (UDP 5353 unicast)    — Apple, Linux Avahi
      3. NetBIOS       (UDP 137)             — Windows, Samba, NAS
      4. LLMNR         (UDP 5355)            — Windows Vista+, Linux

    All methods respect the timeout and never block indefinitely.
    """
    # 1. Reverse DNS
    name = _rdns(ip, timeout=min(timeout, 1.5))
    if name:
        return name

    # 2. mDNS
    name = _mdns(ip, timeout=min(timeout, 1.0))
    if name:
        return name

    # 3. NetBIOS
    name = _netbios(ip, timeout=min(timeout, 0.8))
    if name:
        return name

    # 4. LLMNR
    name = _llmnr(ip, timeout=min(timeout, 0.8))
    if name:
        return name

    return None


# ---------------------------------------------------------------------------
# 2. resolve_hostnames(hosts: List[HostResult]) -> None
#    Resolves hostnames for all hosts in parallel using ThreadPoolExecutor.
# ---------------------------------------------------------------------------

def resolve_hostnames(hosts: List[HostResult], timeout: float = 1.5) -> None:
    """
    Populate the hostname field for every HostResult in *hosts* in parallel.
    Uses up to 25 workers (safe for typical /24 subnets).
    Modifies the list in-place. Never raises — all errors are silently handled.
    """
    if not hosts:
        return

    def _resolve_one(result: HostResult) -> None:
        result.hostname = resolve_hostname(result.ip, timeout=timeout)

    max_w = min(25, len(hosts))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_w,
        thread_name_prefix="ymap-dns",
    ) as pool:
        futures = [pool.submit(_resolve_one, r) for r in hosts]
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Local machine helpers
# ---------------------------------------------------------------------------

def get_local_ip() -> Optional[str]:
    """Return the primary outbound IP of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


def _get_local_mac() -> Optional[str]:
    """Get MAC of the local outbound interface."""
    iface = None
    if SCAPY_AVAILABLE:
        try:
            iface = str(_scapy_conf.iface)
        except Exception:
            pass

    if iface and os.path.exists(f"/sys/class/net/{iface}/address"):
        try:
            mac = open(f"/sys/class/net/{iface}/address").read().strip()
            if mac and mac != "00:00:00:00:00:00":
                return normalise_mac(mac)
        except Exception:
            pass

    if os.path.exists("/sys/class/net"):
        skip = {"lo", "docker0", "virbr0"}
        for name in sorted(os.listdir("/sys/class/net")):
            if name in skip or name.startswith(("veth", "br-")):
                continue
            path = f"/sys/class/net/{name}/address"
            if os.path.exists(path):
                try:
                    mac = open(path).read().strip()
                    if mac and mac != "00:00:00:00:00:00":
                        return normalise_mac(mac)
                except Exception:
                    pass

    try:
        import psutil
        ifaces = psutil.net_if_addrs()
        order  = []
        if iface and iface in ifaces:
            order.append(iface)
        order += [k for k in ifaces if k not in ("lo", "lo0", "docker0")
                  and not k.startswith(("veth", "br-"))]
        for name in order:
            for addr in ifaces.get(name, []):
                if addr.family in (17, 18, -1):
                    mac = addr.address
                    if mac and mac not in ("00:00:00:00:00:00", ""):
                        return normalise_mac(mac)
    except Exception:
        pass

    if SCAPY_AVAILABLE and iface:
        try:
            mac = get_if_hwaddr(iface)
            if mac and mac != "00:00:00:00:00:00":
                return normalise_mac(mac)
        except Exception:
            pass

    return None


# ---------------------------------------------------------------------------
# Proxy-ARP detector
# ---------------------------------------------------------------------------

def _detect_proxy_arp(answered) -> Optional[str]:
    """
    If 3+ different IPs all reply with the SAME MAC, that MAC is a proxy-ARP
    device (router / NAT / hotspot). Returns the proxy MAC or None.
    """
    mac_to_ips: dict = {}
    for _, recv in answered:
        if recv.haslayer(ARP) and recv[ARP].op == 2:
            mac = recv[ARP].hwsrc.upper()
            ip  = recv[ARP].psrc
            mac_to_ips.setdefault(mac, set()).add(ip)
    for mac, ips in mac_to_ips.items():
        if len(ips) >= 3:
            return mac
    return None


# ---------------------------------------------------------------------------
# Pure ARP sweep
# ---------------------------------------------------------------------------

def arp_sweep(target: str, timeout: float = 2.0, retry: int = 1) -> List[HostResult]:
    """
    Send ARP "Who has?" to every IP in *target*.
    Only hosts that reply with op=2 and correct psrc are reported as live.
    Proxy-ARP responses are detected and filtered out.
    Returns HostResult list (no hostname yet — call resolve_hostnames after).
    """
    if not SCAPY_AVAILABLE:
        return []

    hosts = expand_targets(target)
    if not hosts:
        return []

    pkts = [
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, op=1)
        for ip in hosts
    ]

    try:
        answered, _ = srp(pkts, timeout=timeout, verbose=False,
                          retry=retry, inter=0.001)
    except Exception:
        return []

    proxy_mac = _detect_proxy_arp(answered)
    local_ip  = get_local_ip()
    results:  List[HostResult] = []
    seen_ips: set = set()

    for sent, recv in answered:
        try:
            if not recv.haslayer(ARP):
                continue
            reply = recv[ARP]
            if reply.op != 2:
                continue
            if reply.psrc != sent[ARP].pdst:
                continue
            mac_raw = reply.hwsrc
            if not mac_raw or mac_raw in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue

            mac = normalise_mac(mac_raw)

            # Filter proxy-ARP (allow the proxy's own IP through)
            if proxy_mac and mac.upper() == proxy_mac.upper():
                if reply.psrc != sent[ARP].pdst:
                    continue

            if reply.psrc in seen_ips:
                continue
            seen_ips.add(reply.psrc)

            vendor  = lookup_mac_vendor(mac)
            latency = None
            try:
                latency = round((recv.time - sent.sent_time) * 1000, 2)
                if latency < 0:
                    latency = None
            except Exception:
                pass

            results.append(HostResult(
                ip=reply.psrc, mac=mac, mac_vendor=vendor,
                latency_ms=latency, status="up", method="ARP",
            ))
        except Exception:
            continue

    # Include local machine if in range and not already found
    if local_ip and local_ip in hosts and local_ip not in seen_ips:
        local_mac = _get_local_mac()
        results.append(HostResult(
            ip=local_ip,
            mac=local_mac,
            mac_vendor=lookup_mac_vendor(local_mac) if local_mac else None,
            latency_ms=0.0,
            status="up",
            method="ARP (local)",
        ))

    results.sort(key=lambda r: _ip_sort_key(r.ip))
    return results


def _ip_sort_key(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover(
    target: str,
    timing: int = 4,
    use_raw: bool = True,
) -> List[HostResult]:
    """
    Discover live hosts on *target* using pure ARP.

    Requires root (use_raw=True). If called without root, returns [] so
    that core.py can display the appropriate error message.

    After ARP sweep, resolves hostnames for all discovered hosts in parallel.
    """
    if not use_raw or not SCAPY_AVAILABLE:
        return []

    connect_timeout, _ = timing_params(timing)
    arp_timeout = max(2.0, connect_timeout)

    results = arp_sweep(target, timeout=arp_timeout, retry=1)

    # Resolve hostnames for all discovered hosts in parallel
    resolve_hostnames(results, timeout=1.5)

    return results
