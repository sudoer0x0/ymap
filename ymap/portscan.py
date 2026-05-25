"""
portscan.py — Port Scanning Engine for Ymap v1.0.0

Three scan modes:
  T — TCP Connect  (no root; full 3-way handshake)
  S — SYN half-open (root + Scapy)
  U — UDP           (root + Scapy)
"""

import socket
import concurrent.futures
import time
from enum import Enum
from typing import List, Optional
from dataclasses import dataclass

import warnings, logging
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ymap.utils import timing_params

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, RandShort  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

class PortState(str, Enum):
    OPEN          = "open"
    CLOSED        = "closed"
    FILTERED      = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    port:       int
    state:      PortState
    protocol:   str = "tcp"
    banner:     Optional[str] = None
    latency_ms: Optional[float] = None


# ---------------------------------------------------------------------------
# Comprehensive service name database
# ---------------------------------------------------------------------------

_SERVICES: dict = {
    # ── Well-known / IANA assigned ─────────────────────────────────────────
    1:     "tcpmux",
    7:     "echo",
    9:     "discard",
    13:    "daytime",
    17:    "qotd",
    19:    "chargen",
    20:    "ftp-data",
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    37:    "time",
    43:    "whois",
    49:    "tacacs",
    53:    "dns",
    67:    "dhcp-server",
    68:    "dhcp-client",
    69:    "tftp",
    70:    "gopher",
    79:    "finger",
    80:    "http",
    81:    "http-alt",
    82:    "http-alt",
    83:    "http-alt",
    84:    "http-alt",
    85:    "http-alt",
    88:    "kerberos",
    102:   "ms-exchange",
    109:   "pop2",
    110:   "pop3",
    111:   "rpcbind",
    113:   "ident",
    119:   "nntp",
    123:   "ntp",
    135:   "msrpc",
    137:   "netbios-ns",
    138:   "netbios-dgm",
    139:   "netbios-ssn",
    143:   "imap",
    161:   "snmp",
    162:   "snmp-trap",
    177:   "xdmcp",
    179:   "bgp",
    194:   "irc",
    389:   "ldap",
    427:   "svrloc",
    443:   "https",
    444:   "snpp",
    445:   "smb",
    464:   "kpasswd",
    465:   "smtps",
    500:   "isakmp",
    502:   "modbus",
    512:   "rexec",
    513:   "rlogin",
    514:   "syslog",
    515:   "printer",
    520:   "rip",
    540:   "uucp",
    543:   "klogin",
    544:   "kshell",
    548:   "afp",
    554:   "rtsp",
    587:   "smtp-submission",
    593:   "http-rpc-epmap",
    623:   "ipmi",
    631:   "ipp",
    636:   "ldaps",
    873:   "rsync",
    902:   "vmware-auth",
    903:   "vmware-auth-alt",
    989:   "ftps-data",
    990:   "ftps",
    992:   "telnets",
    993:   "imaps",
    995:   "pop3s",
    # ── Registered ports ──────────────────────────────────────────────────
    1080:  "socks",
    1099:  "java-rmi",
    1194:  "openvpn",
    1433:  "mssql",
    1434:  "mssql-browser",
    1521:  "oracle-db",
    1723:  "pptp",
    1812:  "radius",
    1813:  "radius-acct",
    1883:  "mqtt",
    1900:  "upnp",
    2049:  "nfs",
    2082:  "cpanel",
    2083:  "cpanel-ssl",
    2086:  "whm",
    2087:  "whm-ssl",
    2181:  "zookeeper",
    2222:  "ssh-alt",
    2375:  "docker-api",
    2376:  "docker-tls",
    2379:  "etcd-client",
    2380:  "etcd-cluster",
    3000:  "dev-server",        # Node.js / Grafana / Rails dev
    3001:  "dev-server-alt",
    3003:  "dev-server-alt",
    3128:  "squid-proxy",
    3260:  "iscsi",
    3268:  "ldap-gc",
    3269:  "ldap-gc-ssl",
    3306:  "mysql",
    3389:  "rdp",
    3690:  "svn",
    3872:  "oracle-mgmt",
    4000:  "teraterm",
    4200:  "angular-dev",
    4369:  "epmd",              # Erlang Port Mapper (RabbitMQ, Elixir)
    4443:  "https-alt",
    4444:  "metasploit",
    4567:  "sinatra-dev",
    4848:  "glassfish-admin",
    4984:  "couchdb-sync",
    5000:  "upnp-alt",          # UPnP / Flask dev / Docker registry
    5001:  "commplex-link",
    5004:  "rtp",
    5005:  "rtp-alt",
    5060:  "sip",
    5061:  "sip-tls",
    5228:  "gcm",               # Google Cloud Messaging / Android push
    5353:  "mdns",              # mDNS / Bonjour (Apple, Android, Linux)
    5355:  "llmnr",             # Link-Local Multicast Name Resolution
    5432:  "postgresql",
    5555:  "adb",               # Android Debug Bridge
    5601:  "kibana",
    5672:  "amqp",              # RabbitMQ AMQP
    5800:  "vnc-http",
    5900:  "vnc",
    5901:  "vnc-1",
    5938:  "teamviewer",
    5984:  "couchdb",
    5985:  "winrm-http",
    5986:  "winrm-https",
    6000:  "x11",
    6379:  "redis",
    6443:  "k8s-api",           # Kubernetes API server
    6881:  "bittorrent",
    7001:  "weblogic-admin",
    7002:  "weblogic-ssl",
    7474:  "neo4j-http",
    7473:  "neo4j-https",
    7687:  "neo4j-bolt",
    8000:  "http-alt",
    8001:  "http-alt",
    8008:  "http-alt",
    8009:  "ajp",               # Apache JServ Protocol (Tomcat)
    8069:  "odoo",              # Odoo ERP
    8080:  "http-proxy",
    8081:  "http-alt",
    8083:  "influxdb-http",
    8086:  "influxdb",
    8088:  "riak-http",
    8096:  "jellyfin",          # Jellyfin Media Server
    8123:  "hass",              # Home Assistant
    8161:  "activemq-http",     # Apache ActiveMQ web console
    8181:  "http-alt",
    8443:  "https-alt",
    8500:  "consul-http",       # HashiCorp Consul
    8600:  "consul-dns",
    8888:  "jupyter",           # Jupyter Notebook / JupyterLab
    8983:  "solr",              # Apache Solr
    9000:  "sonarqube",         # SonarQube / PHP-FPM / Portainer
    9001:  "supervisord",       # Supervisor process manager
    9042:  "cassandra",         # Apache Cassandra CQL
    9090:  "prometheus",        # Prometheus monitoring
    9091:  "transmission",      # Transmission BitTorrent web UI
    9092:  "kafka",             # Apache Kafka
    9093:  "kafka-ssl",
    9094:  "kafka-controller",
    9100:  "jetdirect",         # HP JetDirect printing
    9200:  "elasticsearch",
    9300:  "elasticsearch-cluster",
    9418:  "git",
    9443:  "https-alt",
    10000: "webmin",
    10250: "k8s-kubelet",       # Kubernetes Kubelet API
    10255: "k8s-kubelet-ro",
    10443: "https-alt",
    11211: "memcached",
    15000: "grafana",
    15672: "rabbitmq-mgmt",     # RabbitMQ management plugin
    16379: "redis-sentinel",
    16443: "microk8s-api",
    18080: "monero-rpc",
    18081: "monero-p2p",
    25565: "minecraft",
    27015: "steam",             # Steam / Source game server
    27016: "steam-alt",
    27017: "mongodb",
    27018: "mongodb-shard",
    27019: "mongodb-config",
    28017: "mongodb-web",
    32400: "plex",              # Plex Media Server
    33060: "mysqlx",            # MySQL X Protocol
    47808: "bacnet",            # BACnet (building automation)
    49152: "win-dyn-1",
    49153: "win-dyn-2",
    49154: "win-dyn-3",
    49155: "win-dyn-4",
    49156: "win-dyn-5",
    49157: "win-dyn-6",
    50000: "ibm-db2",
    50070: "hadoop-namenode",   # Hadoop NameNode web UI
    51413: "transmission-bt",
    55000: "freeipa",
    61616: "activemq-openwire", # Apache ActiveMQ OpenWire protocol
    62078: "iphone-sync",       # iPhone/iOS USB sync (lockdownd)
    # ── IoT / Industrial ──────────────────────────────────────────────────
    102:   "siemens-s7",        # Siemens S7 PLC
    503:   "modbus-alt",
    1911:  "niagara-fox",       # Niagara Framework (building automation)
    2404:  "iec-104",           # IEC 60870-5-104 SCADA
    4712:  "niagara-fox-ssl",
    9600:  "omron-fins",        # Omron FINS industrial protocol
    20000: "dnp3",              # DNP3 SCADA protocol
    44818: "ethernet-ip",       # EtherNet/IP (Allen-Bradley PLCs)
    # ── macOS / iOS specific ──────────────────────────────────────────────
    3689:  "daap",              # iTunes DAAP
    5297:  "xmpp-client-alt",
    7000:  "airplay",           # AirPlay video streaming (iOS/macOS)
    7100:  "font-service",
    49152: "airplay-discovery",
    # ── Additional dev / cloud ────────────────────────────────────────────
    3001:  "grafana-alt",
    3306:  "mysql",
    4000:  "ember-dev",
    4200:  "angular-dev",
    4567:  "artisan-serve",
    5000:  "flask-dev",
    8080:  "http-proxy",
    9229:  "node-inspector",    # Node.js debugger
}

# Deduplicate by highest port number wins
_SERVICES = {k: v for k, v in sorted(_SERVICES.items())}


def service_name(port: int, proto: str = "tcp") -> str:
    """Return a human-readable service name for a port number."""
    if port in _SERVICES:
        return _SERVICES[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


# ---------------------------------------------------------------------------
# TCP Connect Scan
# ---------------------------------------------------------------------------

def _tcp_connect_probe(host: str, port: int, timeout: float,
                       grab_banner: bool = False) -> PortResult:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            elapsed = (time.perf_counter() - start) * 1000
            banner = None
            if grab_banner:
                s.settimeout(0.8)
                try:
                    raw = s.recv(1024)
                    if raw:
                        import re
                        ctrl = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
                        banner = ctrl.sub("", raw.decode("utf-8", errors="replace")).strip()[:200]
                except Exception:
                    pass
            return PortResult(port=port, state=PortState.OPEN, protocol="tcp",
                              banner=banner, latency_ms=round(elapsed, 2))
    except ConnectionRefusedError:
        return PortResult(port=port, state=PortState.CLOSED, protocol="tcp")
    except (socket.timeout, TimeoutError):
        return PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
    except OSError:
        return PortResult(port=port, state=PortState.FILTERED, protocol="tcp")


def tcp_connect_scan(host: str, ports: List[int], timing: int = 4,
                     max_workers: int = 500, grab_banner: bool = False) -> List[PortResult]:
    connect_timeout, _ = timing_params(timing)
    results: List[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="ymap-tcp"
    ) as pool:
        futures = {
            pool.submit(_tcp_connect_probe, host, p, connect_timeout, grab_banner): p
            for p in ports
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    results.sort(key=lambda r: r.port)
    return results


# ---------------------------------------------------------------------------
# SYN Scan
# ---------------------------------------------------------------------------

def _syn_probe(host: str, port: int, timeout: float) -> PortResult:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy required for SYN scan.")
    start = time.perf_counter()
    pkt = IP(dst=host) / TCP(dport=port, sport=int(RandShort()), flags="S")
    try:
        resp = sr1(pkt, timeout=timeout, verbose=False)
    except Exception:
        return PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
    elapsed = (time.perf_counter() - start) * 1000
    if resp is None:
        return PortResult(port=port, state=PortState.FILTERED, protocol="tcp",
                          latency_ms=round(elapsed, 2))
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags & 0x12:  # SYN-ACK
            try:
                rst = IP(dst=host) / TCP(dport=port, sport=resp[TCP].dport,
                                         flags="R", seq=resp[TCP].ack)
                sr1(rst, timeout=0.3, verbose=False)
            except Exception:
                pass
            return PortResult(port=port, state=PortState.OPEN, protocol="tcp",
                              latency_ms=round(elapsed, 2))
        if flags & 0x14:  # RST-ACK
            return PortResult(port=port, state=PortState.CLOSED, protocol="tcp",
                              latency_ms=round(elapsed, 2))
    if resp.haslayer(ICMP) and resp[ICMP].type == 3:
        return PortResult(port=port, state=PortState.FILTERED, protocol="tcp",
                          latency_ms=round(elapsed, 2))
    return PortResult(port=port, state=PortState.FILTERED, protocol="tcp",
                      latency_ms=round(elapsed, 2))


def syn_scan(host: str, ports: List[int], timing: int = 4,
             max_workers: int = 300) -> List[PortResult]:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy not installed. Run: pip install scapy")
    connect_timeout, _ = timing_params(timing)
    results: List[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="ymap-syn"
    ) as pool:
        futures = {pool.submit(_syn_probe, host, p, connect_timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    results.sort(key=lambda r: r.port)
    return results


# ---------------------------------------------------------------------------
# UDP Scan
# ---------------------------------------------------------------------------

def _udp_probe(host: str, port: int, timeout: float) -> PortResult:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy required for UDP scan.")
    start = time.perf_counter()
    pkt = IP(dst=host) / UDP(dport=port)
    try:
        resp = sr1(pkt, timeout=timeout, verbose=False)
    except Exception:
        return PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp")
    elapsed = (time.perf_counter() - start) * 1000
    if resp is None:
        return PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp",
                          latency_ms=round(elapsed, 2))
    if resp.haslayer(UDP):
        return PortResult(port=port, state=PortState.OPEN, protocol="udp",
                          latency_ms=round(elapsed, 2))
    if resp.haslayer(ICMP) and resp[ICMP].type == 3:
        return PortResult(port=port, state=PortState.CLOSED, protocol="udp",
                          latency_ms=round(elapsed, 2))
    return PortResult(port=port, state=PortState.OPEN_FILTERED, protocol="udp",
                      latency_ms=round(elapsed, 2))


def udp_scan(host: str, ports: List[int], timing: int = 4,
             max_workers: int = 100) -> List[PortResult]:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy not installed. Run: pip install scapy")
    connect_timeout, _ = timing_params(timing)
    results: List[PortResult] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="ymap-udp"
    ) as pool:
        futures = {pool.submit(_udp_probe, host, p, connect_timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    results.sort(key=lambda r: r.port)
    return results


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def scan_ports(host: str, ports: List[int], scan_type: str = "T",
               timing: int = 4, grab_banner: bool = False) -> List[PortResult]:
    """Route to the correct scan function."""
    t = scan_type.upper()
    if t == "S":
        return syn_scan(host, ports, timing)
    elif t == "U":
        return udp_scan(host, ports, timing)
    else:
        return tcp_connect_scan(host, ports, timing, grab_banner=grab_banner)
