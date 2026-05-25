# Ymap: Technical Documentation

[![Python ≥ 3.9](https://img.shields.io/badge/python-≥3.9-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/pypi-yhash-orange)](https://pypi.org/project/ymap)

---
**Version:** 1.0.0  
**Developer:** Adekunle Abdulmujeeb   
**License:** MIT  
**Language:** Python 3.8+

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Philosophy](#2-design-philosophy)
3. [Installation](#3-installation)
4. [Project Architecture](#4-project-architecture)
5. [Module Reference](#5-module-reference)
   - [cli.py](#51-clipy--commandline-interface)
   - [core.py](#52-corepy--scan-pipeline-orchestrator)
   - [utils.py](#53-utilspy--shared-utilities)
   - [discovery.py](#54-discoverypy--host-discovery)
   - [portscan.py](#55-portscanpy--port-scanning-engine)
   - [fingerprint.py](#56-fingerprintpy--version-and-os-detection)
   - [scripting.py](#57-scriptingpy--cve-vulnerability-lookup)
   - [output.py](#58-outputpy--terminal-output-and-reporting)
6. [Library Reference](#6-library-reference)
7. [Flag Reference](#7-flag-reference)
8. [Scan Pipeline — End to End](#8-scan-pipeline--end-to-end)
9. [CVE Lookup System](#9-cve-lookup-system)
10. [Security Architecture](#10-security-architecture)
11. [Target Formats](#11-target-formats)
12. [Timing System](#12-timing-system)
13. [Usage Examples](#13-usage-examples)
14. [JSON Report Format](#14-json-report-format)
15. [Platform Differences](#15-platform-differences)
16. [Known Limitations](#16-known-limitations)

---

## 1. Overview

Ymap (Yung Mapper) is a self-contained Python network scanner designed for pentesters, security researchers, students, and network administrators. It provides powerful network scanning capabilities through a small, easy-to-memorise set of flags — deliberately modelled to feel familiar to Nmap users while being much simpler to operate.

Ymap does not wrap Nmap or any external scanning binary. Every scanning technique is implemented from first principles using Python sockets, Scapy raw packets, and standard system utilities. It is fully pip-installable and works on Linux, macOS, and Windows.

**Core capabilities:**

| Capability | How it works |
|---|---|
| Host discovery | ARP, ICMP Echo, subprocess ping, TCP connect |
| Port scanning | TCP Connect (no root), SYN half-open (root), UDP (root) |
| Service version detection | Per-protocol probes: SSH banner, HTTP HEAD, MySQL handshake, etc. |
| OS fingerprinting | ICMP TTL, subprocess ping TTL, SMB dialect negotiation, TCP window |
| CVE lookup | NIST NVD REST API v2.0, three query modes |
| MAC vendor identification | OUI database lookup via mac-vendor-lookup |
| Device naming | Reverse DNS, NetBIOS Node Status (UDP 137), mDNS (UDP 5353) |
| JSON reporting | Structured JSON export of all scan findings |

---

## 2. Design Philosophy

### Simplicity first
Every scan mode maps to a single-letter flag. A pentester can memorise the full flag set in under two minutes: `-A` for aggressive, `-B` for basic, `-C` for CVE, `-D` for discovery, `-O` for OS, `-V` for version. All flags also work in lowercase.

### Speed by default
The default scan (no flags, just a target) scans the top 1,000 ports by TCP connect with no version detection. This gives a useful picture of a host in seconds without any overhead.

### No false positives over no results
Every host detection method requires genuine evidence of a live host:
- ARP: a real MAC address reply
- ICMP: an Echo Reply (type 0) from the exact target IP with a plausible TTL
- TCP: a completed 3-way handshake — not a RST, which NAT routers return for everyone

### Independent — no Nmap dependency
Ymap uses zero Nmap binaries or libraries. All raw packet operations use Scapy. Service probes use Python's built-in `socket` module. OS detection uses ICMP TTL, SMB negotiation, and TCP window analysis — all implemented directly.

### Security by design
- All user inputs are validated before use and reject shell-injection characters
- API keys are never stored to disk; they live only in process memory for one session
- Banner data is sanitised (control characters stripped, length capped) before display
- CVE queries use URL parameters via the `requests` library — never string interpolation

---

## 3. Installation

```bash
# From PyPI
pip3 install ymap

# From source
git clone https://github.com/sudoer0x0/ymap.git
cd ymap
pip3 install .
```

**Dependencies installed automatically:**

| Package | Version | Purpose |
|---|---|---|
| click | ≥ 8.1 | CLI framework |
| rich | ≥ 13.0 | Terminal output |
| scapy | ≥ 2.5 | Raw packet operations |
| requests | ≥ 2.28 | NVD API HTTP calls |
| mac-vendor-lookup | ≥ 0.1.11 | OUI vendor database |
| psutil | ≥ 5.9 | Cross-platform interface info |

**Root / sudo requirement:**

Some features require elevated privileges to open raw sockets:

| Feature | Root required? |
|---|---|
| Basic TCP scan (`-B`) | No |
| Version detection (`-V`) | No |
| CVE lookup (`-C`, `-vc`) | No |
| SYN scan (`-S S`) | Yes |
| UDP scan (`-S U`) | Yes |
| Host discovery (`-D`) | Yes (for best results) |
| OS fingerprinting (`-O`) | Yes |
| Aggressive scan (`-A`) | Yes |

---

## 4. Project Architecture

```
ymap/
├── ymap/
│   ├── __init__.py       Version, author, license metadata
│   ├── cli.py            Command-line interface (entry point)
│   ├── core.py           Scan pipeline orchestrator
│   ├── utils.py          Input validation, top-1000 port list, helpers
│   ├── discovery.py      Host discovery (ARP / ICMP / ping / TCP)
│   ├── portscan.py       Port scanning (Connect / SYN / UDP)
│   ├── fingerprint.py    Service version detection + OS fingerprinting
│   ├── scripting.py      CVE lookup via NIST NVD API
│   └── output.py         Terminal rendering + JSON export
├── tests/
│   └── test_utils.py     Unit tests for input validation
├── pyproject.toml        Build system and package metadata
├── requirements.txt      Runtime dependencies
└── README.md             Quick-start guide
```

**Data flow through the pipeline:**

```
User types:  ymap -A 192.168.1.1
            │
    ┌───────▼────────┐
│   | cli.py         │  Parse flags, validate --cve-check input,
    │                │  prompt for API key if --add-nvd-api-key
    └───────┬────────┘
            │              ScanConfig object
    ┌───────▼────────┐
    │    core.py     │  Orchestrates all phases in order
    └───────┬────────┘
            │
    ┌───────▼──────────┐   Phase 1: is host reachable?
    │  discovery.py    │   Phase 2: -D sweep or single-host check
    └───────┬──────────┘
            │
    ┌───────▼──────────┐   Phase 3: port scan
    │  portscan.py     │
    └───────┬──────────┘
            │
    ┌───────▼──────────┐   Phase 4: version detection (if -V or -A or -C or -vc)
    │ fingerprint.py   │   Phase 5: OS fingerprinting (if -O or -A)
    └───────┬──────────┘
            │
    ┌───────▼──────────┐   Phase 6: CVE lookup (if -C, -vc, or --cve-check)
    │  scripting.py    │
    └───────┬──────────┘
            │
    ┌───────▼──────────┐   Phase 7: display results + optional JSON export
    │   output.py      │
    └──────────────────┘
```

---

## 5. Module Reference

### 5.1 cli.py — Command-Line Interface

`cli.py` is the entry point of the application. It is registered in `pyproject.toml` as the `ymap` console script:

```toml
[project.scripts]
ymap = "ymap.cli:main"
```

**Key responsibilities:**

1. **Flag parsing** — uses Click to define and parse all command-line arguments
2. **Input validation** — calls `parse_manual_cve_input()` on `--cve-check` values before passing them to core
3. **API key handling** — prompts for NVD key via `getpass.getpass()` (masked input), stores it in the session via `set_session_api_key()`, clears it in the `finally` block when the process exits
4. **Root warnings** — checks `is_root()` and emits a warning (not an error) before scans that need elevated privileges
5. **Error routing** — catches `ValueError`, `PermissionError`, and `KeyboardInterrupt` and exits with appropriate messages

**CaseInsensitiveChoice:**

The `-S`/`-s` scan type option uses a custom Click subclass:

```python
class CaseInsensitiveChoice(click.Choice):
    def convert(self, value, param, ctx):
        if value is None:
            return value
        return super().convert(value.upper(), param, ctx)
```

This allows `ymap -s s target` and `ymap -S S target` to be treated identically. All other flags support both cases through duplicate option names: `-A` and `-a` are both registered with Click.

---

### 5.2 core.py — Scan Pipeline Orchestrator

`core.py` contains the `ScanConfig` dataclass and `run_scan()` function. It is the brain that decides which modules to invoke and in what order.

**`ScanConfig` field resolution:**

When the user passes `-A` (aggressive), the config sets:
```
do_discovery = True
do_port_scan = True
do_version   = True
do_os        = True
do_cve       = True
scan_type    = "S"   ← SYN scan for aggressive mode
```

When the user passes `-C` (CVE check), `do_version` is also set to `True` automatically — because CVE lookups are meaningless without knowing the running version. This coupling is handled in `ScanConfig.__init__`:

```python
self.do_version = version_detect or cve or version_cve
```

**Reachability check before scan:**

For single-host scans, `_host_is_reachable()` runs a quick pre-check using `_ping_subprocess()` and `_tcp_probe()`. If neither responds, a warning is printed but the port scan proceeds anyway (the host may be blocking ICMP, exactly like `nmap -Pn`).

**Multi-host detection:**

The `is_multi` flag is set when the target is a CIDR (`/`) or a last-octet range (`192.168.1.1-50`). Multi-host targets trigger an automatic discovery sweep before port scanning.

**CVE error handling in core:**

CVE lookup errors are caught at the host loop level:

```python
try:
    host_cve_map = _run_cve_lookup(services_list, precise=precise)
except RateLimitError:
    rate_limited = True
except InvalidKeyError as e:
    invalid_key = True
    invalid_key_msg = str(e)
```

Errors are collected and displayed once after the entire scan loop completes, not mid-scan. This prevents a rate-limit on host 2 of 5 from disrupting the scan output for the remaining hosts.

---

### 5.3 utils.py — Shared Utilities

`utils.py` provides input validation, target expansion, privilege checks, and the top-1000 port list.

**`validate_target()`**

Accepts four target formats:
- Plain IPv4: `192.168.1.1`
- CIDR notation: `10.0.0.0/24` (validated via `ipaddress.ip_network`)
- Last-octet range: `192.168.1.1-50`
- Hostname/FQDN: `example.com` (validated against RFC 1123 regex)

Rejects any target containing shell-injection characters: `;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `!`.

**`validate_ports()`**

Parses port specifications:
- Single: `80`
- Comma-list: `22,80,443`
- Range: `1-1000`
- All ports: `-` (expands to 1–65535)
- Mixed: `22,80,443,8000-8100`

All ports are clamped to [1, 65535] and deduplicated.

**`NMAP_TOP_1000`**

A hardcoded sorted list of 1,000 port numbers derived from Nmap's `nmap-services` frequency ranking. This is the exact set of ports that `nmap --top-ports 1000` scans. It covers ports 1–65389, with density concentrated on well-known ports (< 10000) and a selection of high-numbered ephemeral service ports.

**`TIMING_MAP`**

```python
TIMING_MAP = {
    0: (5.0,  0.50),   # T0: 5s timeout, 500ms between probes
    1: (4.0,  0.25),   # T1: 4s timeout, 250ms between probes
    2: (3.0,  0.10),   # T2: 3s timeout, 100ms between probes
    3: (2.0,  0.05),   # T3: 2s timeout,  50ms between probes
    4: (1.5,  0.01),   # T4: 1.5s timeout, 10ms between probes (default)
    5: (0.5,  0.00),   # T5: 0.5s timeout, no delay (insane)
}
```

Each template returns `(connect_timeout_seconds, inter_probe_delay_seconds)`. At T4 (default), Ymap can scan 1,000 ports in under 2 seconds on a LAN.

---

### 5.4 discovery.py — Host Discovery

`discovery.py` performs host sweep and device enrichment. It is the most complex module, handling four probe methods, device naming via three protocols, MAC vendor identification, OS hinting, and false-positive prevention.

**Scapy warning suppression**

All Scapy warnings are suppressed at import time with a three-layer approach:

```python
import warnings, logging
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import conf as _scapy_conf
_scapy_conf.verb     = 0   # suppress per-packet output
_scapy_conf.logLevel = 40  # ERROR only (silences MAC broadcast messages)
```

This prevents the `WARNING: MAC address to reach destination not found. Using broadcast.` messages that appear in older versions of Scapy when the ARP cache is empty.

**Host detection methods (in priority order):**

**Method 1: ARP ping (most reliable, LAN only)**

Uses Scapy to broadcast an ARP request:
```python
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
ans, _ = srp(pkt, timeout=timeout, verbose=False, retry=0)
```
Only the target can respond to a unicast ARP, so a response is definitive proof the host exists. The MAC address in the reply is captured and looked up in the OUI database. Requires root and Scapy. Local subnet only.

**Method 2: Scapy ICMP Echo (strict)**

```python
pkt = IP(dst=ip) / ICMP()
resp = sr1(pkt, timeout=timeout, verbose=False)
```

The response is accepted only if:
- `resp[IP].src == ip` — the reply came from the exact target (not a router)
- `resp[ICMP].type == 0` — it is a genuine Echo Reply, not type 3 (Unreachable)
- `resp[IP].ttl >= 10` — the TTL is plausible (rejects NAT-forged replies)

Requires root and Scapy.

**Method 3: subprocess ping (with TTL gate)**

```python
cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
result = subprocess.run(cmd, capture_output=True, text=True)
```

Parses TTL from the output using `re.search(r'[Tt][Tt][Ll]=(\d+)', out)`. Replies with `TTL < 10` are rejected as NAT artifacts. This is the key guard against mobile hotspot false positives, where the NAT router responds to pings for all 255 addresses in the subnet.

**Method 4: TCP connect (strict — no RST)**

```python
socket.create_connection((ip, port), timeout=timeout)
```

Attempts a full TCP 3-way handshake on ports: `[22, 80, 443, 8080, 445, 3389, 25, 8443]`. Only a successful `connect()` counts as "host up". A `ConnectionRefusedError` (TCP RST) is explicitly **not** accepted — mobile hotspot NAT returns RST for every IP in the subnet whether or not a device is actually present.

**MAC vendor lookup (`lookup_mac_vendor`)**

The function first checks the **locally-administered bit** — bit 1 of the first octet:

```python
def _is_locally_administered(mac: str) -> bool:
    first = int(mac.replace(":", "")[:2], 16)
    return bool((first >> 1) & 1)
```

When this bit is `1`, the MAC was randomly generated by software (VMs, Docker containers, mobile hotspots, VPN adapters). These have no entry in any OUI database — they were never assigned to a manufacturer. Ymap returns `"Locally Administered (Virtual/Hotspot/Docker)"` for these instead of a blank.

When bit 1 is `0`, the MAC is globally unique and the OUI prefix is looked up in the `mac_vendor_lookup` database (offline, no internet needed).

**Device naming (three protocols):**

1. **Reverse DNS** — `socket.gethostbyaddr(ip)` queries the PTR record. Works on any network where the DNS server is configured with reverse zones. Always tried first.

2. **NetBIOS Node Status (UDP 137)** — A 50-byte NBSTAT request is sent to port 137. The response contains a name table where entries with `name_type == 0x00` are workstation unique names (the device name). Works for Windows, Samba, and NAS devices. Local subnet only.

3. **mDNS PTR query (UDP 5353)** — A DNS PTR query is sent directly to the device's IP on port 5353. Apple (Bonjour) and Linux (Avahi) devices respond with their `.local` hostname. Local subnet only.

**SMB OS detection (port 445)**

For local-subnet hosts, Ymap sends a raw SMB Negotiate Protocol Request containing both SMB1 and SMB2 dialect options. The server's response contains an OS version string that is matched against a table of known Windows versions:

```python
_SMB_OS = [
    (re.compile(rb'Windows Server 2022'), "Windows Server 2022"),
    (re.compile(rb'Windows Server 2019'), "Windows Server 2019"),
    ...
    (re.compile(rb'Windows 10'),          "Windows 10"),
]
```

This gives exact Windows version identification without any external library.

**Local machine detection**

When the scanner's own IP is in the sweep range, `_probe_host()` detects it by comparing each target IP against `get_local_ip()` (determined via a UDP connect to 8.8.8.8). The local machine is populated directly from interface info — no outbound probe needed:

```python
if local_ip and ip == local_ip:
    mac = _get_local_mac(ip)
    vendor = lookup_mac_vendor(mac)
    hostname = socket.getfqdn()
    return HostResult(..., method="LOCAL", os_hint="Local Machine")
```

`_get_local_mac()` tries: `/sys/class/net/<iface>/address` (Linux), `psutil.net_if_addrs()` (cross-platform), then Scapy `get_if_hwaddr()`.

---

### 5.5 portscan.py — Port Scanning Engine

`portscan.py` implements three scan types dispatched by `scan_ports()`.

**`PortState` enum:**

```python
class PortState(str, Enum):
    OPEN          = "open"          # Host accepted the connection
    CLOSED        = "closed"        # Host sent RST (port exists, nothing listening)
    FILTERED      = "filtered"      # No response (firewall dropping packets)
    OPEN_FILTERED = "open|filtered" # UDP ambiguity — no response could mean either
```

**TCP Connect Scan (`-S T`, default)**

Uses Python's `socket.create_connection()` which performs a full TCP 3-way handshake (SYN → SYN-ACK → ACK). This is the most compatible scan method and requires no root privileges.

Port state classification:
- Connection succeeds → `OPEN`
- `ConnectionRefusedError` (RST-ACK) → `CLOSED`
- `socket.timeout` or `TimeoutError` → `FILTERED`
- `OSError` → `FILTERED`

The scan uses `concurrent.futures.ThreadPoolExecutor` with up to 500 worker threads. All 1,000 default ports are probed in parallel, making the total scan time approximately equal to one connection timeout (1.5s at T4).

**SYN Scan (`-S S`, requires root)**

Uses Scapy to craft a raw TCP SYN packet and analyse the response:

```python
pkt = IP(dst=host) / TCP(dport=port, sport=RandShort(), flags="S")
resp = sr1(pkt, timeout=timeout, verbose=False)
```

Response classification:
- SYN-ACK (flags `0x12`) → `OPEN`. Ymap immediately sends an RST to cleanly tear down the half-open connection:
  ```python
  rst = IP(dst=host) / TCP(dport=port, sport=resp[TCP].dport, flags="R", seq=resp[TCP].ack)
  ```
- RST-ACK (flags `0x14`) → `CLOSED`
- No response → `FILTERED`
- ICMP type 3 (unreachable) → `FILTERED`

SYN scanning is stealthier than TCP Connect because the connection is never fully established. Many basic firewalls and intrusion detection systems log only completed connections.

**UDP Scan (`-S U`, requires root)**

Sends an empty UDP datagram and analyses the response:

```python
pkt = IP(dst=host) / UDP(dport=port)
resp = sr1(pkt, timeout=timeout, verbose=False)
```

Response classification:
- UDP reply received → `OPEN`
- ICMP type 3 (port unreachable) → `CLOSED`
- No response → `OPEN_FILTERED` (ambiguous — the service may be open but not responding to empty payloads, or the packet was dropped)

UDP scanning is slow because filtered ports produce no response, forcing Ymap to wait for the full timeout on every filtered port.

**Service name lookup (`service_name()`)**

Each port result is annotated with a service name. The lookup uses a hardcoded dictionary of 60+ common ports first (for speed), then falls back to `socket.getservbyport()` which queries the OS's `/etc/services` file.

---

### 5.6 fingerprint.py — Version and OS Detection

`fingerprint.py` provides two capabilities: service version detection using protocol-specific probes, and OS fingerprinting using multiple methods.

**Service Version Detection**

The core function is `detect_service_version(host, port, timeout)`. It dispatches to a protocol-specific grabber based on port number using a dispatch table:

```python
_PORT_GRABBERS = {
    21:    _grab_ftp,
    22:    _grab_ssh,
    25:    _grab_smtp,
    80:    _grab_http,
    443:   lambda h, p, t: _tls_banner(h, p, t),
    3306:  _grab_mysql,
    6379:  _grab_redis,
    ...
}
```

If no protocol-specific grabber is registered for a port, `_generic_banner()` is used — it simply reads whatever bytes the service sends on connection.

**Per-protocol grabbers:**

| Protocol | Method | What is extracted |
|---|---|---|
| **SSH** | Read first 256 bytes on connect | Protocol banner: `SSH-2.0-OpenSSH_8.9p1 Ubuntu` |
| **HTTP** | `HEAD / HTTP/1.1` request with `Host:` header | `Server:` header; fallback to `X-Powered-By:` |
| **HTTPS** | TLS handshake | Certificate CN, TLS version, then `Server:` header via HEAD |
| **FTP** | Read 220 greeting | Full service banner after `220 ` |
| **SMTP** | Read 220 greeting | Postfix/Sendmail/Exim version string |
| **POP3** | Read `+OK` greeting | Dovecot/Courier version |
| **IMAP** | Read `* OK` greeting | Service name and version |
| **MySQL/MariaDB** | Parse binary greeting packet | Version string at fixed byte offset (byte 5+) in the initial handshake |
| **Redis** | Send `INFO server\r\n`, parse response | `redis_version:x.x.x` line |
| **Memcached** | Send `stats\r\n`, parse response | `STAT version x.x.x` line |
| **Elasticsearch** | `GET /` JSON response | `version.number` field |
| **VNC** | Read `RFB x.x\n` protocol banner | Protocol version string |

**MySQL binary protocol note:**

The MySQL greeting packet has the following structure:
```
bytes 0-3:  packet length (3 bytes) + sequence number (1 byte)
byte 4:     protocol version (always 0x0a = 10 for modern MySQL)
bytes 5+:   null-terminated version string (e.g., "8.0.30-MySQL Community Server")
```

Ymap reads this packet and extracts the version using:
```python
if data[4] == 0x0a:
    end = data.find(b'\x00', 5)
    ver = data[5:end].decode("ascii", errors="replace")
```

This correctly identifies both MySQL (`8.0.30`) and MariaDB (`10.6.7-MariaDB`).

**TLS Certificate extraction:**

For HTTPS and other TLS-wrapped ports, Ymap wraps the socket with `ssl.SSLContext`:

```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE  # accept self-signed certs
with ctx.wrap_socket(raw, server_hostname=host) as tls:
    cert = tls.getpeercert()
    cn   = dict(x[0] for x in cert.get("subject", []))["commonName"]
```

The TLS version and certificate CN are returned. A `HEAD /` request is then attempted over the TLS channel to also retrieve the `Server:` header.

**OS Fingerprinting (three methods):**

**Method 1: ICMP TTL via Scapy**

Sends an ICMP Echo and reads the TTL of the reply:

```
TTL range   →  OS family
240–260     →  Network Device (Cisco, Juniper, etc.) — default TTL 255
120–130     →  Windows — default TTL 128
60–70       →  Linux / macOS / Android — default TTL 64
250–260     →  Solaris / AIX — default TTL 254
< 60        →  Unknown or unusual
```

Each hop across a router decrements TTL by 1, so a host 3 hops away with an initial TTL of 128 (Windows) will have TTL=125 when observed. The ranges account for up to ~30 hops.

**Method 2: subprocess ping TTL**

Same TTL analysis but uses the OS ping binary instead of Scapy. Works without root privileges. Parses TTL from ping output using `re.search(r'[Tt][Tt][Ll]=(\d+)', out)`.

**Method 3: TCP SYN-ACK window size**

Sends a SYN packet and reads the `window` field in the SYN-ACK response:

```
Window size  →  OS (likely)
65535        →  Windows
32768        →  Linux ≤ 2.6
5840         →  Linux ≥ 3.x
8192         →  Windows XP / Server 2003
16384        →  OpenBSD / FreeBSD
```

Requires Scapy and root.

---

### 5.7 scripting.py — CVE Vulnerability Lookup

`scripting.py` queries the NIST National Vulnerability Database (NVD) REST API v2.0 at:

```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

**Session-only API key**

The API key is stored in a single module-level variable:

```python
_SESSION_KEY: Optional[str] = None
```

It is set by `set_session_api_key()`, retrieved by `get_session_api_key()`, and cleared by `clear_session_api_key()`. The `cli.py` `finally` block calls `clear_session_api_key()` unconditionally when the process exits, ensuring the key is wiped from memory even on error.

The key is validated for minimum length (20 characters) before acceptance:

```python
if len(key) < 20:
    raise ValueError("API key looks too short. Please check and try again.")
```

**Input sanitisation for CVE queries**

All service/version strings are validated before being sent to the NVD API:

```python
_SV_FORBIDDEN = re.compile(r'[;\|&`\$><!\{\}\[\]\(\)\\/~^*?]')
```

This regex rejects common shell-injection and path-traversal characters. Additionally:
- Maximum length: 120 characters
- Must contain at least one letter (a service name with only digits is rejected)
- Final sanitise pass: `re.sub(r"[^a-zA-Z0-9 .\-_/]", "", keyword)[:100]`

**Three CVE query modes:**

**`cve_lookup_broad()` — used by `-C`**

Queries NVD by service name only (with optional version). Returns a wider set of CVEs covering all known vulnerabilities for that service family. Good for a first pass.

```python
keyword = _build_keyword(service, version, precise=False)
# "apache" → search "apache"
# "apache 2.4.41" → also just "apache" (broad)
```

**`cve_lookup_precise()` — used by `-vc`**

Queries NVD with `service + version number`. Returns a narrower set of CVEs that specifically mention that version. More accurate but may miss vulnerabilities that are described without a version number.

```python
keyword = _build_keyword(service, version, precise=True)
# "apache 2.4.41" → search "apache 2.4.41"
```

**`cve_lookup_manual()` — used by `--cve-check`**

The user's validated service/version string is used directly as the NVD keyword. The user controls exactly what is searched.

**Rate limiting:**

NVD enforces rate limits based on whether an API key is provided:

| Mode | Requests per 30 seconds | Delay between requests |
|---|---|---|
| No API key (free tier) | 5 | 6.5 seconds |
| With API key | 50 | 0.7 seconds |

Ymap enforces these delays using a module-level timestamp (`_last_req`) and `time.sleep()` before each request.

**Results caching:**

All NVD responses are cached in memory for 1 hour using a dict keyed by the lowercase keyword:

```python
_CACHE: Dict[str, Tuple[float, List[CVEResult]]] = {}
```

This prevents duplicate API calls when the same service appears on multiple ports (e.g., both port 80 and port 8080 are `http`).

**Error types:**

```python
class CVELookupError(Exception):     # base
class RateLimitError(CVELookupError): # HTTP 429
class InvalidKeyError(CVELookupError):# HTTP 403
```

`InvalidKeyError` additionally wipes the session key from memory immediately:
```python
if resp.status_code == 403:
    clear_session_api_key()
    raise InvalidKeyError("Your NVD API key was rejected...")
```

**CVEResult dataclass:**

```python
@dataclass
class CVEResult:
    cve_id:       str            # "CVE-2021-41773"
    description:  str            # Up to 300 chars
    cvss_score:   Optional[float] # Base score (v3 preferred, v2 fallback)
    cvss_version: Optional[str]   # "3.1", "3.0", or "2.0"
    severity:     Optional[str]   # CRITICAL / HIGH / MEDIUM / LOW
    url:          str             # Auto-set: https://nvd.nist.gov/vuln/detail/{cve_id}
```

CVSS v3 severity thresholds: CRITICAL ≥ 9.0, HIGH ≥ 7.0, MEDIUM ≥ 4.0, LOW < 4.0.

Results are sorted by CVSS score descending (most critical first), capped at 10 per query.

---

### 5.8 output.py — Terminal Output and Reporting

`output.py` handles all display logic. No other module prints anything directly — all output goes through this module. This separation keeps scanner logic clean and allows for future output format changes.

**Rich library integration:**

If Rich is installed, all output is rendered using `Console`, `Table`, `Panel`, and `Rule` objects with coloured terminal output. If Rich is not available, a plain-text fallback path renders identical information without colour.

**Discovery table columns:**

| Column | Source | Notes |
|---|---|---|
| IP ADDRESS | Target IP | Bold white |
| HOSTNAME / NAME | Reverse DNS → NetBIOS → mDNS | `—` if none found |
| MAC ADDRESS | ARP reply | `—` if not on LAN or no root |
| VENDOR | OUI lookup | `"Locally Administered..."` for virtual MACs |
| OS HINT | TTL / SMB | `—` if none detected |
| LATENCY | Measured from first response | Milliseconds |

**Port scan table columns:**

| Column | Source | Shown when |
|---|---|---|
| PORT | Port number | Always |
| PROTO | `tcp` or `udp` | Always |
| STATE | `open`, `closed`, `filtered`, `open\|filtered` | Always |
| SERVICE | OUI database / /etc/services | Always |
| VERSION | Protocol-specific probe result | Only with `-V`, `-A`, `-C`, or `-vc` |
| LATENCY | Milliseconds to connect | Always |

**CVE section rendering:**

Each service gets a Rich `Rule` divider as a heading:
```
──────────── CVEs — apache  |  Version: 2.4.54 ────────────
```

Then a table with columns: CVE ID (clickable URL link in terminals that support it), CVSS score, severity (colour-coded), and description.

**`-vc` note** is always shown after each service section in precise mode, regardless of whether CVEs were found:
```
Note: Version was auto-detected. If the version above is inaccurate,
use --cve-check to manually specify a service version for a more targeted lookup.
```

**Summary panel:**

The `Scan Complete` panel at the end shows:
- Target
- Hosts up
- Ports open
- CVEs found (or `—` if no CVE scan was requested)
- Elapsed time
- Timestamp

**JSON export (`export_json()`):**

Writes a structured report. See Section 14 for the schema.

---

## 6. Library Reference

### Click ≥ 8.1

**What it is:** A Python CLI framework by the Pallets project.

**How Ymap uses it:**
- `@click.command()` wraps `main()` and handles `--help` generation
- `@click.argument("target")` defines the positional TARGET argument
- `@click.option(...)` defines all flags with types, defaults, and help text
- `@click.version_option(...)` provides `--version` output
- `click.IntRange(0, 5)` validates the `-T` timing template is between 0 and 5
- `CaseInsensitiveChoice` subclass makes `-S`/`-s` case-insensitive

Click is used because it handles shell completion, help formatting, error messages, and type conversion automatically. It eliminates hundreds of lines of manual `argparse` boilerplate.

---

### Rich ≥ 13.0

**What it is:** A Python library for rich text and beautiful terminal formatting.

**How Ymap uses it:**

| Rich class | Used for |
|---|---|
| `Console` | Singleton output target; all `console.print()` calls |
| `Table` | Discovery results, port scan results, CVE findings |
| `Panel` | Scan Complete summary, --about box |
| `Rule` | CVE section dividers with service name heading |
| `Text` | Styled text in the summary panel |
| `box.ROUNDED` | Table border style |
| `box.SIMPLE_HEAVY` | CVE table border style |

Rich markup syntax `[bold red]text[/bold red]` is used inline in print strings. The `cprint()` helper in `output.py` strips this markup when Rich is unavailable.

---

### Scapy ≥ 2.5

**What it is:** A powerful Python packet manipulation library that allows raw socket operations.

**How Ymap uses it:**

| Scapy function/class | Used for |
|---|---|
| `ARP(pdst=ip)` | Layer-2 ARP request for host discovery |
| `Ether(dst="ff:ff:ff:ff:ff:ff")` | Broadcast Ethernet frame |
| `srp(pkt, ...)` | Send ARP, receive response (Layer 2) |
| `IP(dst=ip) / ICMP()` | ICMP Echo Request for host discovery |
| `sr1(pkt, ...)` | Send packet, receive one response |
| `IP(dst=host) / TCP(flags="S")` | SYN packet for port scanning |
| `IP(dst=host) / UDP(dport=port)` | UDP probe for UDP scanning |
| `RandShort()` | Random source port for SYN/UDP probes |
| `get_if_hwaddr(iface)` | Get MAC address of local interface |
| `conf.verb = 0` | Suppress verbose output |
| `conf.logLevel = 40` | Suppress routing/MAC warnings |

Scapy operates at the raw socket level (below TCP/IP), which is why root privileges are required for SYN, UDP, and ICMP operations.

---

### requests ≥ 2.28

**What it is:** The standard Python HTTP library.

**How Ymap uses it:**

Used exclusively in `scripting.py` to query the NIST NVD API:

```python
resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"keywordSearch": keyword, "resultsPerPage": 10},
    headers={"User-Agent": "Ymap/1.0.0", "apiKey": key},
    timeout=15,
)
```

The `params` dict ensures keyword values are URL-encoded by requests — preventing any URL injection. The API key is placed in the request header, not the URL, so it does not appear in server logs or browser history.

---

### mac-vendor-lookup ≥ 0.1.11

**What it is:** A Python library that ships a bundled copy of the IEEE OUI (Organizationally Unique Identifier) database for offline MAC vendor lookup.

**How Ymap uses it:**

```python
_mac_lookup = MacLookup()
vendor = _mac_lookup.lookup("00:50:56:AA:BB:CC")  # → "VMware, Inc."
```

The library loads the OUI database from a local file on import — no internet connection is needed during scans. Ymap normalises MACs to uppercase colon-separated format before lookup, and checks the locally-administered bit to avoid unnecessary lookups for virtual MACs.

---

### psutil ≥ 5.9

**What it is:** A cross-platform library for system and process information.

**How Ymap uses it:**

Used in `discovery.py`'s `_get_local_mac()` to enumerate network interfaces on all platforms:

```python
import psutil
LINK_FAMILIES = {17, 18, -1}  # AF_PACKET (Linux), AF_LINK (macOS)
for iface, addrs in psutil.net_if_addrs().items():
    for addr in addrs:
        if addr.family in LINK_FAMILIES and addr.address:
            return addr.address  # MAC address
```

This is the fallback when `/sys/class/net` is unavailable (macOS, Windows). `AF_PACKET = 17` on Linux; `AF_LINK = 18` on macOS.

---

### Python standard library modules

| Module | Used for |
|---|---|
| `socket` | TCP/UDP connect probes, DNS resolution, NetBIOS/mDNS queries |
| `ssl` | TLS wrapping for HTTPS, IMAPS, SMTPS banner grabbing |
| `subprocess` | Calling system `ping` for no-root ICMP |
| `concurrent.futures` | `ThreadPoolExecutor` for parallel port scanning |
| `ipaddress` | Validating and expanding CIDR/IP ranges |
| `re` | Input validation, banner parsing, version extraction |
| `struct` | Not currently used (was used for NetBIOS; now raw bytes) |
| `json` | Parsing NVD API responses, writing JSON reports |
| `getpass` | Masked API key input (key hidden while typing) |
| `logging` | Suppressing Scapy log output |
| `warnings` | Suppressing Scapy warning output |
| `time` | Probe timing, rate-limit delays, elapsed time |
| `os` | Reading `/sys/class/net` for interface MAC addresses |
| `dataclasses` | `HostResult`, `PortResult`, `CVEResult` data structures |
| `enum` | `PortState` enumeration |

---

## 7. Flag Reference

All flags work in both uppercase and lowercase. For example, `-A` and `-a` are identical.

---

### `-A` / `-a` — Aggressive Scan

**Requires root.** The most powerful single flag — enables all scan capabilities in one command.

**What it enables internally:**
```
do_discovery = True   (ping sweep before scanning)
do_version   = True   (banner grab all open ports)
do_os        = True   (OS fingerprinting)
do_cve       = True   (broad CVE lookup)
scan_type    = "S"    (SYN scan instead of TCP Connect)
```

**When to use it:** Full pentesting recon on a target. Combines everything.

```bash
# Aggressive scan of a single host
sudo ymap -A 192.168.1.100

# Aggressive scan + save JSON report
sudo ymap -A 192.168.1.100 --json report.json

# Aggressive scan with custom port range
sudo ymap -A -P 1-10000 192.168.1.100

# Aggressive scan at stealth timing
sudo ymap -A -T 1 192.168.1.100
```

---

### `-B` / `-b` — Basic Scan (default)

**No root required.** TCP Connect scan on the top 1,000 ports. This is the default mode when no scan flag is specified.

```bash
# These are equivalent:
ymap 192.168.1.100
ymap -B 192.168.1.100

# With custom ports:
ymap -B -P 80,443,8080 192.168.1.100
```

---

### `-C` / `-c` — Broad CVE Check

**No root required.** Queries the NIST NVD API for CVEs matching each detected open service. Automatically enables version detection (`-V`) so there is context for the CVE lookup.

The query is **broad** — it searches by service name with an optional version number, returning all known CVEs for that service family. Use `-vc` for more targeted results.

```bash
# CVE check on default ports
ymap -C 192.168.1.100

# CVE check on specific ports (version detected automatically)
ymap -C -P 22,80,443 192.168.1.100

# Combined with aggressive scan
sudo ymap -A -C 192.168.1.100
```

---

### `-VC` / `-vc` — Version-Precise CVE Check

**No root required.** Queries the NVD using the exact detected service version. Returns a smaller, more targeted set of CVEs that specifically mention that version number.

After every service section, a note is displayed:

> *Note: Version was auto-detected. If the version above is inaccurate, use --cve-check to manually specify a service version for a more targeted lookup.*

This note appears regardless of whether vulnerabilities were found.

```bash
# Precise CVE check — only CVEs matching the detected version
ymap -vc 192.168.1.100

# Combined with port selection
ymap -vc -P 22,80,443,3306 192.168.1.100
```

---

### `--cve-check "SERVICE VERSION[, ...]"` — Manual CVE Lookup

**No root required.** Lets you manually specify one or more service version strings to look up in the NVD. This bypasses automatic version detection entirely.

Accepts a comma-separated or semicolon-separated list. Each entry is individually validated and sanitised before being sent to the NVD API.

**Security validation applied to each entry:**
- Rejects shell-injection characters: `;`, `|`, `&`, `` ` ``, `$`, `>`, `<`, `!`, `{}`, `[]`, `()`, `\`, `/`, `~`, `^`, `*`, `?`
- Maximum 120 characters per entry
- Must contain at least one letter

```bash
# Single lookup
ymap --cve-check "vsFTPd 2.3.4" 192.168.1.100

# Multiple lookups in one command
ymap --cve-check "OpenSSH 7.4, Apache 2.4.41" 192.168.1.100

# Can be combined with a scan
ymap -V --cve-check "nginx 1.18.0" 192.168.1.100

# Semicolon separator also accepted
ymap --cve-check "MySQL 5.7.0; PostgreSQL 9.6" 192.168.1.100

# Check without scanning any ports (just CVE lookup)
ymap --cve-check "Samba 4.5.0" 127.0.0.1
```

**Error on invalid input:**
```bash
ymap --cve-check "bad; rm -rf /" 192.168.1.1
# Output: [!] --cve-check input error: Invalid character ';' in service/version input.
```

---

### `-D` / `-d` — Host Discovery

**Requires root for best results** (ARP and ICMP methods). Performs a ping sweep of the target range and displays which hosts are up with hostname, MAC, vendor, OS hint, and latency. Does not port-scan.

```bash
# Discover all hosts on a /24 subnet
sudo ymap -D 192.168.1.0/24

# Discover a range
sudo ymap -D 10.0.0.1-50

# Faster discovery at T5
sudo ymap -D -T 5 192.168.1.0/24
```

**Output columns:**
- IP ADDRESS
- HOSTNAME / NAME (reverse DNS, then NetBIOS, then mDNS)
- MAC ADDRESS (ARP only, local subnet)
- VENDOR (OUI database lookup)
- OS HINT (TTL-based or SMB)
- LATENCY

---

### `-O` / `-o` — OS Fingerprinting

**Requires root for full functionality.** Attempts to identify the operating system of the target using three methods in order: Scapy ICMP TTL, subprocess ping TTL, TCP window size.

Results include a confidence indicator: `Windows [TTL=128, high confidence]`.

```bash
sudo ymap -O 192.168.1.100

# Combined with port scan
sudo ymap -O -V 192.168.1.100

# Part of aggressive scan (enabled automatically)
sudo ymap -A 192.168.1.100
```

---

### `-V` / `-v` — Service Version Detection

**No root required.** After port scanning, connects to each open port and uses a protocol-specific probe to extract the service name and version. Adds a VERSION column to the results table.

Without this flag (or `-A`, `-C`, `-vc`), version detection is disabled and the VERSION column does not appear. This keeps basic scans fast.

```bash
# Version detection on top 1000 ports
ymap -V 192.168.1.100

# Version detection on specific ports
ymap -V -P 22,80,443,3306,6379 192.168.1.100

# Version + CVE check together
ymap -V -C 192.168.1.100
```

---

### `-P` / `-p` — Port Specification

**Default: `top1000`** (Nmap's top 1,000 most common ports).

Accepts four formats:

| Format | Example | Meaning |
|---|---|---|
| `top1000` | `-P top1000` | Default: Nmap's top 1,000 ports |
| Comma list | `-P 22,80,443` | Exactly those ports |
| Range | `-P 1-1000` | Ports 1 through 1000 inclusive |
| All ports | `-P -` or `-P-` | All 65,535 ports |

```bash
# Top 1000 (default)
ymap 192.168.1.100

# Common web ports only
ymap -P 80,443,8080,8443 192.168.1.100

# First 10,000 ports
ymap -P 1-10000 192.168.1.100

# All ports (slow — up to 65,535 probes)
ymap -P- 192.168.1.100

# All ports with faster timing
ymap -P- -T 5 192.168.1.100
```

---

### `-T` / `-t` — Timing Template

**Default: 4.** Controls the aggressiveness of the scan in terms of connection timeouts and delay between probes.

| Template | Name | Connect timeout | Inter-probe delay | Use case |
|---|---|---|---|---|
| `-T 0` | Paranoid | 5.0s | 500ms | Maximum stealth, IDS evasion |
| `-T 1` | Sneaky | 4.0s | 250ms | Low-noise recon |
| `-T 2` | Polite | 3.0s | 100ms | Minimal load on target |
| `-T 3` | Normal | 2.0s | 50ms | Balanced |
| `-T 4` | Aggressive | 1.5s | 10ms | **Default** — fast on LAN |
| `-T 5` | Insane | 0.5s | 0ms | Maximum speed, may miss filtered ports |

```bash
# Stealth scan (very slow)
sudo ymap -T 0 -S S 192.168.1.100

# Default fast scan
ymap 192.168.1.100

# Maximum speed scan
ymap -T 5 -P 80,443 192.168.1.100
```

---

### `-S` / `-s` — Scan Type

**Default: `T` (TCP Connect)**. Selects the underlying probe method.

| Option | Name | Mechanism | Root? |
|---|---|---|---|
| `T` or `t` | TCP Connect | Full 3-way handshake via `socket.create_connection()` | No |
| `S` or `s` | SYN (half-open) | Raw SYN packet via Scapy; RST to clean up | Yes |
| `U` or `u` | UDP | Raw UDP datagram via Scapy | Yes |

```bash
# Default TCP Connect scan
ymap -S T 192.168.1.100
# or simply:
ymap 192.168.1.100

# SYN scan (stealthy, needs root)
sudo ymap -S S 192.168.1.100
# lowercase also works:
sudo ymap -s s 192.168.1.100

# UDP scan
sudo ymap -S U -P 53,67,123,161 192.168.1.100
```

---

### `--json FILE` — JSON Report Export

Saves a complete structured JSON report to the specified file path after the scan completes.

```bash
# Save report to current directory
ymap -A 192.168.1.100 --json report.json

# Save to absolute path
sudo ymap -A 192.168.1.0/24 --json /tmp/network_scan.json
```

See Section 14 for the complete JSON schema.

---

### `--closed` — Show Closed/Filtered Ports

By default, the port table shows only open (or open|filtered) ports. `--closed` adds all closed and filtered ports to the table.

```bash
ymap --closed 192.168.1.100
ymap --closed -P 1-100 192.168.1.100
```

---

### `--add-nvd-api-key` — Add NVD API Key (Session-Only)

Prompts for a NIST NVD API key using `getpass.getpass()` so the key is hidden while typing. The key is validated (minimum 20 characters), stored in process memory for this session only, and cleared when the process exits.

**Security properties:**
- Input masked (does not appear on screen)
- Never written to disk, config files, shell history, or environment variables
- Wiped from memory unconditionally in the `finally` block on exit
- Rejected if too short (< 20 chars)
- Invalidated immediately if NVD returns HTTP 403

```bash
# Add key then run CVE scan
ymap --add-nvd-api-key -C 192.168.1.100

# Add key then run aggressive scan
sudo ymap --add-nvd-api-key -A 192.168.1.100

# Key is prompted interactively:
#   Paste your NVD API key: ************************************
#   ✔  API key accepted for this session.
```

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

---

### `--about`

Displays a Rich panel with version, author, license, and CVE key information, then exits.

```bash
ymap --about
```

---

### `--help` / `-help`

Displays the full usage guide with examples. Available as both `--help` and `-help`.

```bash
ymap --help
ymap -help
```

---

### `--version`

Prints the Ymap version and exits.

```bash
ymap --version
# ymap, version 1.0.0
```

---

## 8. Scan Pipeline — End to End

This section traces exactly what happens when a user runs:

```bash
sudo ymap -A -C 192.168.1.1
```

**Step 1: cli.py receives the command**
- Click parses `-A` → `aggressive=True`, `-C` → `cve=True`, target → `"192.168.1.1"`
- No `--cve-check`, no `--add-nvd-api-key`
- `_warn_root()` is not called because `-A` implies root is expected

**Step 2: ScanConfig is built**
- `validate_target("192.168.1.1")` passes
- Because `aggressive=True`:
  - `do_discovery = True`
  - `do_version = True`
  - `do_os = True`
  - `do_cve = True`
  - `scan_type = "S"`
- `port_list = NMAP_TOP_1000` (1,000 ports)

**Step 3: core.py run_scan()**
- `is_root()` check passes (sudo was used)
- `is_multi` is False (single IP)
- `_host_is_reachable("192.168.1.1", 1.5)` → ping subprocess → yes
- `hosts_to_scan = ["192.168.1.1"]`

**Step 4: Discovery phase**
- `discover("192.168.1.1", ...)` is called because `do_discovery=True`
- `_probe_host()` tries ARP → gets MAC `AA:BB:CC:DD:EE:FF`
- `lookup_mac_vendor("AA:BB:CC:DD:EE:FF")` → `"Apple, Inc."`
- `resolve_device_name()` → reverse DNS → `"Johns-MacBook.local"`
- `_smb_os_detect()` — port 445 not open, returns None
- OS hint from ARP: None (ARP doesn't give TTL)
- `_icmp_ping_scapy()` returns TTL=64 → OS hint: `"Linux / macOS [TTL=64]"`
- `output.print_discovery()` renders discovery table

**Step 5: Port scan**
- `scan_ports("192.168.1.1", NMAP_TOP_1000, scan_type="S", timing=4)`
- `syn_scan()` dispatched
- 1,000 SYN packets sent via `ThreadPoolExecutor(max_workers=300)`
- Results: ports 22, 80, 443 are OPEN; rest are CLOSED or FILTERED

**Step 6: Version detection**
- `detect_service_version("192.168.1.1", 22, timeout=1.5)` → `_grab_ssh()` → `"OpenSSH_8.9p1"`
- `detect_service_version("192.168.1.1", 80, timeout=1.5)` → `_grab_http()` → `"Apache/2.4.54 (Ubuntu)"`
- `detect_service_version("192.168.1.1", 443, timeout=1.5)` → `_tls_banner()` → `"Apache/2.4.54 | TLSv1.3"`
- Results stored in `pr.banner` for each open PortResult

**Step 7: OS fingerprinting**
- `detect_os("192.168.1.1", open_ports=[22, 80, 443], timeout=1.5)`
- `_os_icmp_scapy()` → TTL=64 → `"Linux / macOS / Android [TTL=64, high confidence]"`
- Result stored and displayed in the scan table title

**Step 8: Port table rendered**
- `output.print_scan_results()` renders the ROUNDED table with VERSION column

**Step 9: CVE lookup**
- Services list built: `[{service: "ssh", version: "OpenSSH_8.9p1"}, {service: "http", version: "Apache/2.4.54"}, ...]`
- `bulk_cve_lookup(services_list, precise=False)` → calls `cve_lookup_broad()` for each
- NVD API queried with 6.5s delays between calls
- Results: CVE-2023-xxxxx for Apache, etc.
- `output.print_cve_results()` renders CVE tables with headings

**Step 10: Summary**
- `output.print_summary()` renders the Scan Complete panel

---

## 9. CVE Lookup System

### How the NVD API works

The NIST NVD REST API v2.0 accepts keyword searches and returns a JSON document containing a list of CVE vulnerabilities that match. Ymap queries:

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?keywordSearch=apache%202.4.54
    &resultsPerPage=10
    &startIndex=0
```

The response contains an array of `vulnerabilities`, each with:
- CVE ID
- Description (in multiple languages; Ymap selects `lang: "en"`)
- CVSS metrics (v3.1, v3.0, or v2.0 depending on age of CVE)

### Choosing between `-C`, `-vc`, and `--cve-check`

| Flag | Query sent | Best for |
|---|---|---|
| `-C` | `"apache"` | Wide survey; finds all known Apache CVEs |
| `-vc` | `"apache 2.4.54"` | Targeted; finds CVEs for that specific version |
| `--cve-check "Apache 2.4.54"` | `"Apache 2.4.54"` | Manual override when auto-detect is wrong |

### Rate limiting in practice

On a scan with 5 open services using the free tier:
- Request 1 at T=0s
- Request 2 at T=6.5s
- Request 3 at T=13.0s
- Request 4 at T=19.5s
- Request 5 at T=26.0s
- Total CVE phase: ~26 seconds

With an API key:
- 5 requests in ~3.5 seconds total

The in-memory cache means if you run multiple scans in the same session against the same services, subsequent lookups are instant.

---

## 10. Security Architecture

### Input validation layers

| Input | Validated by | Method |
|---|---|---|
| TARGET argument | `validate_target()` | IP/CIDR/hostname regex; forbidden char set |
| Port `-P` argument | `validate_ports()` | Integer parsing; range [1, 65535] |
| Timing `-T` argument | `validate_timing()` | `click.IntRange(0, 5)` |
| `--cve-check` string | `parse_manual_cve_input()` | Forbidden char regex + length + letter check |
| NVD API key | `set_session_api_key()` | Minimum length check |
| NVD query keyword | `_build_keyword()` | Final `re.sub(r"[^a-zA-Z0-9 .\-_/]", "", keyword)` |

### Banner data sanitisation

All service banner data is processed through `_clean()` before storage or display:

```python
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

def _clean(raw: bytes, limit: int = 512) -> str:
    return _CTRL_RE.sub("", raw.decode("utf-8", errors="replace")).strip()[:limit]
```

This prevents terminal escape sequence injection (where a crafted banner could clear the screen, move the cursor, or even execute commands in some terminal emulators).

### API key security

The NVD API key is:
1. Never stored in any file (no `.env`, no config, no shell history)
2. Input via `getpass.getpass()` — masked, not echoed
3. Stored only in `_SESSION_KEY` (a module-level variable in `scripting.py`)
4. Sent only in HTTP headers, not in URL parameters
5. Wiped by `clear_session_api_key()` in the `finally` block on every exit path
6. Wiped immediately on HTTP 403 (invalid key)

### Privilege model

Raw socket operations (SYN scan, UDP scan, ICMP, ARP) require root because the OS only allows raw socket creation by privileged processes. Ymap checks `os.geteuid() == 0` (Linux/macOS) before initiating any such operation and exits with a clear message if the check fails. It never silently downgrade to a less powerful scan type.

---

## 11. Target Formats

| Format | Example | Expands to |
|---|---|---|
| Single IPv4 | `192.168.1.1` | One host |
| CIDR notation | `10.0.0.0/24` | 254 hosts (10.0.0.1–10.0.0.254) |
| CIDR /30 | `10.0.0.0/30` | 2 hosts (10.0.0.1–10.0.0.2) |
| Last-octet range | `192.168.1.1-50` | 50 hosts (192.168.1.1–192.168.1.50) |
| Hostname | `example.com` | Resolved to IP then scanned |

CIDR expansion uses Python's `ipaddress.ip_network(target, strict=False).hosts()` which correctly excludes the network address and broadcast address.

Hostnames are resolved using `socket.gethostbyname()`. If resolution fails, Ymap exits with an error message rather than proceeding with an unresolvable target.

---

## 12. Timing System

The timing system controls two parameters: `connect_timeout` and `inter_probe_delay`.

**`connect_timeout`** is the maximum time Ymap will wait for a TCP connection (or a packet response in raw mode) before classifying a port as FILTERED. A short timeout misses slow hosts; a long timeout wastes time on dead ports.

**`inter_probe_delay`** is the sleep time between launching individual probe threads. At T4 and T5, this is essentially zero, meaning all 1,000 probes are launched nearly simultaneously. At T0, 500ms between probes means a 1,000-port scan takes over 8 minutes.

The timing template affects both discovery probes and port scan probes. The template value is passed through to `timing_params()` which is called at the start of each phase.

For stealth/IDS-evasion scenarios, T0 combined with SYN scan (`-S S`) gives the slowest, most spaced-out probe pattern — approximately equivalent to Nmap's `-T0 -sS`.

---

## 13. Usage Examples

### Quick reference

```bash
# Basic scan — fastest way to see what's running (no root needed)
ymap 192.168.1.1

# Full pentesting scan — everything enabled
sudo ymap -A 192.168.1.1

# Subnet discovery — find all live hosts + device info
sudo ymap -D 192.168.1.0/24

# Version detection on specific ports
ymap -V -P 22,80,443,3306 192.168.1.1

# CVE check — broad (all services)
ymap -C 192.168.1.1

# CVE check — precise (version-matched)
ymap -vc 192.168.1.1

# Manual CVE lookup for a known service
ymap --cve-check "vsFTPd 2.3.4" 192.168.1.1

# CVE for multiple services at once
ymap --cve-check "OpenSSH 7.4, Apache 2.4.41, MySQL 5.7.0" 192.168.1.1

# SYN scan with OS detection (stealth)
sudo ymap -S S -O -T 2 192.168.1.1

# All 65535 ports
ymap -P- -T 5 192.168.1.1

# Scan with JSON report saved
sudo ymap -A 192.168.1.1 --json /tmp/scan.json

# Show closed/filtered ports too
ymap --closed 192.168.1.1

# Scan with rate-limited NVD lookups accelerated by API key
ymap --add-nvd-api-key -vc 192.168.1.0/24
```

### Pentesting workflow

```bash
# 1. Discover live hosts
sudo ymap -D 192.168.1.0/24

# 2. Scan open ports on a specific host
sudo ymap -A 192.168.1.50

# 3. Investigate a specific service found on a non-standard port
ymap -V -P 2222 192.168.1.50

# 4. Check specific CVE for a manually identified service version
ymap --cve-check "OpenSSH 6.6.1p1" 192.168.1.50

# 5. Full report for documentation
sudo ymap -A -C 192.168.1.50 --json report_192.168.1.50.json
```

### Web application scanning

```bash
# Scan all common web ports with version detection
ymap -V -P 80,443,8080,8443,8000,8888,9000,9090 192.168.1.100

# CVE check on web service only
ymap -vc -P 80,443 192.168.1.100

# Check for known vulnerable web server version
ymap --cve-check "Apache 2.4.49" 192.168.1.100
```

### Database scanning

```bash
# Scan common database ports
ymap -V -P 3306,5432,1433,1521,27017,6379,11211,9200 192.168.1.100

# CVE check for a detected database version
ymap --cve-check "MySQL 5.7.32, PostgreSQL 9.5" 192.168.1.100
```

---

## 14. JSON Report Format

When `--json FILE` is used, Ymap writes a structured JSON file with the following schema:

```json
{
  "meta": {
    "tool": "ymap",
    "version": "1.0.0",
    "target": "192.168.1.1",
    "timestamp": "2024-11-15T14:32:00Z"
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "mac": "AA:BB:CC:DD:EE:FF",
      "mac_vendor": "Apple, Inc.",
      "os_hint": "Linux / macOS [TTL=64]",
      "latency_ms": 0.8,
      "method": "ARP"
    }
  ],
  "os_guess": "Linux / macOS / Android  [TTL=64, high confidence]",
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
      "latency_ms": 1.2
    },
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "Apache/2.4.54 (Ubuntu)",
      "latency_ms": 0.9
    }
  ],
  "cves": {
    "ssh:OpenSSH_8.9p1": [
      {
        "id": "CVE-2023-38408",
        "score": 9.8,
        "severity": "CRITICAL",
        "description": "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2...",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"
      }
    ]
  }
}
```

The `cves` key maps `"service:version"` strings (or just `"service"` if no version was detected) to arrays of CVE objects. If no CVE scan was run, `"cves"` is an empty object `{}`.

---

## 15. Platform Differences

### Linux
- Full functionality with `sudo`
- ARP, ICMP, SYN, UDP scans all available
- MAC detection via `/sys/class/net/<iface>/address`
- NetBIOS and mDNS work well on local networks
- Python 3.8+ recommended

### macOS
- Full functionality with `sudo`
- ARP and ICMP work via Scapy
- MAC detection via `psutil.net_if_addrs()` (AF_LINK family)
- NetBIOS queries work; mDNS replies depend on target device configuration
- Python 3.9+ recommended; tested on 3.14

### Windows
- Basic TCP Connect scans work without extra setup
- SYN/UDP/ICMP scans require Npcap (https://npcap.com) for Scapy raw socket support
- MAC detection via `psutil` (AF_LINK family 18 or -1)
- Python 3.8+ required

### Network differences (Kali vs macOS on hotspot)

Users on Kali Linux (typically on a physical LAN) get more device information than users on macOS connected to a mobile hotspot because:

1. **ARP only works on the local Layer-2 network.** On a mobile hotspot, the phone acts as a NAT gateway. Your device and the phone are on the same Layer-2 segment, but other devices' traffic is routed through the phone's NAT. ARP requests for hosts behind the NAT never receive replies.

2. **NetBIOS and mDNS are broadcast/multicast protocols** that do not cross NAT boundaries. Devices on the other side of the hotspot NAT cannot respond.

3. **ICMP TTL results are identical** — ping still works, and TTL-based OS detection is unaffected.

The code is correct; this is a fundamental network topology difference.

---

## 16. Known Limitations

**UDP scanning accuracy**

UDP services that do not respond to empty datagrams are classified as `open|filtered` rather than `open`. Protocol-specific UDP probes (e.g., a DNS query to port 53) would improve accuracy but are not currently implemented.

**OS detection confidence**

TTL-based OS detection has inherent ambiguity. A Linux host 10 hops away will have TTL=54, which falls in the "Unknown" range (< 60). Hosts very close (1-2 hops) will have TTLs very close to their initial value and are accurately identified. SMB detection only works for Windows hosts with port 445 open.

**NVD API accuracy**

CVE lookup accuracy depends on how well service versions are detected. A service that hides or falsifies its version banner (e.g., `ServerTokens Prod` in Apache httpd) will produce less targeted CVE results. The `--cve-check` flag exists specifically to handle this case by letting you provide the actual version manually.

**IPv6**

Ymap currently supports IPv4 only. IPv6 targets are not accepted.

**Very large networks**

Scanning `/16` or larger networks (65,535+ hosts) is technically supported but may take considerable time. For networks larger than `/22`, consider using discovery (`-D`) first to identify live hosts, then scan each selectively.

**Mobile hotspot false positives (mitigated)**

On mobile hotspot NAT networks, TCP RST responses from the NAT are filtered out. Subprocess ping replies with TTL < 10 are rejected. Only ARP, genuine ICMP Echo Reply from the target IP, or a successful TCP connection is accepted as proof of a live host.

---

*Ymap v1.0.0 — Yung Mapper*  
*Author: Adekunle Abdulmujeeb*  
*License: MIT*  
*GitHub: https://github.com/sudoer0x0/ymap.git*
