# Ymap — Yung Mapper 🗺️

> Lightweight, easy-to-remember network scanner built in Python.  
> Developer: **Adekunle Abdulmujeeb** · Version: **1.0.0**

---

## Installation

```bash
pip3 install ymap
# or from source:
git clone https://github.com/sudoer0x0/ymap.git && cd ymap && pip3 install .
```

---

## Quick-Start

```bash
ymap 192.168.1.1                     # Basic scan, top 1000 ports (no root)
sudo ymap -A 10.0.0.5                # Aggressive: SYN + version + OS + CVE
sudo ymap -D 192.168.1.0/24          # Discover live hosts + device info
ymap -C 192.168.1.1                  # CVE check (version auto-detected)
ymap -V -P 22,80,443 example.com     # Version detect on specific ports
sudo ymap -A target --json out.json  # Full scan + save JSON report
ymap -P- 10.0.0.1                    # Scan all 65535 ports
```

---

## Flag Reference

| Flag | What it does | Root? |
|------|-------------|-------|
| `-A` | Aggressive: SYN + Version + OS + CVE | Yes |
| `-B` | Basic TCP Connect, top 1000 ports (default) | No |
| `-C` | CVE lookup via NIST NVD (auto-enables `-V`) | No |
| `-D` | Host discovery / ping sweep | Yes |
| `-O` | OS fingerprinting (TTL + TCP window + SMB) | Yes |
| `-V` | Service version / banner detection | No |
| `-P` | Ports: `80,443` / `1-1000` / `-` / `top1000` | — |
| `-T` | Timing: 0=stealth … 5=insane (default: 4) | — |
| `-S` | Scan type: `T`=Connect, `S`=SYN, `U`=UDP | S/U: Yes |
| `--json FILE` | Save JSON report | — |
| `--closed` | Show closed/filtered ports too | — |
| `--add-nvd-api-key` | Add a session-only NVD API key | — |

---

## CVE Lookup & API Key

CVE lookups work **without any API key** (free tier: 5 requests/30s).

If you hit rate limits, add a free key for this session:

```bash
ymap --add-nvd-api-key -C 192.168.1.1
```

You'll be prompted to paste your key. It is:
- Used for this terminal session only
- **Never saved to disk, config, or any file**
- Cleared from memory when the terminal closes

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

---

## Discovery Output

The `-D` flag (or implicit for subnets) shows per-host:

| Column | Source |
|--------|--------|
| IP Address | — |
| Hostname / Name | Reverse DNS, then NetBIOS (UDP 137), then mDNS (UDP 5353) |
| MAC Address | ARP reply (local subnet, root required) |
| Vendor | OUI lookup via local database (mac-vendor-lookup) |
| OS Hint | ICMP TTL → ping TTL → SMB dialect → TCP window |
| Latency | Measured from first response |

---

## OS Detection Methods (in order)

1. **ICMP TTL via Scapy** — root + Scapy, highest accuracy
2. **ICMP TTL via system ping** — no root needed, good accuracy
3. **SMB dialect negotiation** — exact Windows version (port 445)
4. **TCP SYN-ACK window size** — Scapy, medium confidence

Result example: `Windows [TTL=128]` or `Windows Server 2022` (from SMB)

---

## Architecture

```
ymap/
├── cli.py          Click CLI — flags, --add-nvd-api-key, --help, --about
├── core.py         Pipeline orchestrator
├── discovery.py    Host discovery (ARP/ICMP/ping/TCP) + device naming
├── portscan.py     Port scanning (Connect / SYN / UDP)
├── fingerprint.py  Version detection + OS fingerprinting
├── scripting.py    CVE lookup — session-only API key, rate-limit handling
├── output.py       Rich terminal tables + JSON export
└── utils.py        Validation, top-1000 port list, helpers
```

---

## Independent — No Nmap Required

Ymap is fully self-contained. It uses:
- **Scapy** — raw packet crafting (ARP, ICMP, SYN, UDP)
- **mac-vendor-lookup** — OUI database for device vendor (local, offline)
- **Rich** — terminal UI
- **Click** — CLI
- **requests** — NIST NVD API for CVEs
- **socket / subprocess** — OS-native ping, NetBIOS, mDNS, SMB probes

No Nmap, no external binaries (other than `ping`).

---

## Legal

For **authorised** testing only. Scanning without permission is illegal.  
The author accepts no liability for misuse.

---

## License

MIT © 2026 Adekunle Abdulmujeeb
