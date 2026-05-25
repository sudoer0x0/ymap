"""
core.py — Scan Pipeline Orchestrator for Ymap v1.0.0

CVE modes:
  -C            Broad CVE lookup per open service
  -VC           Precise CVE lookup using detected service version
  --cve-check   Manual CVE lookup for user-supplied service:version strings
"""

import time
import socket
import logging
import warnings
import re
from typing import List, Optional, Dict

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

from ymap.utils import (
    validate_target, validate_ports, validate_timing,
    expand_targets, is_ip, require_root, is_root,
    timing_params, NMAP_TOP_1000,
)
from ymap.discovery import discover, HostResult
from ymap.portscan import scan_ports, PortResult, PortState, service_name
from ymap.fingerprint import detect_service_version, extract_version, detect_os
from ymap.scripting import (
    bulk_cve_lookup, cve_lookup_manual,
    parse_manual_cve_input, validate_service_version,
    CVEResult, RateLimitError, InvalidKeyError, NetworkError,
    get_session_api_key,
)
from ymap import output


# ---------------------------------------------------------------------------
# Scan Config
# ---------------------------------------------------------------------------

class ScanConfig:
    def __init__(
        self,
        target: str,
        aggressive: bool        = False,
        basic: bool             = False,
        cve: bool               = False,
        version_cve: bool       = False,   # -w
        manual_cve: Optional[List[str]] = None,  # --cve-check validated items
        discovery_only: bool    = False,
        os_detect: bool         = False,
        version_detect: bool    = False,
        ports: str              = "top1000",
        timing: int             = 4,
        scan_type: str          = "T",
        output_json: Optional[str] = None,
        show_closed: bool       = False,
    ):
        self.target      = validate_target(target)
        self.timing      = validate_timing(timing)
        self.scan_type   = scan_type.upper()
        self.output_json = output_json
        self.show_closed = show_closed
        self.manual_cve  = manual_cve or []  # already validated list of strings

        if aggressive:
            self.do_discovery   = True
            self.do_port_scan   = True
            self.do_version     = True
            self.do_os          = True
            self.do_cve         = True
            self.do_version_cve = False
            self.scan_type      = "S"
        else:
            self.do_discovery   = discovery_only
            self.do_port_scan   = not discovery_only
            # Version forced on when CVE or version-CVE mode is active
            self.do_version     = version_detect or cve or version_cve
            self.do_os          = os_detect
            self.do_cve         = cve
            self.do_version_cve = version_cve

        if ports in ("top1000", "1-1000", ""):
            self.port_list = NMAP_TOP_1000
        elif ports.strip() == "-":
            self.port_list = list(range(1, 65536))
        else:
            self.port_list = validate_ports(ports)


# ---------------------------------------------------------------------------
# Reachability check
# ---------------------------------------------------------------------------

def _host_is_reachable(host: str, timeout: float) -> bool:
    """Quick reachability check for a single host before a full port scan."""
    import subprocess as _sp, re as _re, platform as _plat, socket as _sock
    try:
        is_win = _plat.system() == "Windows"
        t = max(1, int(min(timeout, 2.0)))
        cmd = (["ping","-n","1","-w",str(t*1000),host] if is_win
               else ["ping","-c","1","-W",str(t),host])
        r = _sp.run(cmd, capture_output=True, text=True, timeout=t+1)
        if r.returncode == 0:
            m = _re.search(r'[Tt][Tt][Ll]=(\d+)', r.stdout + r.stderr)
            if not m or int(m.group(1)) >= 10:
                return True
    except Exception:
        pass
    for port in [80, 443, 22, 8080, 445, 3389, 25]:
        try:
            with _sock.create_connection((host, port), timeout=min(timeout, 1.5)):
                return True
        except ConnectionRefusedError:
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# CVE runner helper (handles RateLimitError / InvalidKeyError centrally)
# ---------------------------------------------------------------------------

def _run_cve_lookup(
    services_list: List[Dict],
    precise: bool,
) -> Dict[str, List[CVEResult]]:
    """
    Wrapper around bulk_cve_lookup that raises the error types up so
    core can display them properly exactly once.
    """
    return bulk_cve_lookup(services_list, precise=precise)


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

_IS_MULTI_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$")


def run_scan(cfg: ScanConfig) -> int:
    total_start = time.perf_counter()

    # ── Determine if multi-host target (CIDR or range) ──────────────────
    is_multi = "/" in cfg.target or bool(_IS_MULTI_RE.match(cfg.target))

    # ── Privilege checks ──────────────────────────────────────────────────
    # Discovery (-D) and any CIDR/range target both need root for ARP.
    # Without root, ARP is unavailable and the ping/TCP fallback produces
    # large numbers of false positives on NAT/hotspot networks.
    needs_root = (
        cfg.scan_type in ("S", "U")
        or cfg.do_os
        or cfg.do_discovery
        or is_multi   # CIDR or last-octet range always needs ARP → root
    )
    if needs_root and not is_root():
        if is_multi:
            require_root(
                "Scanning a network range (CIDR/range). "
                "ARP requires root. Without root, results are unreliable on NAT/hotspot."
            )
        else:
            require_root("SYN/UDP scan, OS detection, or host discovery")
        return 0

    # ── Hostname resolution ───────────────────────────────────────────────
    resolved_host = cfg.target

    if not is_ip(cfg.target) and not is_multi:
        try:
            ip = socket.gethostbyname(cfg.target)
            output.cprint(f"  [dim]Resolved {cfg.target} → {ip}[/dim]")
            resolved_host = ip
        except socket.gaierror:
            output.cprint(f"[red]  ✗  Cannot resolve hostname: {cfg.target}[/red]\n")
            return 0

    connect_timeout, _ = timing_params(cfg.timing)

    # ── Host Discovery ────────────────────────────────────────────────────
    hosts_to_scan: List[str] = []
    discovered_hosts: List[HostResult] = []

    if cfg.do_discovery or is_multi:
        output.cprint(
            f"\n[bold cyan][ Discovery ][/bold cyan]  Sweeping {cfg.target} …"
        )
        disc_start = time.perf_counter()
        discovered_hosts = discover(cfg.target, timing=cfg.timing, use_raw=is_root())
        output.print_discovery(discovered_hosts, time.perf_counter() - disc_start)

        if cfg.do_discovery and not cfg.do_port_scan:
            output.print_summary(cfg.target, len(discovered_hosts), 0, 0,
                                  time.perf_counter() - total_start,
                                  False, ports_enabled=False)
            return 0

        if not discovered_hosts:
            if is_multi:
                # CIDR/range: no hosts replied to ARP — genuine empty network
                output.cprint(
                    "[yellow]  No live hosts found. "
                    "Ensure you are on the correct subnet "
                    "and ARP traffic is not blocked.[/yellow]"
                )
                output.print_summary(cfg.target, 0, 0, 0,
                                      time.perf_counter() - total_start,
                                      False, ports_enabled=False)
                return 0
            else:
                # Single IP with -A: ARP got no reply (remote/internet host)
                # Still port-scan — the target is explicit
                output.cprint(
                    f"  [dim]ARP probe returned no reply for {cfg.target} "
                    f"(may be remote or ICMP/ARP blocked). "
                    f"Proceeding with port scan …[/dim]"
                )
                hosts_to_scan = [resolved_host]
        else:
            hosts_to_scan = [h.ip for h in discovered_hosts]
    else:
        output.cprint(
            f"\n[bold cyan][ Ymap ][/bold cyan]  "
            f"Scanning [bold white]{cfg.target}[/bold white] …"
        )
        if not _host_is_reachable(resolved_host, connect_timeout):
            output.print_host_down(cfg.target)
        hosts_to_scan = [resolved_host]

    if not hosts_to_scan:
        output.cprint("[yellow]  No hosts to scan.[/yellow]")
        return 0

    # ── Per-host scan loop ─────────────────────────────────────────────────
    all_port_results: List[PortResult]   = []
    all_cve_map:      Dict[str, List]    = {}
    all_svc_versions: Dict[str, str]     = {}
    final_os: Optional[str]              = None
    rate_limited = False
    invalid_key  = False
    invalid_key_msg = ""

    for host in hosts_to_scan:
        if is_multi:
            output.cprint(
                f"\n[bold cyan][ Scanning ][/bold cyan]  {host}  "
                f"({len(cfg.port_list)} ports · {cfg.scan_type} · T{cfg.timing})"
            )

        # Port scan
        scan_start   = time.perf_counter()
        port_results = scan_ports(
            host, cfg.port_list,
            scan_type=cfg.scan_type, timing=cfg.timing, grab_banner=False,
        )
        scan_elapsed = time.perf_counter() - scan_start
        open_ports   = [r for r in port_results if r.state == PortState.OPEN]

        # Version detection
        if cfg.do_version and open_ports:
            output.cprint(
                f"  [dim]Version detection on {len(open_ports)} open port(s) …[/dim]"
            )
            for pr in open_ports:
                ver = detect_service_version(host, pr.port, timeout=connect_timeout)
                pr.banner = ver or "—"
        elif not cfg.do_version:
            for pr in port_results:
                pr.banner = None

        # OS detection
        os_guess: Optional[str] = None
        if cfg.do_os:
            output.cprint("  [dim]OS fingerprinting …[/dim]")
            os_guess = detect_os(
                host,
                open_ports=[r.port for r in open_ports],
                timeout=connect_timeout,
            )
            final_os = os_guess

        output.print_scan_results(
            host, port_results, os_guess=os_guess, elapsed=scan_elapsed,
            show_closed=cfg.show_closed, show_version=cfg.do_version,
        )
        all_port_results.extend(port_results)

        # ── CVE Lookup ─────────────────────────────────────────────────────
        any_cve_requested = cfg.do_cve or cfg.do_version_cve

        if any_cve_requested and open_ports and not invalid_key:
            output.cprint("  [dim]Querying NIST NVD for CVEs …[/dim]")
            services_list = []
            for r in open_ports:
                svc = service_name(r.port, r.protocol)
                ver = extract_version(r.banner) if (r.banner and r.banner not in ("—", "-")) else None
                svc_key = f"{svc}:{ver}" if (ver and ver not in ("—", "-")) else svc
                all_svc_versions[svc_key] = ver or "—"
                services_list.append({"service": svc, "version": ver})

            try:
                # -VC: precise (version-scoped) lookup
                # -C:  broad lookup
                precise = cfg.do_version_cve
                host_cve_map = _run_cve_lookup(services_list, precise=precise)
                all_cve_map.update(host_cve_map)
                output.print_cve_results(
                    host_cve_map, all_svc_versions, precise=precise,
                )
            except RateLimitError:
                rate_limited = True
            except InvalidKeyError as e:
                invalid_key     = True
                invalid_key_msg = str(e)
            except NetworkError as e:
                output.print_cve_error(str(e))

    # ── Manual CVE lookup (--cve-check) ───────────────────────────────────
    if cfg.manual_cve and not invalid_key:
        output.cprint(
            f"\n[bold cyan][ Manual CVE Lookup ][/bold cyan]  "
            f"{len(cfg.manual_cve)} service version(s) …"
        )
        manual_cve_map: Dict[str, List] = {}
        for sv_str in cfg.manual_cve:
            key = sv_str
            try:
                results = cve_lookup_manual(sv_str)
                manual_cve_map[key] = results
            except RateLimitError:
                rate_limited = True
                break
            except InvalidKeyError as e:
                invalid_key     = True
                invalid_key_msg = str(e)
                break
            except NetworkError as e:
                output.print_cve_error(str(e))
                break
        if manual_cve_map:
            output.print_manual_cve_results(manual_cve_map)
            for v in manual_cve_map.values():
                all_cve_map[f"manual:{len(all_cve_map)}"] = v

    # ── Error advisories ──────────────────────────────────────────────────
    if invalid_key:
        output.print_invalid_key_error(invalid_key_msg)
    elif rate_limited:
        output.print_rate_limit_advisory()

    # ── Summary ────────────────────────────────────────────────────────────
    total_open = sum(1 for r in all_port_results if r.state == PortState.OPEN)
    total_cves = sum(len(v) for v in all_cve_map.values())
    cve_enabled = cfg.do_cve or cfg.do_version_cve or bool(cfg.manual_cve)

    output.print_summary(
        target=cfg.target,
        n_hosts=len(discovered_hosts) if discovered_hosts else len(hosts_to_scan),
        n_open=total_open,
        n_cves=total_cves,
        total_elapsed=time.perf_counter() - total_start,
        cve_enabled=cve_enabled,
    )

    if cfg.output_json:
        output.export_json(cfg.target, discovered_hosts, all_port_results,
                           all_cve_map, final_os, cfg.output_json)

    return total_open
