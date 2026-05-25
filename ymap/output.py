"""
output.py — Terminal Output & Reporting for Ymap v1.0.0
"""

import json
import re as _re
from datetime import datetime
from typing import List, Optional, Dict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from ymap.discovery import HostResult
from ymap.portscan import PortResult, PortState, service_name
from ymap.scripting import CVEResult

console = Console() if RICH_AVAILABLE else None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cprint(msg: str = "", **kwargs):
    if RICH_AVAILABLE and console:
        console.print(msg, **kwargs)
    else:
        plain = _re.sub(r"\[/?[^\]]+\]", "", msg)
        print(plain)


_STATE_COLOUR = {
    PortState.OPEN:          "bold green",
    PortState.CLOSED:        "red",
    PortState.FILTERED:      "yellow",
    PortState.OPEN_FILTERED: "cyan",
}
_SEV_COLOUR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim white",
}

_LOGO = r"""
  __  __
  \ \/ /_ __ ___   __ _ _ __
   \  /| '_ ` _ \ / _` | '_ \
   /  \| | | | | | (_| | |_) |
  /_/\_\_| |_| |_|\__,_| .__/
                        |_|
"""


def print_banner(version: str = "1.0.0"):
    if RICH_AVAILABLE and console:
        console.print(f"[bold cyan]{_LOGO}[/bold cyan]")
        console.print(
            f"  [bold white]Ymap[/bold white] [dim]v{version}[/dim]  "
            "[dim]—  Yung Mapper  ·  Lightweight Network Scanner[/dim]"
        )
        console.print("  [dim]Author: Adekunle Abdulmujeeb[/dim]\n")
    else:
        print(_LOGO)
        print(f"  Ymap v{version} — Yung Mapper\n")


# ---------------------------------------------------------------------------
# API key prompt (masked input)
# ---------------------------------------------------------------------------

def prompt_api_key() -> str:
    import getpass
    if RICH_AVAILABLE and console:
        console.print(
            "\n[bold cyan]NVD API Key[/bold cyan]\n"
            "  [dim]Get a free key at:[/dim] "
            "[cyan]https://nvd.nist.gov/developers/request-an-api-key[/cyan]\n"
            "  [dim]Your key is used for this session only — never saved to disk.[/dim]\n"
        )
    else:
        print("\n  Get a free NVD key: https://nvd.nist.gov/developers/request-an-api-key")
    return getpass.getpass("  Paste your NVD API key: ").strip()


# ---------------------------------------------------------------------------
# Error / advisory messages
# ---------------------------------------------------------------------------

def print_rate_limit_advisory():
    if RICH_AVAILABLE and console:
        console.print(
            "\n[yellow]  ⚠   NVD API rate limit reached (HTTP 429).[/yellow]\n"
            "  [dim]Free tier: 5 requests / 30 seconds.[/dim]\n\n"
            "  To continue with faster CVE lookups, add a free API key:\n"
            "    [bold white]ymap --add-nvd-api-key [OPTIONS] TARGET[/bold white]\n\n"
            "  Get a free key at:\n"
            "    [cyan]https://nvd.nist.gov/developers/request-an-api-key[/cyan]\n\n"
            "  [dim]Run [bold]ymap --help[/bold] for more information.[/dim]\n"
        )
    else:
        print("\n  ⚠  NVD API rate limit reached. Free tier: 5 req/30s.")
        print("  Add key: ymap --add-nvd-api-key  |  ymap --help\n")


def print_invalid_key_error(detail: str = ""):
    msg = detail or (
        "NVD API key rejected. "
        "The key may be invalid, mistyped, or not yet activated. "
        "NVD keys can take up to 24 hours to activate after registration."
    )
    if RICH_AVAILABLE and console:
        console.print(f"\n[red]  ✗  {msg}[/red]")
        console.print(
            "  [dim]Also check:[/dim]\n"
            "  [dim]  • Internet connectivity  (ping api.nvd.nist.gov)[/dim]\n"
            "  [dim]  • Key activation status  (may take up to 24 hours)[/dim]\n"
            "  [dim]  • Get a new key at:[/dim] "
            "[cyan]https://nvd.nist.gov/developers/request-an-api-key[/cyan]\n"
        )
    else:
        print(f"\n  ✗  {msg}")
        print("  Check: internet connection, key activation (24h), or get new key.")
        print("  New key: https://nvd.nist.gov/developers/request-an-api-key\n")


def print_cve_error(msg: str):
    """Generic CVE lookup error — shown when we can't fetch data for a clear reason."""
    if RICH_AVAILABLE and console:
        console.print(f"\n[yellow]  ⚠   CVE lookup error: {msg}[/yellow]\n")
    else:
        print(f"\n  ⚠  CVE lookup error: {msg}\n")


# ---------------------------------------------------------------------------
# Discovery Table
# ---------------------------------------------------------------------------

def print_discovery(results: List[HostResult], elapsed: float):
    if not results:
        cprint("\n[yellow]  No live hosts found.[/yellow]\n")
        return
    count = len(results)
    if RICH_AVAILABLE and console:
        table = Table(
            title=f"Host Discovery  —  {count} host{'s' if count != 1 else ''} up",
            box=box.ROUNDED, border_style="cyan", header_style="bold cyan",
        )
        table.add_column("IP ADDRESS",      style="bold white", no_wrap=True, min_width=16)
        table.add_column("HOSTNAME / NAME", style="white",      min_width=28)
        table.add_column("MAC ADDRESS",     style="magenta",    no_wrap=True, min_width=18)
        table.add_column("VENDOR",          style="dim magenta", min_width=22)
        table.add_column("LATENCY",         style="green", justify="right", min_width=10)
        for h in results:
            table.add_row(
                h.ip,
                h.hostname   or "—",
                h.mac        or "—",
                h.mac_vendor or "—",
                f"{h.latency_ms:.1f} ms" if h.latency_ms is not None else "—",
            )
        console.print()
        console.print(table)
        console.print(f"  [dim]Discovery completed in {elapsed:.2f}s[/dim]\n")
    else:
        print(f"\n{'IP':<18} {'HOSTNAME':<30} {'MAC':<18} {'VENDOR':<24} {'LATENCY':>10}")
        print("─" * 105)
        for h in results:
            print(
                f"{h.ip:<18} {(h.hostname or '—'):<30} "
                f"{(h.mac or '—'):<18} {(h.mac_vendor or '—'):<24} "
                f"{(f'{h.latency_ms:.1f} ms' if h.latency_ms else '—'):>10}"
            )
        print(f"\n  Discovery in {elapsed:.2f}s\n")


# ---------------------------------------------------------------------------
# Port Scan Results
# ---------------------------------------------------------------------------

def print_scan_results(
    host: str,
    port_results: List[PortResult],
    os_guess: Optional[str] = None,
    elapsed: float = 0.0,
    show_closed: bool = False,
    show_version: bool = False,
):
    open_ports = [r for r in port_results if r.state in (PortState.OPEN, PortState.OPEN_FILTERED)]
    if not open_ports:
        cprint(f"\n[yellow]  No open ports found on {host}.[/yellow]")
        if os_guess:
            cprint(f"  [dim]OS: {os_guess}[/dim]")
        cprint()
        return
    if RICH_AVAILABLE and console:
        title = f"Scan Results  —  {host}"
        if os_guess:
            title += f"   |   OS: {os_guess}"
        table = Table(title=title, box=box.ROUNDED, border_style="cyan",
                      header_style="bold cyan")
        table.add_column("PORT",    style="bold white", no_wrap=True, width=8)
        table.add_column("PROTO",   style="dim",        width=6)
        table.add_column("STATE",   no_wrap=True,       width=12)
        table.add_column("SERVICE", style="cyan",       width=16)
        if show_version:
            table.add_column("VERSION", style="white", min_width=22)
        table.add_column("LATENCY", style="green", justify="right", width=10)
        display = port_results if show_closed else open_ports
        for r in display:
            colour = _STATE_COLOUR.get(r.state, "white")
            row = [
                str(r.port),
                r.protocol.upper(),
                f"[{colour}]{r.state.value}[/{colour}]",
                service_name(r.port, r.protocol),
            ]
            if show_version:
                row.append(r.banner or "—")
            row.append(f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "—")
            table.add_row(*row)
        console.print()
        console.print(table)
        console.print(
            f"  [dim]{len(open_ports)} open port(s)  ·  scan completed in {elapsed:.2f}s[/dim]\n"
        )
    else:
        print(f"\nResults — {host}" + (f"  |  OS: {os_guess}" if os_guess else ""))
        header = f"{'PORT':<8} {'PROTO':<6} {'STATE':<12} {'SERVICE':<16}"
        if show_version:
            header += "  VERSION"
        print(header + "\n" + "─" * 70)
        for r in (port_results if show_closed else open_ports):
            row = f"{r.port:<8} {r.protocol.upper():<6} {r.state.value:<12} {service_name(r.port, r.protocol):<16}"
            if show_version:
                row += f"  {r.banner or '—'}"
            print(row)
        print(f"\n  {len(open_ports)} open port(s)  ·  {elapsed:.2f}s\n")


# ---------------------------------------------------------------------------
# CVE Results  — heading includes service + version
# ---------------------------------------------------------------------------

_VC_NOTE = (
    "  Note: Version was auto-detected. If the version above is inaccurate, "
    "use --cve-check to manually specify a service version for a more targeted lookup."
)
_VC_NOTE_RICH = (
    "  [dim italic]Note: Version was auto-detected. "
    "If the version above is inaccurate, use [bold]--cve-check[/bold] "
    "to manually specify a service version for a more targeted lookup.[/dim italic]"
)


def print_cve_results(
    cve_map: Dict[str, List[CVEResult]],
    service_versions: Optional[Dict[str, str]] = None,
    precise: bool = False,
):
    """
    Print CVE findings per service.
    precise=True (-VC mode): always shows the auto-detection note after EACH
    service section, whether or not vulnerabilities were found.
    service_versions: {service_key: version_string} shown in section heading.
    """
    if not cve_map:
        cprint("[green]  ✔  No vulnerabilities found for detected services.[/green]")
        if precise:
            cprint(_VC_NOTE_RICH if RICH_AVAILABLE else _VC_NOTE)
        return

    for svc_key, cves in cve_map.items():
        ver_str = ""
        if service_versions:
            ver = service_versions.get(svc_key)
            if ver and ver not in ("—", "-", "unknown", "None"):
                ver_str = f"  |  Version: {ver}"

        if RICH_AVAILABLE and console:
            console.print()
            console.print(Rule(
                title=f"[bold red]CVEs — {svc_key}{ver_str}[/bold red]",
                style="red",
            ))
            if not cves:
                console.print(
                    "  [green]✔  No vulnerabilities found for this service.[/green]"
                )
            else:
                table = Table(
                    box=box.SIMPLE_HEAVY, border_style="red",
                    header_style="bold red", show_lines=True, padding=(0, 1),
                )
                table.add_column("CVE ID",      style="bold white", no_wrap=True, width=18)
                table.add_column("SCORE",        justify="right",   width=7)
                table.add_column("SEVERITY",     width=10)
                table.add_column("DESCRIPTION", style="dim white")
                for cve in cves:
                    sc  = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
                    sev = _SEV_COLOUR.get(cve.severity or "UNKNOWN", "white")
                    table.add_row(
                        f"[link={cve.url}]{cve.cve_id}[/link]",
                        sc,
                        f"[{sev}]{cve.severity or '—'}[/{sev}]",
                        cve.description,
                    )
                console.print(table)

            # Always show the note in -VC mode
            if precise:
                console.print(_VC_NOTE_RICH + "\n")
        else:
            print(f"\n{'='*60}")
            print(f"CVEs — {svc_key}{ver_str}")
            print("=" * 60)
            if not cves:
                print("  ✔  No vulnerabilities found for this service.")
            else:
                for cve in cves:
                    print(f"  {cve.cve_id:<20} [{cve.severity:<8}]  Score: {cve.cvss_score or 'N/A'}")
                    print(f"    {cve.description[:120]}")
            if precise:
                print(_VC_NOTE + "\n")


# ---------------------------------------------------------------------------
# Manual CVE results  (--cve-check)
# ---------------------------------------------------------------------------

def print_manual_cve_results(cve_map: Dict[str, List[CVEResult]]):
    """Print CVE results for user-supplied service versions (--cve-check)."""
    total = sum(len(v) for v in cve_map.values())
    if total == 0:
        cprint("[green]  ✔  No vulnerabilities found for the specified service versions.[/green]")
        return

    if RICH_AVAILABLE and console:
        console.print()
        console.print(Rule(title="[bold cyan]Manual CVE Lookup Results[/bold cyan]", style="cyan"))

    for svc_key, cves in cve_map.items():
        if not cves:
            cprint(f"  [dim]No CVEs found for: {svc_key}[/dim]")
            continue
        if RICH_AVAILABLE and console:
            console.print()
            console.print(Rule(
                title=f"[bold red]CVEs — {svc_key}[/bold red]", style="red",
            ))
            table = Table(
                box=box.SIMPLE_HEAVY, border_style="red",
                header_style="bold red", show_lines=True, padding=(0, 1),
            )
            table.add_column("CVE ID",      style="bold white", no_wrap=True, width=18)
            table.add_column("SCORE",        justify="right",   width=7)
            table.add_column("SEVERITY",     width=10)
            table.add_column("DESCRIPTION", style="dim white")
            for cve in cves:
                sc  = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
                sev = _SEV_COLOUR.get(cve.severity or "UNKNOWN", "white")
                table.add_row(
                    f"[link={cve.url}]{cve.cve_id}[/link]", sc,
                    f"[{sev}]{cve.severity or '—'}[/{sev}]",
                    cve.description,
                )
            console.print(table)
        else:
            print(f"\nCVEs — {svc_key}")
            for cve in cves:
                print(f"  {cve.cve_id} [{cve.severity}] {cve.cvss_score}: {cve.description[:100]}")


# ---------------------------------------------------------------------------
# Host-down notice
# ---------------------------------------------------------------------------

def print_host_down(host: str):
    if RICH_AVAILABLE and console:
        console.print(
            f"\n[yellow]  ⚠  Host [bold]{host}[/bold] does not appear to be up.[/yellow]\n"
            "  [dim]It may be blocking ICMP. Proceeding with port scan anyway.[/dim]\n"
            f"  [dim]For a more thorough check, try: sudo ymap -A {host}[/dim]\n"
        )
    else:
        print(f"\n  ⚠  Host {host} does not appear to be up (may block ICMP).")
        print("     Proceeding with port scan anyway.\n")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(
    target: str,
    n_hosts: int,
    n_open: int,
    n_cves: int,
    total_elapsed: float,
    cve_enabled: bool = False,
    ports_enabled: bool = True,
):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if RICH_AVAILABLE and console:
        text = Text()
        text.append("  Target  : ", style="dim");  text.append(f"{target}\n",         style="bold white")
        text.append("  Hosts   : ", style="dim");  text.append(f"{n_hosts} live\n",   style="bold green")
        text.append("  Ports   : ", style="dim")
        if ports_enabled:
            text.append(f"{n_open} open\n", style="bold green")
        else:
            text.append("—\n", style="dim")
        text.append("  CVEs    : ", style="dim")
        if cve_enabled:
            text.append(f"{n_cves}\n", style="bold red" if n_cves else "green")
        else:
            text.append("—\n", style="dim")
        text.append("  Elapsed : ", style="dim");  text.append(f"{total_elapsed:.2f}s\n", style="bold white")
        text.append("  Time    : ", style="dim");  text.append(ts,                    style="dim white")
        console.print(Panel(text, title="[bold cyan]Scan Complete[/bold cyan]", border_style="cyan"))
    else:
        print(f"\n{'='*42}")
        print(f"  Target  : {target}")
        print(f"  Hosts   : {n_hosts} live")
        print(f"  Ports   : {n_open} open" if ports_enabled else "  Ports   : —")
        print(f"  CVEs    : {'—' if not cve_enabled else n_cves}")
        print(f"  Elapsed : {total_elapsed:.2f}s  [{ts}]")
        print("=" * 42 + "\n")


# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------

def export_json(target, hosts, port_results, cve_map, os_guess, output_path):
    from ymap.portscan import service_name
    report = {
        "meta": {"tool": "ymap", "version": "1.0.0",
                 "target": target, "timestamp": datetime.utcnow().isoformat() + "Z"},
        "hosts": [{"ip": h.ip, "hostname": h.hostname, "mac": h.mac,
                   "mac_vendor": h.mac_vendor,
                   "latency_ms": h.latency_ms, "method": h.method} for h in hosts],
        "os_guess": os_guess,
        "ports": [{"port": r.port, "protocol": r.protocol, "state": r.state.value,
                   "service": service_name(r.port, r.protocol),
                   "version": r.banner, "latency_ms": r.latency_ms}
                  for r in port_results if r.state == PortState.OPEN],
        "cves": {svc: [{"id": c.cve_id, "score": c.cvss_score, "severity": c.severity,
                         "description": c.description, "url": c.url} for c in cves]
                 for svc, cves in cve_map.items()},
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    cprint(f"\n[green]  ✔  Report saved → {output_path}[/green]")


# ---------------------------------------------------------------------------
# Info display  (ymap --info / ymap-info)
# ---------------------------------------------------------------------------

def print_info_result(result) -> None:
    """
    Render an InfoResult to the terminal.
    Shows everything that was found, skips fields that are None/empty.
    """
    from ymap.info import InfoResult  # avoid circular at module level

    def _row(label: str, value, style: str = "white"):
        """Add a row to the info table if value is non-empty."""
        if value is None or value == "" or value == []:
            return False
        table.add_row(f"[dim]{label}[/dim]", f"[{style}]{value}[/{style}]")
        return True

    if RICH_AVAILABLE and console:
        title = f"Target Info  —  {result.target}"
        table = Table(
            title=title,
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            show_header=False,
            padding=(0, 1),
        )
        table.add_column("Field",  style="dim",        min_width=22, no_wrap=True)
        table.add_column("Value",  style="bold white",  min_width=40)

        # Target
        table.add_row("[dim]Target[/dim]",      f"[bold cyan]{result.target}[/bold cyan]")
        table.add_row("[dim]Type[/dim]",         f"[dim]{result.target_type.upper()}[/dim]")
        console.print()

        # Identity
        if result.hostname:
            _row("Hostname",      result.hostname, "bold white")
        if result.ptr_hostname and result.ptr_hostname != result.hostname:
            _row("PTR Record",    result.ptr_hostname)
        if result.ip_addresses:
            _row("IPv4 Address",  ", ".join(result.ip_addresses), "bold green")
        if result.ipv6_addresses:
            _row("IPv6 Address",  ", ".join(result.ipv6_addresses[:3]))
        if result.device_names:
            for dn in result.device_names:
                _row("Device Name", dn, "yellow")

        # MAC / Hardware
        if result.mac:
            _row("MAC Address",   result.mac, "magenta")
        if result.mac_vendor:
            _row("Vendor",        result.mac_vendor, "magenta")
        if result.mac_type:
            _row("MAC Type",      result.mac_type, "dim magenta")

        # Network / WHOIS
        if result.asn or result.asn_name:
            asn_str = " ".join(filter(None, [result.asn, result.asn_name]))
            _row("ASN",           asn_str)
        if result.organisation:
            _row("Organisation",  result.organisation)
        if result.isp and result.isp != result.organisation:
            _row("ISP",           result.isp)
        if result.ip_range:
            _row("Network Range", result.ip_range)
        if result.country:
            parts = [p for p in [result.city, result.region, result.country] if p]
            _row("Location",      ", ".join(parts))

        # DNS records
        if result.mx_records:
            _row("MX Records",    ", ".join(result.mx_records[:3]))
        if result.ns_records:
            _row("NS Records",    ", ".join(result.ns_records[:4]))

        # TLS / HTTP
        if result.tls_version:
            _row("TLS Version",   result.tls_version, "cyan")
        if result.tls_cert_cn:
            _row("Cert CN",       result.tls_cert_cn, "cyan")
        if result.tls_cert_org:
            _row("Cert Org",      result.tls_cert_org)
        if result.tls_cert_issuer:
            _row("Cert Issuer",   result.tls_cert_issuer, "dim")
        if result.http_server:
            _row("HTTP Server",   result.http_server)

        # Timing + errors
        console.print(table)
        console.print(f"  [dim]Gathered in {result.scan_time:.2f}s[/dim]\n")

        if result.errors:
            for err in result.errors:
                console.print(f"  [yellow]⚠  {err}[/yellow]")
            console.print()

    else:
        # Plain-text fallback
        print(f"\n  Target      : {result.target}  ({result.target_type.upper()})")
        if result.hostname:
            print(f"  Hostname    : {result.hostname}")
        if result.ip_addresses:
            print(f"  IPv4        : {', '.join(result.ip_addresses)}")
        if result.ipv6_addresses:
            print(f"  IPv6        : {', '.join(result.ipv6_addresses[:3])}")
        if result.mac:
            print(f"  MAC         : {result.mac}")
        if result.mac_vendor:
            print(f"  Vendor      : {result.mac_vendor}")
        if result.mac_type:
            print(f"  MAC Type    : {result.mac_type}")
        if result.asn:
            print(f"  ASN         : {result.asn}  {result.asn_name or ''}")
        if result.isp:
            print(f"  ISP         : {result.isp}")
        if result.country:
            parts = [p for p in [result.city, result.region, result.country] if p]
            print(f"  Location    : {', '.join(parts)}")
        if result.tls_version:
            print(f"  TLS         : {result.tls_version}  CN={result.tls_cert_cn or '—'}")
        if result.http_server:
            print(f"  HTTP Server : {result.http_server}")
        print(f"\n  Gathered in {result.scan_time:.2f}s\n")
        for err in result.errors:
            print(f"  ⚠  {err}")
