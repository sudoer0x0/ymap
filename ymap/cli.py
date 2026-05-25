"""
cli.py — Command-Line Interface for Ymap v1.0.0

Follows POSIX Utility Syntax Guidelines and GNU Coding Standards:
  Short options: -a, -b, -c ... (single dash, single char)
  Long options:  --aggressive, --basic, --cve ... (double dash, words)
  Every flag has both a short and a long form.
"""

import sys
import os
import atexit
import click
from ymap import __version__, __author__


# ---------------------------------------------------------------------------
# Ctrl+C / threading traceback suppression
# ---------------------------------------------------------------------------

def _suppress_thread_errors():
    """
    Three-layer suppression of Python internals noise on multiple Ctrl+C.
    1. sys.unraisablehook  — suppresses 'Exception ignored in: ...' messages
    2. concurrent.futures atexit wrapper — catches KeyboardInterrupt on join
    3. sys.excepthook      — silences remaining Ctrl+C tracebacks
    """
    if hasattr(sys, "unraisablehook"):
        _orig = sys.unraisablehook
        def _quiet(args):
            if args.exc_type is KeyboardInterrupt:
                return
            obj_mod = getattr(args.object, "__module__", "") or ""
            if any(s in obj_mod for s in ("threading", "concurrent.futures")):
                return
            _orig(args)
        sys.unraisablehook = _quiet

    try:
        import concurrent.futures.thread as _cft
        _orig_exit = getattr(_cft, "_python_exit", None)
        if _orig_exit:
            def _safe_exit():
                try: _orig_exit()
                except Exception: pass
            try: atexit.unregister(_orig_exit)
            except Exception: pass
            atexit.register(_safe_exit)
    except Exception:
        pass

    _orig_hook = sys.excepthook
    def _quiet_hook(t, v, tb):
        if t is KeyboardInterrupt: return
        _orig_hook(t, v, tb)
    sys.excepthook = _quiet_hook


_suppress_thread_errors()


# ---------------------------------------------------------------------------
# About / bare-command display
# ---------------------------------------------------------------------------

_LOGO_LINES = [
    "██  ██  ██   ██    ██     █████ ",
    "██  ██  ███ ███   ████    ██  ██",
    " ████   ██ █ ██  ██  ██   █████ ",
    "  ██    ██   ██  ██████   ██    ",
    "  ██    ██   ██  ██  ██   ██    ",
]

def _print_help():
    """
    Render the full help/about screen — shown when user types bare 'ymap'.
    Design inspired by pixel-font terminal tools: cyan logo, two-column layout.
    """
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich import box as rbox
        c = Console()

        # ── Pixel logo ──────────────────────────────────────────────────────
        _logo_pad = " " * 26   # centre the 32-char logo in 92-char terminal
        c.print()
        for line in _LOGO_LINES:
            c.print(f"[bold cyan]{_logo_pad}{line}[/bold cyan]")
        c.print()
        subtitle = f"Yung Mapper  •  v{__version__}  •  Lightweight. Fast. Reliable."
        pad = " " * ((92 - len(subtitle)) // 2)
        c.print(f"[cyan]{pad}{subtitle}[/cyan]")
        c.print()

        # ── Header bar ──────────────────────────────────────────────────────
        c.print(Panel(
            f"[bold cyan]Ymap — Yung Mapper[/bold cyan]  [dim]|[/dim]  "
            f"[cyan]Lightweight Network Scanner[/cyan]  [dim]|[/dim]  "
            f"[bold cyan]v{__version__}[/bold cyan]",
            box=rbox.SIMPLE_HEAVY,
            border_style="cyan",
            expand=True,
        ))

        def _section(title):
            c.print(f"\n[bold cyan]{title}[/bold cyan]")

        def _row(cmd, desc="", indent="  "):
            if desc:
                c.print(f"{indent}[cyan]{cmd:<38}[/cyan] [dim]{desc}[/dim]")
            else:
                c.print(f"{indent}[dim]{cmd}[/dim]")


        
        # ── Basic Usage ──────────────────────────────────────────────────────
        _section("Basic Usage")
        _row("ymap <target>",                    "Scan top 1000 ports  (default)")
        _row("ymap -a 10.0.0.5",                 "Aggressive: SYN + version + OS + CVE")
        _row("sudo ymap -d 192.168.1.0/24",      "Discover live hosts on subnet")
        _row("ymap --info 192.168.1.1",           "Gather host info: DNS, ASN, MAC, TLS")
        _row("ymap --cve-check \"Apache 2.4.41\"", "Manual CVE lookup, no target needed")

        # ── Scan Mode Flags ──────────────────────────────────────────────────
        _section("Scan Mode Flags")
        _row("-a, --aggressive",    "Full scan: SYN + version + OS + CVE  [root]")
        _row("-b, --basic",         "Basic TCP connect, top 1000 ports    [default]")
        _row("-c, --cve",           "Broad CVE check for all open services")
        _row("-w, --version-cve",   "CVE check scoped to detected version")
        _row("-d, --discovery",     "ARP ping sweep — find live hosts     [root]")
        _row("-o, --os",            "OS fingerprinting: TTL + SMB + TCP   [root]")
        _row("-v, --version-det",   "Service version / banner detection")

        # ── Tuning Flags ─────────────────────────────────────────────────────
        _section("Tuning Flags")
        _row("-p, --ports <spec>",  "80,443 | 1-1000 | - (all) | top1000")
        _row("-t, --timing <0-5>",  "0=paranoid  3=normal  4=fast  5=insane")
        _row("-s, --scantype <T|S|U>", "T=Connect  S=SYN(root)  U=UDP(root)")

        # ── CVE Lookup ────────────────────────────────────────────────────────
        _section("CVE Lookup")
        _row("-c, --cve",           "Broad CVE check for each open service")
        _row("-w, --version-cve",   "Precise CVE matched to detected version")
        _row("--cve-check \"SVC VER\"", "Manual lookup — no scan target needed")
        c.print()
        c.print("  [dim]No API key required. Free tier: 5 requests / 30s.[/dim]")
        c.print("  [dim]For faster lookups:  ymap --add-nvd-api-key [OPTIONS] TARGET[/dim]")
        c.print("  [dim]Get a free key:       https://nvd.nist.gov/developers/request-an-api-key[/dim]")

        # ── Target Info ───────────────────────────────────────────────────────
        _section("Target Information  (--info)")
        _row("ymap --info 192.168.1.1",    "IP info: PTR, ASN, ISP, city, MAC, TLS")
        _row("ymap --info google.com",     "Hostname: DNS records, MX, NS, IP info")
        _row("sudo ymap --info 10.0.0.5",  "Includes MAC via ARP  (root)")
        _row("ymap --info 00:50:56:aa:bb:cc", "MAC vendor lookup  (offline)")

        # ── Output ────────────────────────────────────────────────────────────
        _section("Output")
        _row("--json <file>",        "Save full scan results to JSON file")
        _row("--closed",             "Show closed/filtered ports in table")

        # ── Target Formats ────────────────────────────────────────────────────
        _section("Target Formats")
        _row("192.168.1.1",          "Single IPv4 address")
        _row("10.0.0.0/24",          "CIDR subnet range")
        _row("192.168.1.1-50",       "Last-octet range (50 hosts)")
        _row("example.com",          "Hostname — resolved before scanning")

        # ── About──────────────────────────────────────────────────────
        _section("About")
        _row("App: ",                 "Yung Mapper (Ymap)")
        _row("Developer: ",                 "Adekunle Abdulmujeeb")
        _row("License: ",                    "MIT")
        _row("Language: ",                    "Python 3.8+")
        _row("Version: ",                    "1.0.0")
        _row("Repository: ",      "https://github.com/sudoer0x0/ymap")
        _row("Clone: ",           "git clone https://github.com/sudoer0x0/ymap.git")
        _row("Get a free key: ",  "https://nvd.nist.gov/developers/request-an-api-key")

        # ── Footer ────────────────────────────────────────────────────────────
        c.print()
        c.print(f"  [dim]Developer: [cyan]{__author__}[/cyan]  •  MIT License  •  https://github.com/sudoer0x0/ymap.git[/dim]")
        c.print()

    except ImportError:
        # Plain-text fallback
        print(f"  Ymap v{__version__} — Yung Mapper")
        print(f"  Developer: {__author__}")
        print("  ymap <target>          Basic scan")
        print("  ymap -a <target>       Aggressive scan (sudo)")
        print("  ymap --help            Full flag reference")


def _print_about():
    """Alias kept for compatibility — calls the help screen."""
    _print_help()


# ---------------------------------------------------------------------------
# Case-insensitive scan type choice
# ---------------------------------------------------------------------------

class _ScanTypeChoice(click.Choice):
    def convert(self, value, param, ctx):
        if value is None: return value
        return super().convert(value.upper(), param, ctx)


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

CONTEXT = dict(help_option_names=["--help"], max_content_width=92)


@click.command(context_settings=CONTEXT)
@click.argument("target", required=False)
# ── Scan modes ────────────────────────────────────────────────────────────────
@click.option("-a", "--aggressive",   is_flag=True,
              help="Full scan: SYN + version + OS + CVE  [requires root]")
@click.option("-b", "--basic",        is_flag=True, default=False,
              help="Basic TCP Connect scan, top 1000 ports  [default if no mode given]")
@click.option("-c", "--cve",          is_flag=True,
              help="Broad CVE lookup for all open services  (auto-enables -v)")
@click.option("-w", "--version-cve",  is_flag=True,
              help="Precise CVE lookup scoped to detected service version  (auto-enables -v)")
@click.option("--cve-check",          default=None, metavar="\"SVC VER[,...]\"",
              help=("Manual CVE lookup. No scan target needed.\n"
                    "  ymap --cve-check \"Apache 2.4.41\"\n"
                    "  ymap --cve-check \"OpenSSH 7.4, nginx 1.18\""))
@click.option("-d", "--discovery",    is_flag=True,
              help="Host discovery (ARP ping sweep)  [requires root]")
@click.option("-o", "--os",           is_flag=True,
              help="OS fingerprinting: TTL + TCP window + SMB  [requires root]")
@click.option("-v", "--version-det",  is_flag=True,
              help="Service version / banner detection")
# ── Tuning ────────────────────────────────────────────────────────────────────
@click.option("-p", "--ports",        default="top1000", show_default=True,
              help="80,443 | 1-1000 | - (all) | top1000")
@click.option("-t", "--timing",       default=4, type=click.IntRange(0, 5),
              show_default=True,
              help="Timing: 0=paranoid … 5=insane  [default: 4]")
@click.option("-s", "--scantype",     default="T",
              type=_ScanTypeChoice(["T", "S", "U"]), show_default=True,
              help="Scan type: T=Connect  S=SYN (root)  U=UDP (root)")
# ── Info & output ─────────────────────────────────────────────────────────────
@click.option("--info",     "info_target", default=None, metavar="TARGET",
              help=("Gather detailed info about a target. No port scan.\n"
                    "Accepts IP, hostname, or MAC address.\n"
                    "  ymap --info 192.168.1.1\n"
                    "  ymap --info google.com\n"
                    "  sudo ymap --info 192.168.1.1  (includes MAC via ARP)\n"
                    "  ymap --info 00:50:56:aa:bb:cc"))
@click.option("--json",     "output_json", default=None, metavar="FILE",
              help="Save structured JSON report to FILE")
@click.option("--closed",   is_flag=True,
              help="Show closed/filtered ports in results table")
# ── NVD API key (session-only) ────────────────────────────────────────────────
@click.option("--add-nvd-api-key", "add_nvd_key", is_flag=True, default=False,
              help=("Prompt for NVD API key (session-only, never saved to disk).\n"
                    "Gives 50 req/30s instead of 5 req/30s.\n"
                    "Get a free key: https://nvd.nist.gov/developers/request-an-api-key"))
# ── Meta ──────────────────────────────────────────────────────────────────────
@click.version_option(__version__, "--version", prog_name="ymap")
def main(target,
         aggressive, basic, cve, version_cve, cve_check,
         discovery, os, version_det,
         ports, timing, scantype,
         info_target, output_json, closed,
         add_nvd_key):
    """
    \b
    Ymap — Yung Mapper  ·  Lightweight Network Scanner

    \b
    TARGET:
      192.168.1.1      single IP
      10.0.0.0/24      CIDR range
      192.168.1.1-50   IP range (last-octet)
      example.com      hostname

    \b
    Common examples:
      ymap 192.168.1.1                  Basic scan, top 1000 ports
      sudo ymap -a 10.0.0.5             Aggressive: SYN + version + OS + CVE
      sudo ymap -d 192.168.1.0/24       Discover live hosts on subnet
      ymap -c 192.168.1.1               CVE check (versions auto-detected)
      ymap -w 192.168.1.1               Precise CVE (version-matched)
      ymap --cve-check "Apache 2.4.41"  Manual CVE, no target needed
      ymap --info 192.168.1.1           Host info (DNS, ASN, MAC, TLS...)
      sudo ymap --info 192.168.1.100    Host info + MAC via ARP
      ymap -v -p 22,80,443 example.com  Version detect on chosen ports
      sudo ymap -s S -o -t 2 host       SYN scan + OS detect
      ymap -p - 10.0.0.1                All 65535 ports
      sudo ymap -a host --json out.json Full scan + JSON report

    \b
    CVE lookup (no API key needed by default):
      -c   Broad CVE check for all open services
      -w   Precise CVE check using detected versions
      --cve-check "..."  Manual lookup, no target needed
      --add-nvd-api-key  Add session key for faster lookups (50 req/30s)
    """
    # ── Bare command: show about/banner ───────────────────────────────────
    if target is None and not any([
        aggressive, basic, cve, version_cve, cve_check, discovery, os,
        version_det, info_target, output_json, closed, add_nvd_key,
        ports != "top1000", timing != 4, scantype != "T",
    ]):
        _print_help()
        return

    # ── --info (no scan) ──────────────────────────────────────────────────
    if info_target:
        _handle_info(info_target)
        return

    # ── --cve-check standalone (no target needed) ─────────────────────────
    cve_check_only = (cve_check is not None and target is None and not any([
        aggressive, basic, cve, version_cve, discovery, os, version_det,
    ]))

    if cve_check_only:
        _handle_cve_check_only(cve_check, add_nvd_key)
        return

    # ── Target is required for everything else ────────────────────────────
    if target is None:
        click.echo(
            "\n  No target specified.\n"
            "  Usage: ymap [OPTIONS] TARGET\n"
            "  Run 'ymap' with no arguments to see quick-start guide.\n"
            "  Run 'ymap --help' for the full flag reference.\n",
            err=True,
        )
        sys.exit(1)

    # ── --add-nvd-api-key ─────────────────────────────────────────────────
    if add_nvd_key:
        _prompt_and_set_api_key()

    # ── Root warnings ─────────────────────────────────────────────────────
    if not aggressive:
        if scantype.upper() in ("S", "U"):
            _warn_root(f"-s {scantype.upper()} scan")
        if os:
            _warn_root("-o (OS fingerprinting)")
        if discovery:
            _warn_root("-d (host discovery)")

    # ── Build config and run scan ─────────────────────────────────────────
    try:
        from ymap.core import ScanConfig, run_scan
        cfg = ScanConfig(
            target=target,
            aggressive=aggressive,
            basic=basic,
            cve=cve,
            version_cve=version_cve,
            manual_cve=_parse_cve_check(cve_check),
            discovery_only=discovery and not (aggressive or basic or version_det or os),
            os_detect=os,
            version_detect=version_det,
            ports=ports,
            timing=timing,
            scan_type=scantype,
            output_json=output_json,
            show_closed=closed,
        )
        run_scan(cfg)
    except ValueError as e:
        click.echo(f"\n  Invalid input: {e}\n", err=True)
        sys.exit(1)
    except PermissionError:
        click.echo("\n  Permission denied — try running with sudo.\n", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\n\n  Scan interrupted.\n", err=True)
        sys.exit(130)
    finally:
        try:
            from ymap.scripting import clear_session_api_key
            clear_session_api_key()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _warn_root(feature: str):
    from ymap.utils import is_root
    if not is_root():
        click.echo(
            f"\n  ⚠  {feature} requires root privileges.\n"
            f"     Run:  sudo ymap ...\n", err=True,
        )


def _parse_cve_check(raw: str | None) -> list:
    if not raw:
        return []
    try:
        from ymap.scripting import parse_manual_cve_input
        return parse_manual_cve_input(raw)
    except ValueError as e:
        click.echo(f"\n  --cve-check error: {e}\n", err=True)
        sys.exit(1)


def _prompt_and_set_api_key():
    try:
        from ymap.scripting import set_session_api_key
        from ymap.output import prompt_api_key
        key = prompt_api_key()
        set_session_api_key(key)
        try:
            from rich.console import Console
            Console().print("  [green]✔  API key set for this session.[/green]\n")
        except ImportError:
            print("  API key set for this session.\n")
    except ValueError as e:
        click.echo(f"\n  {e}\n", err=True)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        click.echo("\n  Cancelled.\n", err=True)
        sys.exit(1)


def _handle_cve_check_only(raw: str, add_nvd_key: bool):
    if add_nvd_key:
        _prompt_and_set_api_key()
    validated = _parse_cve_check(raw)
    from ymap.scripting import (
        cve_lookup_manual, RateLimitError, InvalidKeyError, NetworkError,
    )
    from ymap import output as _out
    _out.cprint(
        f"\n[bold cyan][ CVE Lookup ][/bold cyan]  "
        f"{len(validated)} service version(s) …"
    )
    cve_map = {}
    for sv in validated:
        try:
            cve_map[sv] = cve_lookup_manual(sv)
        except RateLimitError:
            _out.print_rate_limit_advisory()
            break
        except InvalidKeyError as e:
            _out.print_invalid_key_error(str(e))
            break
        except NetworkError as e:
            _out.print_cve_error(str(e))
            break
    if cve_map:
        _out.print_manual_cve_results(cve_map)
    try:
        from ymap.scripting import clear_session_api_key
        clear_session_api_key()
    except Exception:
        pass


def _handle_info(target: str):
    from ymap.utils import is_root
    from ymap.info import gather_info, classify_target
    from ymap import output as _out

    try:
        classify_target(target)
    except ValueError as e:
        click.echo(f"\n  Invalid target: {e}\n", err=True)
        return

    use_root = is_root()

    try:
        from rich.console import Console
        Console().print(
            f"\n  [dim]Gathering information for "
            f"[bold white]{target}[/bold white] …[/dim]\n"
        )
    except ImportError:
        print(f"\n  Gathering info for {target} …\n")

    result = gather_info(target, use_root=use_root, timeout=5.0)
    _out.print_info_result(result)


if __name__ == "__main__":
    main()
