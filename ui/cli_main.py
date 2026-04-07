"""
JiaguSentinel Pro v2.0 — CLI Interface
========================================
Professional Rich-based terminal interface with Click command groups
for static scanning, dynamic dumping, malware analysis, and reporting.

Features:
- Click-based command groups: scan, dump, analyze, report
- Rich panels, tables, progress bars, and live logging
- Interactive mode with prompts for missing arguments
- JSON output mode for CI/CD integration
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click

logger = logging.getLogger("sentinel.cli")


def _get_console():
    """Lazy-import Rich console."""
    from rich.console import Console
    return Console()


def _rich_log(message: str) -> None:
    """Output a log message using Rich markup."""
    console = _get_console()
    if "[ERROR]" in message:
        console.print(f"[bold red]{message}[/]")
    elif "[WARNING]" in message:
        console.print(f"[bold yellow]{message}[/]")
    elif "[SUCCESS]" in message or "✓" in message:
        console.print(f"[bold green]{message}[/]")
    elif "═══" in message:
        console.print(f"[bold cyan]{message}[/]")
    else:
        console.print(f"[dim]{message}[/]")


def _print_banner() -> None:
    """Print the JiaguSentinel ASCII banner."""
    console = _get_console()
    from rich.panel import Panel

    banner = """
   ╦╦╔═╗╔═╗╦ ╦  ╔═╗╔═╗╔╗╔╔╦╗╦╔╗╔╔═╗╦
   ║║╠═╣║ ╦║ ║  ╚═╗║╣ ║║║ ║ ║║║║║╣ ║
  ╚╝╩╩ ╩╚═╝╚═╝  ╚═╝╚═╝╝╚╝ ╩ ╩╝╚╝╚═╝╩═╝
         Advanced APK Unpacker & Forensics
                     v2.0 PRO
    """
    console.print(Panel(
        banner,
        border_style="cyan",
        title="[bold white]JiaguSentinel[/]",
        subtitle="[dim]360 Jiagu Packer Analysis Framework[/]",
    ))


# ═══════════════════════════════════════════════════════════════════
# CLI Command Group
# ═══════════════════════════════════════════════════════════════════

@click.group(invoke_without_command=True)
@click.option("--json-output", is_flag=True, help="Output results in JSON format (for CI/CD).")
@click.pass_context
def cli(ctx: click.Context, json_output: bool) -> None:
    """JiaguSentinel Pro v2.0 — Advanced APK Unpacker & Malware Forensics."""
    ctx.ensure_object(dict)
    ctx.obj["json_output"] = json_output

    if ctx.invoked_subcommand is None:
        _print_banner()
        console = _get_console()
        console.print("\n[bold]Available commands:[/]")
        console.print("  [cyan]scan[/]     — Static APK analysis (entropy, byte-pattern, YARA)")
        console.print("  [cyan]dump[/]     — Dynamic DEX dump via Frida")
        console.print("  [cyan]analyze[/]  — Malware scoring on extracted DEX")
        console.print("  [cyan]report[/]   — Generate forensic report")
        console.print("  [cyan]device[/]   — Show connected device info")
        console.print("  [cyan]payloads[/] — List available Frida payloads")
        console.print("\n[dim]Run 'python main.py --cli <command> --help' for details.[/]\n")


# ─── SCAN Command ─────────────────────────────────────────────────

@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("-o", "--output", default="unpacked_output", help="Output directory for extracted files.")
@click.option("--xor/--no-xor", default=True, help="Enable XOR brute-force scanning.")
@click.option("--entropy-threshold", default=6.5, type=float, help="Minimum entropy for deep scan.")
@click.pass_context
def scan(ctx: click.Context, apk_path: str, output: str, xor: bool, entropy_threshold: float) -> None:
    """Run static analysis on an APK file."""
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from core.static_engine import StaticEngine

    json_mode = ctx.obj.get("json_output", False)

    if not json_mode:
        _print_banner()

    log_fn = (lambda m: None) if json_mode else _rich_log

    engine = StaticEngine(
        output_dir=output,
        log_callback=log_fn,
        xor_bruteforce=xor,
    )

    if not json_mode:
        console = _get_console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Scanning..."),
            console=console,
        ) as progress:
            progress.add_task("scan", total=None)
            result = engine.scan(apk_path)
    else:
        result = engine.scan(apk_path)

    # Output
    if json_mode:
        output_data = {
            "apk": apk_path,
            "sha256": result.apk_sha256,
            "jiagu_detected": result.jiagu_detected,
            "jiagu_libraries": result.jiagu_libraries,
            "extracted_dex": result.extracted_dex,
            "total_files": result.total_files,
            "errors": result.errors,
        }
        click.echo(json.dumps(output_data, indent=2))
    else:
        _print_scan_results(result)


def _print_scan_results(result) -> None:
    """Render static scan results as a Rich table."""
    from rich.table import Table
    from rich.panel import Panel

    console = _get_console()

    # Summary panel
    summary = (
        f"[bold]APK SHA256:[/] {result.apk_sha256[:32]}...\n"
        f"[bold]Total Files:[/] {result.total_files}\n"
        f"[bold]Jiagu Detected:[/] {'[red]Yes[/]' if result.jiagu_detected else '[green]No[/]'}\n"
        f"[bold]Jiagu Libraries:[/] {', '.join(result.jiagu_libraries) or 'None'}\n"
        f"[bold]DEX Extracted:[/] {len(result.extracted_dex)}"
    )
    console.print(Panel(summary, title="[bold]Scan Results[/]", border_style="cyan"))

    # Extracted DEX table
    if result.extracted_dex:
        table = Table(title="Extracted DEX Files", border_style="green")
        table.add_column("#", style="dim", width=4)
        table.add_column("Path", style="green")
        for i, path in enumerate(result.extracted_dex, 1):
            table.add_row(str(i), path)
        console.print(table)

    # High entropy files
    high_ent = {k: v for k, v in result.entropy_map.items() if v > 7.0}
    if high_ent:
        table = Table(title="High Entropy Files (>7.0)", border_style="yellow")
        table.add_column("File", style="yellow")
        table.add_column("Entropy", justify="right")
        table.add_column("Heatmap", width=10)
        for fname, ent in sorted(high_ent.items(), key=lambda x: x[1], reverse=True)[:15]:
            bar = "█" * int(ent) + "░" * (8 - int(ent))
            table.add_row(fname, f"{ent:.2f}", bar)
        console.print(table)


# ─── DUMP Command ─────────────────────────────────────────────────

@cli.command()
@click.argument("package_name")
@click.option("-o", "--output", default="unpacked_output", help="Output directory.")
@click.option("--payload", default=None, help="Custom Frida JS payload file.")
@click.option("--no-anti-detect", is_flag=True, help="Disable anti-detection hooks.")
@click.option("--attach", is_flag=True, help="Attach to running process instead of spawning.")
@click.option("--timeout", default=60, type=int, help="Dump timeout in seconds.")
@click.pass_context
def dump(
    ctx: click.Context,
    package_name: str,
    output: str,
    payload: Optional[str],
    no_anti_detect: bool,
    attach: bool,
    timeout: int,
) -> None:
    """Dynamic DEX dump via Frida injection."""
    from core.dynamic_engine import DynamicEngine

    json_mode = ctx.obj.get("json_output", False)

    if not json_mode:
        _print_banner()

    log_fn = (lambda m: None) if json_mode else _rich_log

    engine = DynamicEngine(
        output_dir=output,
        log_callback=log_fn,
        anti_detection=not no_anti_detect,
    )

    custom_payload = None
    if payload:
        custom_payload = Path(payload).read_text(encoding="utf-8")

    result = engine.dump(
        package_name=package_name,
        custom_payload=custom_payload,
        spawn=not attach,
        timeout=timeout,
    )

    if json_mode:
        output_data = {
            "package": package_name,
            "dumped_dex": [
                {"address": d.address, "size": d.size, "path": d.path, "sha256": d.sha256}
                for d in result.dumped_dex
            ],
            "duration": result.session_duration,
            "errors": result.errors,
        }
        click.echo(json.dumps(output_data, indent=2))
    else:
        _print_dump_results(result)


def _print_dump_results(result) -> None:
    """Render dynamic dump results as Rich output."""
    from rich.table import Table
    from rich.panel import Panel

    console = _get_console()

    summary = (
        f"[bold]Package:[/] {result.package_name}\n"
        f"[bold]Device:[/] {result.device_id}\n"
        f"[bold]Frida:[/] {result.frida_version}\n"
        f"[bold]Anti-Detection:[/] {'[green]Active[/]' if result.anti_detection_active else '[dim]Off[/]'}\n"
        f"[bold]Duration:[/] {result.session_duration:.1f}s\n"
        f"[bold]DEX Dumped:[/] {len(result.dumped_dex)}"
    )
    console.print(Panel(summary, title="[bold]Dump Results[/]", border_style="yellow"))

    if result.dumped_dex:
        table = Table(title="Dumped DEX Files", border_style="green")
        table.add_column("#", style="dim", width=4)
        table.add_column("Address", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("SHA256", style="dim")
        for i, d in enumerate(result.dumped_dex, 1):
            table.add_row(str(i), d.address, f"{d.size:,}", d.sha256[:16] + "...")
        console.print(table)


# ─── ANALYZE Command ──────────────────────────────────────────────

@cli.command()
@click.argument("dex_paths", nargs=-1, type=click.Path(exists=True), required=True)
@click.pass_context
def analyze(ctx: click.Context, dex_paths: tuple[str, ...]) -> None:
    """Analyze extracted DEX files for malware indicators."""
    from analytics.malware_scorer import MalwareScorer

    json_mode = ctx.obj.get("json_output", False)

    if not json_mode:
        _print_banner()

    log_fn = (lambda m: None) if json_mode else _rich_log

    scorer = MalwareScorer(log_callback=log_fn)
    reports = scorer.analyze_batch(list(dex_paths))

    if json_mode:
        output_data = []
        for r in reports:
            output_data.append({
                "dex": r.dex_path,
                "sha256": r.dex_sha256,
                "score": r.threat_score,
                "level": r.threat_level.value,
                "categories": r.category_scores,
                "indicators": len(r.indicators),
                "network": r.network_indicators,
            })
        click.echo(json.dumps(output_data, indent=2))
    else:
        for r in reports:
            _print_analysis_results(r)


def _print_analysis_results(report) -> None:
    """Render malware analysis as Rich output."""
    from rich.table import Table
    from rich.panel import Panel

    console = _get_console()

    level_colors = {
        "CLEAN": "green", "LOW": "yellow", "MEDIUM": "dark_orange",
        "HIGH": "red", "CRITICAL": "bold red on white",
    }
    color = level_colors.get(report.threat_level.value, "white")

    summary = (
        f"[bold]DEX:[/] {Path(report.dex_path).name}\n"
        f"[bold]SHA256:[/] {report.dex_sha256}\n"
        f"[bold]Size:[/] {report.dex_size:,} bytes\n"
        f"[bold]Score:[/] [{color}]{report.threat_score}/100 [{report.threat_level.value}][/]\n"
    )
    console.print(Panel(summary, title="[bold]Malware Analysis[/]", border_style=color))

    # Category table
    if report.category_scores:
        table = Table(title="Category Breakdown", border_style="magenta")
        table.add_column("Category", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Bar", width=25)
        for cat, sc in sorted(report.category_scores.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * int(sc) + "░" * (25 - int(sc))
            table.add_row(cat, f"{sc:.1f}", bar)
        console.print(table)

    # Top indicators
    top_indicators = sorted(report.indicators, key=lambda x: x.weight, reverse=True)[:10]
    if top_indicators:
        table = Table(title="Top Threat Indicators", border_style="red")
        table.add_column("Indicator", style="bold red", max_width=35)
        table.add_column("Category")
        table.add_column("Weight", justify="right")
        table.add_column("Description")
        for ind in top_indicators:
            table.add_row(ind.indicator[:35], ind.category, f"{ind.weight:.1f}", ind.description)
        console.print(table)


# ─── REPORT Command ───────────────────────────────────────────────

@cli.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "markdown", "both"]), default="both")
@click.option("-o", "--output", default="reports", help="Reports output directory.")
@click.pass_context
def report(ctx: click.Context, apk_path: str, fmt: str, output: str) -> None:
    """Generate a comprehensive forensic report."""
    from analytics.report_gen import ReportGenerator

    if not ctx.obj.get("json_output", False):
        _print_banner()

    gen = ReportGenerator(output_dir=output, log_callback=_rich_log)

    if fmt in ("json", "both"):
        path = gen.generate_json(apk_path)
        click.echo(f"JSON report: {path}")

    if fmt in ("markdown", "both"):
        path = gen.generate_markdown(apk_path)
        click.echo(f"Markdown report: {path}")


# ─── DEVICE Command ───────────────────────────────────────────────

@cli.command()
@click.pass_context
def device(ctx: click.Context) -> None:
    """Show connected Android device information."""
    from core.adb_manager import ADBManager
    from rich.panel import Panel

    if not ctx.obj.get("json_output", False):
        _print_banner()

    console = _get_console()
    try:
        adb = ADBManager(log_callback=_rich_log)
        info = adb.connect()

        if ctx.obj.get("json_output", False):
            click.echo(json.dumps({
                "serial": info.serial,
                "model": info.model,
                "android": info.android_version,
                "sdk": info.sdk_level,
                "arch": info.architecture.value,
                "rooted": info.is_rooted,
                "selinux": info.selinux_mode,
            }, indent=2))
        else:
            device_info = (
                f"[bold]Serial:[/] {info.serial}\n"
                f"[bold]Model:[/] {info.model}\n"
                f"[bold]Android:[/] {info.android_version} (SDK {info.sdk_level})\n"
                f"[bold]Architecture:[/] {info.architecture.value}\n"
                f"[bold]Rooted:[/] {'[green]Yes[/]' if info.is_rooted else '[red]No[/]'}\n"
                f"[bold]SELinux:[/] {info.selinux_mode}"
            )
            console.print(Panel(device_info, title="[bold]Device Info[/]", border_style="cyan"))

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/]")


# ─── PAYLOADS Command ─────────────────────────────────────────────

@cli.command()
def payloads() -> None:
    """List available Frida JS payloads."""
    from rich.table import Table

    console = _get_console()
    payloads_dir = Path(__file__).parent.parent / "payloads"

    if not payloads_dir.is_dir():
        console.print("[yellow]No payloads directory found.[/]")
        return

    js_files = sorted(payloads_dir.glob("*.js"))
    if not js_files:
        console.print("[yellow]No .js payloads found.[/]")
        return

    table = Table(title="Available Frida Payloads", border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Payload", style="cyan bold")
    table.add_column("Size", justify="right")

    for i, f in enumerate(js_files, 1):
        size = f.stat().st_size
        table.add_row(str(i), f.name, f"{size:,} bytes")

    console.print(table)
