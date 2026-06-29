from __future__ import annotations
import sys
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from .runner import run_scan
from .reporter import save_reports
from .modules.subdomain_enum import DEFAULT_WORDLIST, load_wordlist

app = typer.Typer(help="Recon Toolkit — automated reconnaissance for pentesters", add_completion=False, no_args_is_help=True)
console = Console()


@app.callback()
def _root() -> None:
    """Recon Toolkit — automated reconnaissance for pentesters."""


def _parse_ports(ports_str: str | None) -> list[int] | None:
    if not ports_str:
        return None
    try:
        return [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        console.print(f"[red]Invalid port list:[/red] {ports_str}")
        raise typer.Exit(1)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or IP address to scan"),
    ports: str | None = typer.Option(None, "--ports", "-p", help="Comma-separated ports (default: top 20 common)"),
    skip_dns: bool = typer.Option(False, "--no-dns", help="Skip DNS enumeration"),
    skip_whois: bool = typer.Option(False, "--no-whois", help="Skip WHOIS lookup"),
    skip_ports: bool = typer.Option(False, "--no-ports", help="Skip port scan"),
    subdomains: bool = typer.Option(False, "--subdomains", "-s", help="Enable subdomain brute-force"),
    wordlist: Path | None = typer.Option(None, "--wordlist", "-w", help="Wordlist for subdomain brute-force (default: built-in 50-word list)"),
    output_dir: Path = typer.Option(Path("reports"), "--output", "-o", help="Output directory for reports"),
) -> None:
    """Run a full recon scan against a domain or IP."""
    sys.stdout.reconfigure(encoding="utf-8")

    console.print(Panel(
        f"[bold cyan]Recon Toolkit[/bold cyan]  scanning [yellow]{target}[/yellow]",
        box=box.ROUNDED,
    ))

    port_list = _parse_ports(ports)

    wl: list[str] | None = None
    if subdomains or wordlist:
        wl_path = wordlist if wordlist else DEFAULT_WORDLIST
        if not wl_path.exists():
            console.print(f"[red]Wordlist not found:[/red] {wl_path}")
            raise typer.Exit(1)
        wl = load_wordlist(wl_path)
        console.print(f"[dim]Subdomain wordlist:[/dim] {len(wl)} words from {wl_path.name}")

    with console.status("[cyan]Running modules...[/cyan]"):
        report = run_scan(
            target,
            ports=port_list,
            skip_dns=skip_dns,
            skip_whois=skip_whois,
            skip_ports=skip_ports,
            wordlist=wl,
        )

    # ── DNS ──────────────────────────────────────────────────────────────────
    if report.dns:
        if report.dns.error:
            console.print(f"[yellow]DNS error:[/yellow] {report.dns.error}")
        elif report.dns.records:
            table = Table(title="DNS Records", box=box.SIMPLE_HEAVY, show_lines=False)
            table.add_column("Type", style="bold cyan", width=8)
            table.add_column("Value")
            for r in report.dns.records:
                table.add_row(r.record_type, r.value)
            console.print(table)
        else:
            console.print("[yellow]No DNS records found.[/yellow]")

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    if report.whois:
        w = report.whois
        if w.error:
            console.print(f"[yellow]WHOIS error:[/yellow] {w.error}")
        else:
            table = Table(title="WHOIS", box=box.SIMPLE_HEAVY)
            table.add_column("Field", style="bold cyan", no_wrap=True)
            table.add_column("Value")
            if w.registrar:
                table.add_row("Registrar", w.registrar)
            if w.creation_date:
                table.add_row("Created", w.creation_date)
            if w.expiration_date:
                table.add_row("Expires", w.expiration_date)
            if w.name_servers:
                table.add_row("Name Servers", "\n".join(w.name_servers))
            console.print(table)

    # ── Ports ─────────────────────────────────────────────────────────────────
    if report.ports:
        open_ports = report.open_ports
        table = Table(
            title=f"Port Scan — [green]{len(open_ports)} open[/green] / {len(report.ports)} scanned",
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("Port", style="bold green", width=7)
        table.add_column("Service", style="cyan", width=16)
        table.add_column("Banner", style="dim")
        for p in open_ports:
            banner = (p.banner[:80] + "...") if len(p.banner) > 80 else p.banner
            table.add_row(str(p.port), p.service, banner)
        if not open_ports:
            console.print("[yellow]No open ports found in scanned range.[/yellow]")
        else:
            console.print(table)

    # ── Subdomains ────────────────────────────────────────────────────────────
    if report.subdomains:
        sub = report.subdomains
        if sub.error:
            console.print(f"[yellow]Subdomain error:[/yellow] {sub.error}")
        elif sub.found:
            table = Table(
                title=f"Subdomains — [green]{len(sub.found)} found[/green] / {sub.total_checked} checked",
                box=box.SIMPLE_HEAVY,
            )
            table.add_column("Subdomain", style="bold cyan")
            table.add_column("IP Addresses", style="green")
            for r in sub.found:
                table.add_row(r.subdomain, ", ".join(r.ip_addresses))
            console.print(table)
        else:
            console.print(f"[yellow]No subdomains found[/yellow] ({sub.total_checked} checked).")

    # ── Save reports ──────────────────────────────────────────────────────────
    paths = save_reports(report, output_dir)
    console.print("\n[green]Reports saved:[/green]")
    for fmt, path in paths.items():
        console.print(f"  [dim]{fmt}:[/dim] {path}")


def main() -> None:
    app()
