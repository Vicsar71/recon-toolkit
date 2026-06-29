from __future__ import annotations
from pathlib import Path
from .models import ScanReport, PortState
from .html_reporter import render_html

_VALID_FORMATS = ("md", "html", "both")


def save_reports(
    report: ScanReport,
    output_dir: Path = Path("reports"),
    fmt: str = "both",
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = report.scan_time.strftime("%Y%m%d_%H%M%S")
    safe_target = report.target.replace(".", "_").replace("/", "_").replace(":", "_")
    stem = f"{safe_target}_{timestamp}"

    paths: dict[str, Path] = {}

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    paths["json"] = json_path

    if fmt in ("md", "both"):
        md_path = output_dir / f"{stem}.md"
        md_path.write_text(_render_markdown(report), encoding="utf-8")
        paths["markdown"] = md_path

    if fmt in ("html", "both"):
        html_path = output_dir / f"{stem}.html"
        html_path.write_text(render_html(report), encoding="utf-8")
        paths["html"] = html_path

    return paths


def _render_markdown(report: ScanReport) -> str:
    lines: list[str] = [
        f"# Recon Report: {report.target}",
        f"**Scan time:** {report.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
    ]

    if report.dns:
        lines += ["## DNS Records", ""]
        if report.dns.error:
            lines.append(f"_Error: {report.dns.error}_")
        elif report.dns.records:
            lines += ["| Type | Value |", "|------|-------|"]
            for r in report.dns.records:
                lines.append(f"| {r.record_type} | `{r.value}` |")
        else:
            lines.append("_No records found._")
        lines.append("")

    if report.whois:
        lines += ["## WHOIS", ""]
        w = report.whois
        if w.error:
            lines.append(f"_Error: {w.error}_")
        else:
            if w.registrar:
                lines.append(f"- **Registrar:** {w.registrar}")
            if w.creation_date:
                lines.append(f"- **Created:** {w.creation_date}")
            if w.expiration_date:
                lines.append(f"- **Expires:** {w.expiration_date}")
            if w.name_servers:
                lines.append(f"- **Name servers:** {', '.join(w.name_servers)}")
        lines.append("")

    open_ports = [p for p in report.ports if p.state == PortState.OPEN]
    if report.ports:
        lines += [f"## Port Scan — {len(open_ports)} open / {len(report.ports)} scanned", ""]
        if open_ports:
            lines += ["| Port | Service | Banner |", "|------|---------|--------|"]
            for p in open_ports:
                banner = (p.banner[:60] + "...") if len(p.banner) > 60 else p.banner
                lines.append(f"| {p.port} | {p.service} | `{banner}` |")
        else:
            lines.append("_No open ports found in scanned range._")
        lines.append("")

    if report.subdomains:
        sub = report.subdomains
        lines += [f"## Subdomain Enumeration — {len(sub.found)} found / {sub.total_checked} checked", ""]
        if sub.error:
            lines.append(f"_Error: {sub.error}_")
        elif sub.found:
            lines += ["| Subdomain | IP Addresses |", "|-----------|-------------|"]
            for r in sub.found:
                lines.append(f"| {r.subdomain} | {', '.join(r.ip_addresses)} |")
        else:
            lines.append("_No subdomains found._")
        lines.append("")

    if report.http:
        lines += [f"## HTTP Fingerprinting — {len(report.http)} endpoint(s)", ""]
        lines += ["| URL | Status | Title | Server | Technologies |",
                  "|-----|--------|-------|--------|-------------|"]
        for fp in report.http:
            if fp.error:
                lines.append(f"| {fp.url} | — | _Error: {fp.error}_ | | |")
            else:
                techs = ", ".join(fp.technologies) if fp.technologies else "—"
                lines.append(
                    f"| {fp.url} | {fp.status_code} | {fp.title or '—'} | {fp.server or '—'} | {techs} |"
                )
        lines.append("")
        for fp in report.http:
            if fp.robots_txt:
                lines += [f"### robots.txt — {fp.url}", "", "```", fp.robots_txt.strip(), "```", ""]

    return "\n".join(lines)
