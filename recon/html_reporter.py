from __future__ import annotations
import html
from .models import ScanReport

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Courier New', Courier, monospace;
    padding: 2rem;
    max-width: 1100px;
    margin: 0 auto;
    line-height: 1.6;
    font-size: 14px;
}
h1 {
    color: #58a6ff;
    border-bottom: 1px solid #30363d;
    padding-bottom: .6rem;
    margin-bottom: .4rem;
    font-size: 1.6rem;
    letter-spacing: -.02em;
}
h2 {
    color: #79c0ff;
    margin: 1.6rem 0 .6rem;
    font-size: .95rem;
    text-transform: uppercase;
    letter-spacing: .08em;
}
h3 { color: #8b949e; margin: .8rem 0 .3rem; font-size: .85rem; }
.meta { color: #8b949e; font-size: .82rem; margin-bottom: 1.4rem; }
.section {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 1rem 1.2rem;
    margin-bottom: 1.1rem;
}
.summary { display: flex; flex-wrap: wrap; gap: .6rem; margin-bottom: 1.2rem; }
.stat {
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: .3rem .8rem;
    font-size: .82rem;
}
.stat-val { color: #58a6ff; font-weight: bold; margin-right: .3rem; }
table { width: 100%; border-collapse: collapse; font-size: .86rem; }
th {
    background: #1c2128;
    color: #58a6ff;
    text-align: left;
    padding: .4rem .75rem;
    border-bottom: 2px solid #30363d;
    font-weight: normal;
    letter-spacing: .04em;
}
td { padding: .38rem .75rem; border-bottom: 1px solid #21262d; vertical-align: top; }
tr:last-child td { border-bottom: none; }
code {
    background: #1c2128;
    padding: .1rem .35rem;
    border-radius: 3px;
    font-size: .85em;
    color: #a5d6ff;
}
pre {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: .7rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    color: #8b949e;
    font-size: .8rem;
    margin-top: .4rem;
}
.open  { color: #3fb950; font-weight: bold; }
.s2xx  { color: #3fb950; font-weight: bold; }
.s3xx  { color: #d29922; font-weight: bold; }
.s4xx  { color: #f85149; font-weight: bold; }
.s5xx  { color: #f85149; font-weight: bold; }
.err   { color: #f85149; font-style: italic; }
.dim   { color: #8b949e; }
.tag {
    display: inline-block;
    background: #1c2128;
    border: 1px solid #388bfd44;
    border-radius: 12px;
    padding: .1rem .55rem;
    margin: .1rem .1rem 0 0;
    font-size: .76rem;
    color: #79c0ff;
}
"""


def _e(value: object) -> str:
    return html.escape(str(value))


def _status_cls(code: int) -> str:
    if 200 <= code < 300:
        return "s2xx"
    if 300 <= code < 400:
        return "s3xx"
    if 400 <= code < 500:
        return "s4xx"
    return "s5xx"


def render_html(report: ScanReport) -> str:
    parts: list[str] = []
    w = parts.append
    open_ports = report.open_ports

    w(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon: {_e(report.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>&#x1F50D; Recon Report: {_e(report.target)}</h1>
<p class="meta">Scan time: {_e(report.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC'))}</p>""")

    # ── Summary badges ─────────────────────────────────────────────────────────
    stats: list[tuple[str, str]] = []
    if report.dns:
        stats.append((str(len(report.dns.records)), "DNS records"))
    if report.ports:
        stats.append((str(len(open_ports)), "open ports"))
    if report.http:
        stats.append((str(len(report.http)), "web endpoints"))
    if report.subdomains:
        stats.append((str(len(report.subdomains.found)), "subdomains found"))
    if stats:
        w('<div class="summary">')
        for val, label in stats:
            w(f'<div class="stat"><span class="stat-val">{_e(val)}</span>{_e(label)}</div>')
        w('</div>')

    # ── DNS ───────────────────────────────────────────────────────────────────
    if report.dns:
        w('<div class="section"><h2>DNS Records</h2>')
        if report.dns.error:
            w(f'<p class="err">{_e(report.dns.error)}</p>')
        elif report.dns.records:
            w('<table><tr><th>Type</th><th>Value</th></tr>')
            for r in report.dns.records:
                w(f'<tr><td><code>{_e(r.record_type)}</code></td><td>{_e(r.value)}</td></tr>')
            w('</table>')
        else:
            w('<p class="dim">No records found.</p>')
        w('</div>')

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    if report.whois:
        wh = report.whois
        w('<div class="section"><h2>WHOIS</h2>')
        if wh.error:
            w(f'<p class="err">{_e(wh.error)}</p>')
        else:
            w('<table>')
            rows = [
                ("Registrar", wh.registrar),
                ("Created", wh.creation_date),
                ("Expires", wh.expiration_date),
                ("Name Servers", ", ".join(wh.name_servers)),
            ]
            for label, value in rows:
                if value:
                    w(f'<tr><td class="dim">{_e(label)}</td><td>{_e(value)}</td></tr>')
            w('</table>')
        w('</div>')

    # ── Port scan ─────────────────────────────────────────────────────────────
    if report.ports:
        w(f'<div class="section"><h2>Port Scan &mdash; {len(open_ports)} open / {len(report.ports)} scanned</h2>')
        if open_ports:
            w('<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>')
            for p in open_ports:
                banner = (_e(p.banner[:80]) + "&hellip;") if len(p.banner) > 80 else _e(p.banner)
                w(f'<tr>'
                  f'<td class="open">{p.port}</td>'
                  f'<td><code>{_e(p.service)}</code></td>'
                  f'<td class="dim">{banner}</td>'
                  f'</tr>')
            w('</table>')
        else:
            w('<p class="dim">No open ports in scanned range.</p>')
        w('</div>')

    # ── HTTP fingerprinting ───────────────────────────────────────────────────
    if report.http:
        w(f'<div class="section"><h2>HTTP Fingerprinting &mdash; {len(report.http)} endpoint(s)</h2>')
        w('<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technologies</th></tr>')
        for fp in report.http:
            if fp.error:
                w(f'<tr>'
                  f'<td><code>{_e(fp.url)}</code></td>'
                  f'<td colspan="4" class="err">{_e(fp.error)}</td>'
                  f'</tr>')
            else:
                cls = _status_cls(fp.status_code)
                techs = (
                    "".join(f'<span class="tag">{_e(t)}</span>' for t in fp.technologies)
                    if fp.technologies else '<span class="dim">—</span>'
                )
                w(f'<tr>'
                  f'<td><code>{_e(fp.url)}</code></td>'
                  f'<td class="{cls}">{fp.status_code}</td>'
                  f'<td>{_e(fp.title) or "<span class=\'dim\'>—</span>"}</td>'
                  f'<td class="dim">{_e(fp.server) or "—"}</td>'
                  f'<td>{techs}</td>'
                  f'</tr>')
        w('</table>')
        for fp in report.http:
            if fp.robots_txt:
                w(f'<h3>robots.txt &mdash; <code>{_e(fp.url)}</code></h3>')
                w(f'<pre>{_e(fp.robots_txt.strip())}</pre>')
        w('</div>')

    # ── Subdomains ─────────────────────────────────────────────────────────────
    if report.subdomains:
        sub = report.subdomains
        w(f'<div class="section"><h2>Subdomain Enumeration &mdash; {len(sub.found)} found / {sub.total_checked} checked</h2>')
        if sub.error:
            w(f'<p class="err">{_e(sub.error)}</p>')
        elif sub.found:
            w('<table><tr><th>Subdomain</th><th>IP Addresses</th></tr>')
            for r in sub.found:
                ips = _e(", ".join(r.ip_addresses))
                w(f'<tr><td><code>{_e(r.subdomain)}</code></td><td>{ips}</td></tr>')
            w('</table>')
        else:
            w('<p class="dim">No subdomains found.</p>')
        w('</div>')

    w('</body>\n</html>')
    return "\n".join(parts)
