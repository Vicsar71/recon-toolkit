# Recon Toolkit

Automated reconnaissance tool for pentesters and security researchers. Given a domain or IP address, it runs DNS enumeration, WHOIS lookup and port scanning in parallel, then produces a clean Markdown and JSON report.

```
$ python -m recon scan scanme.nmap.org

╭─────────────────────────────────────────╮
│  Recon Toolkit  scanning scanme.nmap.org │
╰─────────────────────────────────────────╯

      DNS Records
 Type  Value
 ──────────────────────────────────────
 A     45.33.32.156
 AAAA  2600:3c01::f03c:91ff:fe18:bb2f
 MX    0 .

      WHOIS
 Field        Value
 ────────────────────────────────────
 Registrar    ARIN

  Port Scan — 2 open / 20 scanned
 Port   Service    Banner
 ─────────────────────────────────────────────────────
 22     ssh        SSH-2.0-OpenSSH_6.6.1p1 Ubuntu...
 80     http
```

## Features

- **DNS enumeration** — A, AAAA, MX, NS, TXT, CNAME records via `dnspython`
- **WHOIS lookup** — registrar, creation/expiration dates, name servers
- **Port scanning** — concurrent TCP connect scan (ThreadPoolExecutor), banner grabbing, top-20 common ports by default
- **Rich terminal output** — colour-coded tables via `rich`
- **Dual report format** — Markdown + JSON saved automatically to `reports/`
- **Fully modular** — skip any module with `--no-dns`, `--no-whois`, `--no-ports`

## Installation

```bash
git clone https://github.com/Vicsar71/recon-toolkit.git
cd recon-toolkit
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
# Full scan (DNS + WHOIS + ports)
python -m recon scan scanme.nmap.org

# Custom port list
python -m recon scan 45.33.32.156 --ports 22,80,443,8080,8443

# Skip WHOIS (faster, no external query)
python -m recon scan example.com --no-whois

# Save reports to a custom directory
python -m recon scan example.com --output my_reports/
```

Reports are written to `reports/` by default:

```
reports/
  scanme_nmap_org_20260625_184938.md
  scanme_nmap_org_20260625_184938.json
```

## Project structure

```
recon/
  models.py          # Pydantic data models
  runner.py          # Scan orchestrator
  reporter.py        # Markdown + JSON report writer
  cli.py             # Typer CLI + Rich output
  modules/
    dns_enum.py      # DNS enumeration (dnspython)
    whois_lookup.py  # WHOIS lookup (python-whois)
    port_scanner.py  # Concurrent TCP port scanner
tests/
  test_models.py
  test_reporter.py
```

## Running tests

```bash
pytest                              # all tests
pytest tests/test_reporter.py      # reporter only
```

Tests are pure-logic (no network required).

## Roadmap

- [x] Milestone 1 — DNS, WHOIS, port scan, reporter, CLI, tests
- [ ] Milestone 2 — Subdomain enumeration (async wordlist brute-force)
- [ ] Milestone 3 — HTTP fingerprinting (title, server, tech stack)
- [ ] Milestone 4 — HTML report + screenshots

## Legal

For use against systems you own or have explicit written permission to test.
