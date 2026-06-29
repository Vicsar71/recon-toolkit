# Recon Toolkit

Automated reconnaissance tool for pentesters and security researchers. Given a domain or IP address, it runs DNS enumeration, WHOIS lookup, port scanning and async subdomain brute-force in parallel, then produces a clean Markdown and JSON report.

```
$ python -m recon scan scanme.nmap.org --subdomains

╭──────────────────────────────────────────╮
│  Recon Toolkit  scanning scanme.nmap.org │
╰──────────────────────────────────────────╯
Subdomain wordlist: 50 words from subdomains-small.txt

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

  Subdomains — 1 found / 50 checked
 Subdomain              IP Addresses
 ──────────────────────────────────────────
 www.scanme.nmap.org    45.33.32.156
```

## Features

- **DNS enumeration** — A, AAAA, MX, NS, TXT, CNAME records via `dnspython`
- **WHOIS lookup** — registrar, creation/expiration dates, name servers
- **Port scanning** — concurrent TCP connect scan (ThreadPoolExecutor), banner grabbing, top-20 common ports by default
- **Subdomain brute-force** — async DNS resolution via `asyncio` + `dnspython`, up to 50 concurrent queries; built-in 50-word wordlist or bring your own
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

# Include subdomain brute-force (built-in wordlist)
python -m recon scan example.com --subdomains

# Custom wordlist
python -m recon scan example.com --wordlist /path/to/wordlist.txt

# Custom port list, skip WHOIS
python -m recon scan 45.33.32.156 --ports 22,80,443,8080,8443 --no-whois

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
    subdomain_enum.py  # Async subdomain brute-force
data/
  wordlists/
    subdomains-small.txt  # Built-in 50-word subdomain list
tests/
  test_models.py
  test_reporter.py
  test_subdomain_enum.py
```

## Running tests

```bash
pytest                                    # all tests
pytest tests/test_subdomain_enum.py      # subdomain module only
```

Tests are pure-logic (no network required).

## Roadmap

- [x] Milestone 1 — DNS, WHOIS, port scan, reporter, CLI, tests
- [x] Milestone 2 — Subdomain enumeration (async wordlist brute-force)
- [ ] Milestone 3 — HTTP fingerprinting (title, server, tech stack)
- [ ] Milestone 4 — HTML report + screenshots

## Legal

For use against systems you own or have explicit written permission to test.
