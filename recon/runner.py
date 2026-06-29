from __future__ import annotations
import socket
from datetime import datetime, timezone
from .models import ScanReport
from .modules.dns_enum import enumerate_dns
from .modules.whois_lookup import lookup_whois
from .modules.port_scanner import scan_ports, TOP_PORTS
from .modules.subdomain_enum import enumerate_subdomains
from .modules.http_fingerprint import fingerprint_web_ports


def run_scan(
    target: str,
    ports: list[int] | None = None,
    skip_dns: bool = False,
    skip_whois: bool = False,
    skip_ports: bool = False,
    skip_http: bool = False,
    wordlist: list[str] | None = None,
) -> ScanReport:
    report = ScanReport(target=target, scan_time=datetime.now(timezone.utc))

    if not skip_dns:
        report.dns = enumerate_dns(target)

    if not skip_whois:
        report.whois = lookup_whois(target)

    if not skip_ports:
        try:
            host_ip = socket.gethostbyname(target)
        except socket.gaierror:
            host_ip = target
        report.ports = scan_ports(host_ip, ports if ports is not None else TOP_PORTS)

    if not skip_ports and not skip_http and report.open_ports:
        report.http = fingerprint_web_ports(target, report.open_ports)

    if wordlist is not None:
        report.subdomains = enumerate_subdomains(target, wordlist)

    return report
