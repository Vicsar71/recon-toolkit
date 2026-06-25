from __future__ import annotations
import socket
from datetime import datetime, timezone
from .models import ScanReport
from .modules.dns_enum import enumerate_dns
from .modules.whois_lookup import lookup_whois
from .modules.port_scanner import scan_ports, TOP_PORTS


def run_scan(
    target: str,
    ports: list[int] | None = None,
    skip_dns: bool = False,
    skip_whois: bool = False,
    skip_ports: bool = False,
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

    return report
