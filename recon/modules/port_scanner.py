from __future__ import annotations
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..models import PortResult, PortState

COMMON_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
    9200: "elasticsearch",
    5601: "kibana",
}

TOP_PORTS: list[int] = list(COMMON_SERVICES.keys())


def _probe_port(host: str, port: int, timeout: float = 1.5) -> PortResult:
    service = COMMON_SERVICES.get(port, "")
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(1.0)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass
            return PortResult(port=port, state=PortState.OPEN, service=service, banner=banner)
    except ConnectionRefusedError:
        return PortResult(port=port, state=PortState.CLOSED, service=service)
    except OSError:
        return PortResult(port=port, state=PortState.CLOSED, service=service)
    except socket.timeout:
        return PortResult(port=port, state=PortState.FILTERED, service=service)


def scan_ports(host: str, ports: list[int] | None = None, max_workers: int = 50) -> list[PortResult]:
    target_ports = ports if ports is not None else TOP_PORTS
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_port, host, port): port for port in target_ports}
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r.port)
