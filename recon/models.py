from __future__ import annotations
from enum import Enum
from datetime import datetime
from pydantic import BaseModel


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class PortResult(BaseModel):
    port: int
    state: PortState
    service: str = ""
    banner: str = ""


class DnsRecord(BaseModel):
    record_type: str
    value: str


class DnsResult(BaseModel):
    target: str
    records: list[DnsRecord] = []
    error: str = ""


class WhoisResult(BaseModel):
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: list[str] = []
    error: str = ""


class SubdomainRecord(BaseModel):
    subdomain: str
    ip_addresses: list[str] = []


class SubdomainResult(BaseModel):
    domain: str
    found: list[SubdomainRecord] = []
    total_checked: int = 0
    error: str = ""


class HttpFingerprint(BaseModel):
    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    technologies: list[str] = []
    robots_txt: str = ""
    error: str = ""


class ScanReport(BaseModel):
    target: str
    scan_time: datetime
    dns: DnsResult | None = None
    whois: WhoisResult | None = None
    ports: list[PortResult] = []
    subdomains: SubdomainResult | None = None
    http: list[HttpFingerprint] = []

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]
