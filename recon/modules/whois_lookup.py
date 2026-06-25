from __future__ import annotations
import whois
from ..models import WhoisResult


def _fmt_date(d: object) -> str:
    if isinstance(d, list):
        d = d[0]
    return str(d) if d else ""


def lookup_whois(target: str) -> WhoisResult:
    try:
        w = whois.whois(target)
        name_servers: list[str] = w.name_servers or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        name_servers = sorted({ns.lower() for ns in name_servers if ns})

        return WhoisResult(
            domain=target,
            registrar=w.registrar or "",
            creation_date=_fmt_date(w.creation_date),
            expiration_date=_fmt_date(w.expiration_date),
            name_servers=name_servers,
        )
    except Exception as exc:
        return WhoisResult(domain=target, error=str(exc))
