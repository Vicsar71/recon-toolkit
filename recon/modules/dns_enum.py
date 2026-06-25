from __future__ import annotations
import dns.resolver
import dns.exception
from ..models import DnsRecord, DnsResult

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def enumerate_dns(target: str) -> DnsResult:
    records: list[DnsRecord] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            for rdata in answers:
                records.append(DnsRecord(record_type=rtype, value=str(rdata)))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            pass

    return DnsResult(target=target, records=records)
