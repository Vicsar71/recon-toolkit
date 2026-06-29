from __future__ import annotations
import asyncio
from pathlib import Path
import dns.asyncresolver
import dns.exception
import dns.resolver
from ..models import SubdomainRecord, SubdomainResult

DEFAULT_WORDLIST = Path(__file__).parent.parent.parent / "data" / "wordlists" / "subdomains-small.txt"

_CONCURRENCY = 50


def load_wordlist(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


async def _check(
    resolver: dns.asyncresolver.Resolver,
    subdomain: str,
    sem: asyncio.Semaphore,
) -> SubdomainRecord | None:
    async with sem:
        try:
            answers = await resolver.resolve(subdomain, "A")
            return SubdomainRecord(subdomain=subdomain, ip_addresses=[str(r) for r in answers])
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            return None


async def _bruteforce(domain: str, words: list[str]) -> SubdomainResult:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    sem = asyncio.Semaphore(_CONCURRENCY)
    tasks = [_check(resolver, f"{w}.{domain}", sem) for w in words]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    found = [r for r in results if isinstance(r, SubdomainRecord)]
    return SubdomainResult(domain=domain, found=found, total_checked=len(words))


def enumerate_subdomains(domain: str, wordlist: list[str]) -> SubdomainResult:
    if not wordlist:
        return SubdomainResult(domain=domain, found=[], total_checked=0)
    return asyncio.run(_bruteforce(domain, wordlist))
