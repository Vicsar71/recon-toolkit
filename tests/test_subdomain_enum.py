from __future__ import annotations
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import dns.resolver

from recon.models import SubdomainRecord, SubdomainResult, ScanReport
from recon.modules.subdomain_enum import enumerate_subdomains, _bruteforce, DEFAULT_WORDLIST, load_wordlist
from recon.reporter import _render_markdown


# ── Model tests ───────────────────────────────────────────────────────────────

def test_subdomain_record_stores_fields():
    r = SubdomainRecord(subdomain="www.example.com", ip_addresses=["1.2.3.4", "5.6.7.8"])
    assert r.subdomain == "www.example.com"
    assert r.ip_addresses == ["1.2.3.4", "5.6.7.8"]


def test_subdomain_result_defaults():
    result = SubdomainResult(domain="example.com")
    assert result.found == []
    assert result.total_checked == 0
    assert result.error == ""


def test_subdomain_result_counts():
    result = SubdomainResult(
        domain="example.com",
        found=[SubdomainRecord(subdomain="www.example.com", ip_addresses=["1.2.3.4"])],
        total_checked=50,
    )
    assert len(result.found) == 1
    assert result.total_checked == 50


# ── enumerate_subdomains edge cases ───────────────────────────────────────────

def test_empty_wordlist_returns_empty():
    result = enumerate_subdomains("example.com", [])
    assert result.found == []
    assert result.total_checked == 0
    assert result.domain == "example.com"


# ── Async brute-force with mocked resolver ────────────────────────────────────

def _make_mock_resolver(hits: dict[str, list[str]]) -> MagicMock:
    """Return a mock dns.asyncresolver.Resolver where only `hits` subdomains resolve."""
    resolver = MagicMock()

    async def fake_resolve(name: str, rtype: str):
        if name in hits:
            return [MagicMock(__str__=lambda self, ip=ip: ip) for ip in hits[name]]
        raise dns.resolver.NXDOMAIN()

    resolver.resolve = fake_resolve
    resolver.timeout = 3
    resolver.lifetime = 5
    return resolver


def test_bruteforce_finds_known_subdomains():
    hits = {"www.example.com": ["1.2.3.4"], "api.example.com": ["5.6.7.8"]}
    mock_resolver = _make_mock_resolver(hits)

    with patch("recon.modules.subdomain_enum.dns.asyncresolver.Resolver", return_value=mock_resolver):
        result = asyncio.run(_bruteforce("example.com", ["www", "mail", "api", "ftp"]))

    assert result.total_checked == 4
    assert len(result.found) == 2
    found_names = {r.subdomain for r in result.found}
    assert found_names == {"www.example.com", "api.example.com"}


def test_bruteforce_all_nxdomain():
    mock_resolver = _make_mock_resolver({})

    with patch("recon.modules.subdomain_enum.dns.asyncresolver.Resolver", return_value=mock_resolver):
        result = asyncio.run(_bruteforce("example.com", ["www", "mail"]))

    assert result.found == []
    assert result.total_checked == 2


# ── Default wordlist ──────────────────────────────────────────────────────────

def test_default_wordlist_exists():
    assert DEFAULT_WORDLIST.exists(), f"Default wordlist not found at {DEFAULT_WORDLIST}"


def test_default_wordlist_not_empty():
    words = load_wordlist(DEFAULT_WORDLIST)
    assert len(words) >= 10
    assert "www" in words
    assert "api" in words


def test_load_wordlist_ignores_blank_lines(tmp_path: Path):
    wl = tmp_path / "words.txt"
    wl.write_text("www\n\nmail\n  \napi\n", encoding="utf-8")
    words = load_wordlist(wl)
    assert words == ["www", "mail", "api"]


# ── Reporter includes subdomains ──────────────────────────────────────────────

def test_markdown_includes_subdomain_section():
    report = ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        subdomains=SubdomainResult(
            domain="example.com",
            found=[SubdomainRecord(subdomain="www.example.com", ip_addresses=["1.2.3.4"])],
            total_checked=50,
        ),
    )
    md = _render_markdown(report)
    assert "Subdomain" in md
    assert "www.example.com" in md
    assert "1.2.3.4" in md
    assert "50" in md


def test_markdown_no_subdomains_found():
    report = ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        subdomains=SubdomainResult(domain="example.com", found=[], total_checked=50),
    )
    md = _render_markdown(report)
    assert "No subdomains found" in md
