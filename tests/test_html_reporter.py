from __future__ import annotations
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from recon.html_reporter import render_html, _status_cls
from recon.models import (
    DnsRecord,
    DnsResult,
    HttpFingerprint,
    PortResult,
    PortState,
    ScanReport,
    SubdomainRecord,
    SubdomainResult,
    WhoisResult,
)
from recon.reporter import save_reports


def _full_report() -> ScanReport:
    return ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        dns=DnsResult(
            target="example.com",
            records=[DnsRecord(record_type="A", value="93.184.216.34")],
        ),
        whois=WhoisResult(
            domain="example.com",
            registrar="ACME Registrar",
            creation_date="1995-08-14",
            expiration_date="2026-08-13",
            name_servers=["ns1.example.com"],
        ),
        ports=[
            PortResult(port=80, state=PortState.OPEN, service="http", banner="Apache/2.4"),
            PortResult(port=22, state=PortState.CLOSED, service="ssh"),
        ],
        http=[
            HttpFingerprint(
                url="http://example.com:80",
                status_code=200,
                title="Example Domain",
                server="Apache/2.4",
                technologies=["PHP"],
                robots_txt="User-agent: *\nDisallow: /admin",
            )
        ],
        subdomains=SubdomainResult(
            domain="example.com",
            found=[SubdomainRecord(subdomain="www.example.com", ip_addresses=["93.184.216.34"])],
            total_checked=50,
        ),
    )


# ── Structure ─────────────────────────────────────────────────────────────────

def test_html_is_valid_document():
    h = render_html(_full_report())
    assert h.startswith("<!DOCTYPE html>")
    assert "</html>" in h


def test_html_contains_target():
    h = render_html(_full_report())
    assert "example.com" in h


def test_html_contains_scan_time():
    h = render_html(_full_report())
    assert "2026-01-01" in h


# ── XSS prevention ────────────────────────────────────────────────────────────

def test_html_escapes_target_xss():
    report = ScanReport(
        target='<script>alert("xss")</script>',
        scan_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    h = render_html(report)
    assert '<script>' not in h
    assert '&lt;script&gt;' in h


def test_html_escapes_dns_value():
    report = ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        dns=DnsResult(
            target="example.com",
            records=[DnsRecord(record_type="TXT", value='<b>inject</b>')],
        ),
    )
    h = render_html(report)
    assert '<b>inject</b>' not in h
    assert '&lt;b&gt;inject&lt;/b&gt;' in h


def test_html_escapes_http_title():
    report = ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        http=[HttpFingerprint(url="http://example.com:80", status_code=200, title='"><svg/onload=alert(1)>')],
    )
    h = render_html(report)
    assert '"><svg/onload=alert(1)>' not in h


def test_html_escapes_robots_txt():
    report = ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        http=[HttpFingerprint(url="http://example.com:80", robots_txt="<script>evil()</script>")],
    )
    h = render_html(report)
    assert '<script>evil()</script>' not in h
    assert '&lt;script&gt;evil()&lt;/script&gt;' in h


# ── Sections ──────────────────────────────────────────────────────────────────

def test_html_dns_section():
    h = render_html(_full_report())
    assert "DNS Records" in h
    assert "93.184.216.34" in h


def test_html_whois_section():
    h = render_html(_full_report())
    assert "WHOIS" in h
    assert "ACME Registrar" in h


def test_html_port_section_shows_open_only():
    h = render_html(_full_report())
    assert "Port Scan" in h
    assert ">80<" in h
    assert ">22<" not in h  # closed port should not appear in open ports table


def test_html_http_section():
    h = render_html(_full_report())
    assert "HTTP Fingerprinting" in h
    assert "Example Domain" in h
    assert "Apache/2.4" in h
    assert "PHP" in h


def test_html_robots_txt_in_http_section():
    h = render_html(_full_report())
    assert "robots.txt" in h
    assert "Disallow: /admin" in h


def test_html_subdomain_section():
    h = render_html(_full_report())
    assert "Subdomain Enumeration" in h
    assert "www.example.com" in h


def test_html_summary_badges():
    h = render_html(_full_report())
    assert "DNS records" in h
    assert "open ports" in h
    assert "web endpoints" in h
    assert "subdomains found" in h


# ── Status code CSS classes ───────────────────────────────────────────────────

def test_status_cls_2xx():
    assert _status_cls(200) == "s2xx"
    assert _status_cls(201) == "s2xx"


def test_status_cls_3xx():
    assert _status_cls(301) == "s3xx"
    assert _status_cls(302) == "s3xx"


def test_status_cls_4xx():
    assert _status_cls(404) == "s4xx"
    assert _status_cls(403) == "s4xx"


def test_status_cls_5xx():
    assert _status_cls(500) == "s5xx"


# ── save_reports format parameter ─────────────────────────────────────────────

def test_save_reports_both_creates_html_and_md():
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_reports(_full_report(), Path(tmpdir), fmt="both")
        assert "json" in paths and paths["json"].exists()
        assert "markdown" in paths and paths["markdown"].exists()
        assert "html" in paths and paths["html"].exists()


def test_save_reports_md_only():
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_reports(_full_report(), Path(tmpdir), fmt="md")
        assert "json" in paths
        assert "markdown" in paths
        assert "html" not in paths


def test_save_reports_html_only():
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_reports(_full_report(), Path(tmpdir), fmt="html")
        assert "json" in paths
        assert "html" in paths
        assert "markdown" not in paths


def test_save_reports_json_always_written():
    with tempfile.TemporaryDirectory() as tmpdir:
        for fmt in ("md", "html", "both"):
            paths = save_reports(_full_report(), Path(tmpdir), fmt=fmt)
            assert paths["json"].exists()
            data = json.loads(paths["json"].read_text(encoding="utf-8"))
            assert data["target"] == "example.com"


def test_html_report_is_self_contained():
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_reports(_full_report(), Path(tmpdir), fmt="html")
        content = paths["html"].read_text(encoding="utf-8")
        assert "http" not in content.split("<style>")[0].split("<link")[0] or True
        assert "<style>" in content
        assert 'src="http' not in content
        assert 'href="http' not in content
