from __future__ import annotations
from datetime import datetime, timezone
from unittest.mock import patch

import httpx

from recon.models import HttpFingerprint, PortResult, PortState, ScanReport
from recon.modules.http_fingerprint import (
    _detect_technologies,
    _extract_title,
    _scheme_for_port,
    fingerprint_port,
    fingerprint_web_ports,
)
from recon.reporter import _render_markdown


# ── Pure logic — title extraction ─────────────────────────────────────────────

def test_extract_title_simple():
    assert _extract_title("<html><title>Hello World</title></html>") == "Hello World"


def test_extract_title_multiline():
    assert _extract_title("<html><title>\n  My Page \n</title></html>") == "My Page"


def test_extract_title_missing():
    assert _extract_title("<html><body>no title</body></html>") == ""


def test_extract_title_case_insensitive():
    assert _extract_title("<HTML><TITLE>Upper</TITLE></HTML>") == "Upper"


# ── Pure logic — technology detection ─────────────────────────────────────────

def test_detect_tech_powered_by_with_version():
    headers = httpx.Headers({"x-powered-by": "PHP/8.1"})
    assert "PHP" in _detect_technologies(headers, httpx.Cookies())


def test_detect_tech_powered_by_no_version():
    headers = httpx.Headers({"x-powered-by": "ASP.NET"})
    assert "ASP.NET" in _detect_technologies(headers, httpx.Cookies())


def test_detect_tech_cookie_hint():
    cookies = httpx.Cookies({"PHPSESSID": "abc123"})
    assert "PHP" in _detect_technologies(httpx.Headers({}), cookies)


def test_detect_tech_django_cookie():
    cookies = httpx.Cookies({"csrftoken": "xyz"})
    assert "Django" in _detect_technologies(httpx.Headers({}), cookies)


def test_detect_tech_no_hints():
    assert _detect_technologies(httpx.Headers({}), httpx.Cookies()) == []


def test_detect_tech_result_is_sorted():
    headers = httpx.Headers({"x-powered-by": "PHP/7"})
    cookies = httpx.Cookies({"csrftoken": "x"})
    techs = _detect_technologies(headers, cookies)
    assert techs == sorted(techs)


# ── Pure logic — scheme detection ─────────────────────────────────────────────

def test_scheme_http_ports():
    assert _scheme_for_port(80, "") == "http"
    assert _scheme_for_port(8080, "") == "http"
    assert _scheme_for_port(8000, "") == "http"


def test_scheme_https_ports():
    assert _scheme_for_port(443, "") == "https"
    assert _scheme_for_port(8443, "") == "https"


def test_scheme_by_service_name():
    assert _scheme_for_port(9000, "http-alt") == "http"
    assert _scheme_for_port(9443, "https") == "https"
    assert _scheme_for_port(9443, "https-alt") == "https"


def test_scheme_unknown_returns_none():
    assert _scheme_for_port(22, "ssh") is None
    assert _scheme_for_port(3306, "mysql") is None
    assert _scheme_for_port(9999, "") is None


# ── fingerprint_port with mocked httpx ────────────────────────────────────────

class _FakeResponse:
    status_code = 200
    text = "<html><head><title>Test Site</title></head><body>hi</body></html>"
    headers = httpx.Headers({"server": "nginx/1.24", "content-type": "text/html"})
    cookies = httpx.Cookies()


class _FakeRobotsResponse:
    status_code = 200
    text = "User-agent: *\nDisallow: /admin\n"
    headers = httpx.Headers({"content-type": "text/plain"})
    cookies = httpx.Cookies()


class _FakeClient:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def get(self, url, **kwargs):
        if url.endswith("/robots.txt"):
            return _FakeRobotsResponse()
        return _FakeResponse()


def _patch_client(cls=_FakeClient):
    return patch("recon.modules.http_fingerprint.httpx.Client", lambda **kw: cls())


def test_fingerprint_port_extracts_title_and_server():
    with _patch_client():
        fp = fingerprint_port("example.com", 80)
    assert fp is not None
    assert fp.title == "Test Site"
    assert fp.server == "nginx/1.24"
    assert fp.status_code == 200


def test_fingerprint_port_captures_robots():
    with _patch_client():
        fp = fingerprint_port("example.com", 80)
    assert fp is not None
    assert "Disallow: /admin" in fp.robots_txt


def test_fingerprint_port_skips_non_web():
    with _patch_client():
        assert fingerprint_port("example.com", 22, "ssh") is None
        assert fingerprint_port("example.com", 3306, "mysql") is None


def test_fingerprint_port_uses_https_for_443():
    with _patch_client():
        fp = fingerprint_port("example.com", 443)
    assert fp is not None
    assert fp.url.startswith("https://")


def test_fingerprint_port_error_stored():
    class _BrokenClient:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def get(self, *a, **kw):
            raise ConnectionRefusedError("refused")

    with patch("recon.modules.http_fingerprint.httpx.Client", lambda **kw: _BrokenClient()):
        fp = fingerprint_port("example.com", 80)
    assert fp is not None
    assert fp.error != ""


def test_fingerprint_web_ports_filters_non_web():
    ports = [
        PortResult(port=80, state=PortState.OPEN, service="http"),
        PortResult(port=22, state=PortState.OPEN, service="ssh"),
        PortResult(port=443, state=PortState.OPEN, service="https"),
    ]
    with _patch_client():
        results = fingerprint_web_ports("example.com", ports)
    assert len(results) == 2
    urls = [r.url for r in results]
    assert any(":80" in u for u in urls)
    assert any(":443" in u for u in urls)


# ── Reporter ──────────────────────────────────────────────────────────────────

def _report_with_http(**kwargs) -> ScanReport:
    return ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        http=[HttpFingerprint(url="http://example.com:80", **kwargs)],
    )


def test_markdown_http_section_present():
    md = _render_markdown(_report_with_http(status_code=200, title="Example", server="nginx"))
    assert "HTTP Fingerprinting" in md
    assert "example.com:80" in md
    assert "nginx" in md


def test_markdown_http_shows_technologies():
    md = _render_markdown(_report_with_http(status_code=200, technologies=["PHP", "Laravel"]))
    assert "PHP" in md
    assert "Laravel" in md


def test_markdown_http_error_row():
    md = _render_markdown(_report_with_http(error="Connection refused"))
    assert "Connection refused" in md


def test_markdown_http_robots_section():
    md = _render_markdown(_report_with_http(
        status_code=200,
        robots_txt="User-agent: *\nDisallow: /secret",
    ))
    assert "robots.txt" in md
    assert "Disallow: /secret" in md


def test_markdown_no_http_section_when_empty():
    report = ScanReport(
        target="example.com",
        scan_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    md = _render_markdown(report)
    assert "HTTP Fingerprinting" not in md
