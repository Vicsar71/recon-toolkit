import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from recon.models import ScanReport, PortResult, PortState, DnsResult, DnsRecord, WhoisResult
from recon.reporter import save_reports, _render_markdown


def _sample_report() -> ScanReport:
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
            name_servers=["ns1.example.com", "ns2.example.com"],
        ),
        ports=[
            PortResult(port=80, state=PortState.OPEN, service="http"),
            PortResult(port=443, state=PortState.OPEN, service="https"),
            PortResult(port=22, state=PortState.CLOSED, service="ssh"),
        ],
    )


def test_markdown_contains_target():
    md = _render_markdown(_sample_report())
    assert "example.com" in md


def test_markdown_contains_open_ports():
    md = _render_markdown(_sample_report())
    assert "80" in md
    assert "443" in md


def test_markdown_closed_ports_not_in_table():
    md = _render_markdown(_sample_report())
    lines = [l for l in md.splitlines() if "| 22 |" in l]
    assert lines == [], "Closed ports should not appear in the port table"


def test_markdown_contains_dns_record():
    md = _render_markdown(_sample_report())
    assert "93.184.216.34" in md


def test_save_reports_creates_files():
    report = _sample_report()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_reports(report, Path(tmpdir))
        assert paths["json"].exists()
        assert paths["markdown"].exists()


def test_json_report_is_valid():
    report = _sample_report()
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = save_reports(report, Path(tmpdir))
        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        assert data["target"] == "example.com"
        assert len(data["ports"]) == 3
