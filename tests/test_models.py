from datetime import datetime, timezone
from recon.models import PortResult, PortState, ScanReport, DnsRecord, DnsResult, WhoisResult


def test_open_ports_filter():
    report = ScanReport(
        target="example.com",
        scan_time=datetime.now(timezone.utc),
        ports=[
            PortResult(port=80, state=PortState.OPEN, service="http"),
            PortResult(port=443, state=PortState.OPEN, service="https"),
            PortResult(port=22, state=PortState.CLOSED, service="ssh"),
            PortResult(port=8080, state=PortState.FILTERED, service="http-alt"),
        ],
    )
    assert len(report.open_ports) == 2
    assert all(p.state == PortState.OPEN for p in report.open_ports)


def test_empty_report_has_no_open_ports():
    report = ScanReport(target="example.com", scan_time=datetime.now(timezone.utc))
    assert report.open_ports == []


def test_dns_result_stores_records():
    result = DnsResult(
        target="example.com",
        records=[
            DnsRecord(record_type="A", value="93.184.216.34"),
            DnsRecord(record_type="MX", value="0 ."),
        ],
    )
    assert len(result.records) == 2
    assert result.records[0].record_type == "A"


def test_whois_result_defaults():
    w = WhoisResult(domain="example.com")
    assert w.registrar == ""
    assert w.name_servers == []
    assert w.error == ""


def test_whois_error_stored():
    w = WhoisResult(domain="example.com", error="timeout")
    assert w.error == "timeout"
