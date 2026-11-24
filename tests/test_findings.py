from datetime import UTC

from honeytrap.findings import Finding, Severity


def test_finding_creation():
    finding = Finding(
        rule_id="TEST-001",
        severity=Severity.MEDIUM,
        message="Test finding",
        session_id="session-123",
    )

    assert finding.rule_id == "TEST-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.message == "Test finding"
    assert finding.session_id == "session-123"


def test_finding_id_is_unique():
    first = Finding("TEST-001", Severity.INFO, "First")
    second = Finding("TEST-001", Severity.INFO, "Second")

    assert first.finding_id != second.finding_id


def test_finding_timestamp_is_utc():
    finding = Finding("TEST-001", Severity.INFO, "Test")

    assert finding.timestamp.tzinfo == UTC


def test_finding_to_dict():
    finding = Finding(
        rule_id="TEST-002",
        severity=Severity.HIGH,
        message="Example alert",
        session_id="session-456",
    )

    result = finding.to_dict()

    assert result["rule_id"] == "TEST-002"
    assert result["severity"] == "high"
    assert result["message"] == "Example alert"
    assert result["session_id"] == "session-456"
    assert "finding_id" in result
    assert "timestamp" in result


def test_all_severity_levels():
    assert Severity.INFO.value == "info"
    assert Severity.LOW.value == "low"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"


def test_finding_session_is_optional():
    finding = Finding(
        rule_id="TEST-003",
        severity=Severity.LOW,
        message="General observation",
    )

    assert finding.session_id is None