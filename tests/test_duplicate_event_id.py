from honeytrap.rules.duplicate_event_id import DuplicateEventIDRule


def test_unique_event_ids_produce_no_findings():
    events = [
        {"event_id": "e1"},
        {"event_id": "e2"},
        {"event_id": "e3"},
    ]

    assert DuplicateEventIDRule().evaluate(events) == []


def test_detects_duplicate_event_id():
    events = [
        {"event_id": "e1"},
        {"event_id": "e1"},
    ]

    findings = DuplicateEventIDRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-006"


def test_detects_multiple_duplicate_ids():
    events = [
        {"event_id": "e2"},
        {"event_id": "e2"},
        {"event_id": "e1"},
        {"event_id": "e1"},
    ]

    findings = DuplicateEventIDRule().evaluate(events)

    assert len(findings) == 2


def test_ignores_missing_event_ids():
    events = [
        {},
        {"event_id": None},
        {"event_id": ""},
    ]

    assert DuplicateEventIDRule().evaluate(events) == []


def test_mixed_unique_and_duplicate_ids():
    events = [
        {"event_id": "e1"},
        {"event_id": "e2"},
        {"event_id": "e2"},
        {"event_id": "e3"},
    ]

    findings = DuplicateEventIDRule().evaluate(events)

    assert len(findings) == 1