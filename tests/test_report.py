from honeytrap.report import generate_report


def test_empty_report():
    report = generate_report([])

    assert report == {
        "total_events": 0,
        "connections_opened": 0,
        "connections_closed": 0,
        "unique_sessions": 0,
        "average_duration": 0.0,
        "total_duration": 0.0,
    }


def test_report_counts_events():
    events = [
        {"event_type": "connection_opened", "session_id": "1", "details": {}},
        {
            "event_type": "connection_closed",
            "session_id": "1",
            "details": {"duration": 5},
        },
        {"event_type": "connection_opened", "session_id": "2", "details": {}},
        {
            "event_type": "connection_closed",
            "session_id": "2",
            "details": {"duration": 10},
        },
    ]

    report = generate_report(events)

    assert report["total_events"] == 4
    assert report["connections_opened"] == 2
    assert report["connections_closed"] == 2
    assert report["unique_sessions"] == 2


def test_report_calculates_durations():
    events = [
        {
            "event_type": "connection_closed",
            "session_id": "1",
            "details": {"duration": 4},
        },
        {
            "event_type": "connection_closed",
            "session_id": "2",
            "details": {"duration": 8},
        },
    ]

    report = generate_report(events)

    assert report["average_duration"] == 6.0
    assert report["total_duration"] == 12.0


def test_report_ignores_missing_duration():
    events = [
        {"event_type": "connection_closed", "session_id": "1", "details": {}},
        {
            "event_type": "connection_closed",
            "session_id": "2",
            "details": {"duration": 6},
        },
    ]

    report = generate_report(events)

    assert report["average_duration"] == 6.0
    assert report["total_duration"] == 6.0