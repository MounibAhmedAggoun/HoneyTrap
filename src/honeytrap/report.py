from collections import Counter


def generate_report(events: list[dict]) -> dict:
    event_counts = Counter(event["event_type"] for event in events)

    opened = event_counts.get("connection_opened", 0)
    closed = event_counts.get("connection_closed", 0)

    durations = [
        event["details"]["duration"]
        for event in events
        if event["event_type"] == "connection_closed"
        and isinstance(event.get("details", {}).get("duration"), (int, float))
    ]

    sessions = {
        event["session_id"]
        for event in events
        if event.get("session_id")
    }

    return {
        "total_events": len(events),
        "connections_opened": opened,
        "connections_closed": closed,
        "unique_sessions": len(sessions),
        "average_duration": round(sum(durations) / len(durations), 2)
        if durations
        else 0.0,
        "total_duration": round(sum(durations), 2),
    }