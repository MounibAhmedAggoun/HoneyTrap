from honeytrap.stats import ServerStats


def test_initial_stats():
    stats = ServerStats()

    assert stats.total_connections == 0
    assert stats.active_connections == 0
    assert stats.rejected_connections == 0


def test_connection_opened():
    stats = ServerStats()

    stats.connection_opened()

    assert stats.total_connections == 1
    assert stats.active_connections == 1


def test_connection_closed():
    stats = ServerStats()

    stats.connection_opened()
    stats.connection_closed()

    assert stats.total_connections == 1
    assert stats.active_connections == 0


def test_rejected_connection():
    stats = ServerStats()

    stats.connection_rejected()

    assert stats.rejected_connections == 1


def test_multiple_connections():
    stats = ServerStats()

    for _ in range(5):
        stats.connection_opened()

    stats.connection_closed()
    stats.connection_closed()

    assert stats.total_connections == 5
    assert stats.active_connections == 3


def test_active_connections_never_go_negative():
    stats = ServerStats()

    stats.connection_closed()
    stats.connection_closed()

    assert stats.active_connections == 0


def test_snapshot():
    stats = ServerStats()

    stats.connection_opened()
    stats.connection_opened()
    stats.connection_rejected()
    stats.connection_closed()

    assert stats.snapshot() == {
        "total_connections": 2,
        "active_connections": 1,
        "rejected_connections": 1,
    }


def test_snapshot_is_independent():
    stats = ServerStats()

    snapshot = stats.snapshot()
    snapshot["total_connections"] = 999

    assert stats.total_connections == 0