from honeytrap.__main__ import parse_args


def test_default_arguments(monkeypatch):
    monkeypatch.setattr("sys.argv", ["honeytrap"])

    args = parse_args()

    assert args.port == 2222
    assert args.max_connections == 50
    assert args.timeout == 30.0


def test_custom_arguments(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "honeytrap",
            "--port",
            "3333",
            "--max-connections",
            "20",
            "--timeout",
            "10",
        ],
    )

    args = parse_args()

    assert args.port == 3333
    assert args.max_connections == 20
    assert args.timeout == 10.0


def test_partial_custom_arguments(monkeypatch):
    monkeypatch.setattr("sys.argv", ["honeytrap", "--port", "4444"])

    args = parse_args()

    assert args.port == 4444
    assert args.max_connections == 50
    assert args.timeout == 30.0