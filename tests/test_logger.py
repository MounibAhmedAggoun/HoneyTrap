from honeytrap.logger import setup_logging


def test_setup_logging(monkeypatch):
    captured = {}

    def fake_basic_config(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("logging.basicConfig", fake_basic_config)

    setup_logging("DEBUG")

    assert captured["level"] == "DEBUG"
    assert "asctime" in captured["format"]
    assert "levelname" in captured["format"]
    assert "name" in captured["format"]


def test_setup_logging_uppercases_level(monkeypatch):
    captured = {}

    def fake_basic_config(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr("logging.basicConfig", fake_basic_config)

    setup_logging("debug")

    assert captured["level"] == "DEBUG"