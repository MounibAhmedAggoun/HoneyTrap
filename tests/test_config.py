import pytest

from honeytrap.config import ServerConfig


def test_default_config():
    config = ServerConfig()

    assert config.host == "127.0.0.1"
    assert config.port == 2222
    assert config.max_connections == 50
    assert config.timeout == 30.0


def test_custom_config():
    config = ServerConfig(port=8080, max_connections=10, timeout=5.0)

    assert config.port == 8080
    assert config.max_connections == 10
    assert config.timeout == 5.0


def test_non_localhost_rejected():
    with pytest.raises(ValueError):
        ServerConfig(host="0.0.0.0")


def test_invalid_port_rejected():
    with pytest.raises(ValueError):
        ServerConfig(port=70000)


def test_zero_connections_rejected():
    with pytest.raises(ValueError):
        ServerConfig(max_connections=0)


def test_invalid_timeout_rejected():
    with pytest.raises(ValueError):
        ServerConfig(timeout=0)


def test_config_is_immutable():
    config = ServerConfig()

    with pytest.raises(AttributeError):
        config.port = 8080