from dataclasses import dataclass


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 2222
    max_connections: int = 50
    timeout: float = 30.0

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("HoneyTrap v0.1 is restricted to localhost.")

        if not 1 <= self.port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        if self.max_connections < 1:
            raise ValueError("max_connections must be at least 1.")

        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0.")