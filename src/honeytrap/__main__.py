import argparse
import logging

from honeytrap.config import ServerConfig
from honeytrap.server import TCPServer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HoneyTrap local honeypot")

    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--max-connections", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=30.0)

    return parser.parse_args()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    args = parse_args()

    config = ServerConfig(
        port=args.port,
        max_connections=args.max_connections,
        timeout=args.timeout,
    )

    server = TCPServer(config=config)

    print("=" * 40)
    print("           HoneyTrap v0.1")
    print("      Local Defensive Honeypot")
    print("=" * 40)
    print(f"Listening on {server.host}:{server.port}")
    print(f"Max connections: {server.max_connections}")
    print(f"Timeout: {server.timeout}s")
    print("Press CTRL+C to stop.")
    print()

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down HoneyTrap...")
        server.stop()


if __name__ == "__main__":
    main()