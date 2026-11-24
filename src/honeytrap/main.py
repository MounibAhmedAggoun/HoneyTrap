import logging

from honeytrap.server import TCPServer


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    server = TCPServer()

    print("=" * 40)
    print("           HoneyTrap v0.1")
    print("      Local Defensive Honeypot")
    print("=" * 40)
    print(f"Listening on {server.host}:{server.port}")
    print("Press CTRL+C to stop.")
    print()

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down HoneyTrap...")
        server.stop()


if __name__ == "__main__":
    main()