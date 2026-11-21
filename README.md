# HoneyTrap

**A defensive cybersecurity honeypot and network deception platform.**

HoneyTrap is a Python-based security project designed to observe interactions with controlled decoy services, record structured security events, and help analyze suspicious activity through evidence-based detection and investigation.

## Objectives

- Observe network connections to controlled decoy services.
- Track connections using unique session IDs.
- Record structured, timestamped events.
- Detect suspicious patterns using transparent rules.
- Generate investigation timelines and reports.
- Provide a controlled environment for security research and testing.

## Planned Features

- TCP connection monitoring
- Session tracking
- Structured event logging
- SQLite storage
- HTTP decoy
- SSH-themed interaction simulator
- Explainable detection engine
- Alert management
- Investigation timeline
- Replay Studio
- Analytics and reporting
- CLI and terminal dashboard

## Security

HoneyTrap is designed for controlled defensive research.

- Localhost-only during initial development.
- No real credential collection.
- No real command execution.
- No interaction with external systems.
- Resource limits and privacy-conscious logging.

## Technology

- Python
- Linux
- Git
- SQLite
- pytest
- Ruff

## Project Status

**Current stage: Pre-alpha — Foundation**

Currently establishing project specifications, architecture, and development foundations. The honeypot functionality has not yet been implemented.

## Disclaimer

HoneyTrap is intended for authorized defensive security research and controlled environments.
