# HoneyTrap — Project Specification

## 1. Overview

HoneyTrap is a defensive cybersecurity honeypot and network deception
platform designed to observe real interactions with controlled decoy services,
record structured security events, and support investigation through
evidence-based analysis.

## 2. Project Goals

- Observe real network connections to controlled decoy services.
- Maintain unique session identifiers.
- Record timestamped, structured events.
- Analyze observed behavior using transparent detection rules.
- Provide investigation timelines and reports.
- Support reproducible testing and isolated demonstrations.
- Minimize sensitive data collection.

## 3. Initial MVP — v0.1

- TCP connection listener.
- Localhost-only operation.
- Connection and disconnection tracking.
- Session identification.
- Real connection metadata collection.
- UTC timestamps.
- Structured event logging.
- Graceful shutdown.
- Connection limits and timeouts.
- Automated tests.

## 4. Planned Features

- SQLite persistence.
- CLI management interface.
- HTTP decoy service.
- SSH-themed interaction simulator.
- Event correlation.
- Explainable detection rules.
- Alert management.
- Investigation timelines.
- Analytics.
- Replay lab using explicitly labeled synthetic data.
- Report generation.
- Live terminal dashboard.
- Configurable retention and privacy controls.

## 5. Data Integrity Policy

HoneyTrap must distinguish between:

- Real observations: events actually observed by the running application.
- Synthetic data: generated data used for testing and replay.
- Derived findings: analytical conclusions calculated from recorded events.

Synthetic data must never be presented as real attacker activity.

Detection results must be based on actual evidence or explicitly identified test scenarios.

## 6. Security and Safety Boundaries

- Initial operation is restricted to localhost.
- No public deployment during the initial development stages.
- No real credential collection.
- No real shell or command execution.
- No retaliation or interaction with external systems.
- Strict connection, input, and resource limits.
- Sensitive information must not be unnecessarily recorded.
- Network exposure must never be enabled silently.

## 7. Technology Stack

- Language: Python
- Operating system: Linux
- Initial database: None
- Planned database: SQLite
- Version control: Git
- Testing: pytest
- Code quality: Ruff
- Interface: CLI initially

Dependencies will be introduced only when required.

## 8. Development Methodology

Every feature follows this lifecycle:

1. Understand the concept.
2. Define its requirements.
3. Implement it.
4. Test it.
5. Verify actual behavior.
6. Document it.
7. Commit the changes.

Untested functionality must not be described as verified.

## 9. v0.1 Acceptance Criteria

v0.1 is considered complete when:

- HoneyTrap starts successfully.
- A real localhost client can connect.
- The connection creates a valid session.
- Real connection metadata is recorded.
- Events have valid UTC timestamps.
- Disconnects are handled correctly.
- The application shuts down cleanly.
- Connection limits and timeouts work.
- Automated tests pass.
- Installation and execution are documented.

## 10. Project Status

Current version: Pre-alpha / development

Current milestone: Project foundation

No network monitoring or honeypot functionality has been implemented yet.