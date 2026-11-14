# Changelog

**English** | [简体中文](CHANGELOG.zh-CN.md)

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-14

### Added

- Single-instance daemon with SQLite + WAL storage and transactional schema
  migrations that take a pre-migration backup.
- HTTP JSON API, native web UI, and `lsec` CLI for status, components, scans,
  tasks, events, quarantine, audit, doctor, and export.
- Admin and read-only roles with HttpOnly, SameSite=Strict sessions and CSRF
  protection for write operations.
- Component probing for ClamAV, YARA, Lynis, Falco, Wazuh, Docker, Containerd,
  and systemd, with truthful installed/running/healthy states.
- ClamAV on-demand scanning, signature database status, freshclam updates, and
  post-update CVD signature verification.
- YARA rule packs with manifest hashing, OpenSSL signature verification,
  `yarac` compile validation, version activation, and rule-match events.
- Read-only host security audit covering accounts, SSH baseline, sensitive file
  permissions, listening ports, ASLR, and AppArmor/SELinux.
- Lynis integration with hardening index parsing and warnings normalized into
  the unified event center.
- Read-only container inventory and risky-configuration checks through a
  separate GET-only Docker API proxy.
- Optional local Wazuh Agent probing and `alerts.json` ingestion; explicitly not
  a Wazuh Manager.
- Unified event center with deterministic severity mapping, deduplication,
  filtering, state transitions, and JSON/CSV export.
- Quarantine with hash verification, symlink and path containment checks, and
  confirmation for restore and delete.
- Docker Compose deployment and a Debian package with source archive,
  `SHA256SUMS`, and optional detached GPG signatures.
- English and Chinese web UI with a language switch; English is the default.

### Security

- Binds to host loopback by default; remote access should use an SSH tunnel or
  an explicit TLS reverse proxy.
- The web process does not mount the Docker socket; container monitoring uses
  the separate read-only proxy.
- No automatic quarantine, deletion, process termination, or container
  stop/restart.

[Unreleased]: https://github.com/UnmetDecade/linux-security-client/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/UnmetDecade/linux-security-client/releases/tag/v0.4.0
