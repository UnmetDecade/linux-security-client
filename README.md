# lsec · Unified Linux Security Client

**English** | [简体中文](README.zh-CN.md)

lsec is a local-first Linux host security client: a single-instance daemon that unifies ClamAV, YARA, Lynis, Falco, and optional integration with a local Wazuh Agent, exposed through a web UI and a CLI. Every status, scan result, and risk conclusion comes from real on-host probing and real task execution.

<p align="center">
  <img src="docs/images/dashboard.png" alt="lsec web security overview" width="900">
</p>

> The screenshot comes from a test deployment that intentionally runs a high-risk container to exercise the container risk checks, so the overall status honestly reads "at risk". lsec will never display an ability that is not installed, not enabled, or not verifiable as "protected".

## Key capabilities

- Single-instance daemon (file lock), SQLite + WAL, transactional migrations with pre-migration backups
- HTTP JSON API + native web UI (no frontend framework, no external CDN)
- CLI (`lsec`): status, components, scans, tasks, events, quarantine, audit, doctor, export
- Admin and read-only roles; web sessions use HttpOnly + SameSite=Strict cookies, write operations require a CSRF header
- Unified component probing: real install, running, and health state for ClamAV, Lynis, Falco, YARA, Wazuh, Docker, and systemd
- ClamAV: clamd probe/start/stop, signature database status, freshclam updates, quick/full/custom scans
- Scan tasks: queue, concurrency limits, real progress, cancellation, interrupted tasks marked failed after restart, evidence reports
- Unified event center: normalization of ClamAV/YARA/Falco/Wazuh/Lynis events, deterministic severity mapping, deduplication while retaining all source evidence, filtering, state transitions, JSON/CSV export
- Quarantine: explicit confirmation, hash verification, rejection of symlinks and out-of-bounds paths, two-step confirmation for restore/delete, full audit trail
- Host security audit (read-only): accounts/UIDs, empty passwords, duplicate UIDs, sensitive file permissions, SSH baseline, dangerous listening ports, legacy services, ASLR, AppArmor/SELinux
- Lynis integration: read-only audit, hardening index, warnings normalized into unified events, suggestions retained in the evidence report
- Container inventory: read through a separate read-only Docker API proxy; the web process does not mount the Docker socket by default
- Container risky-configuration checks: privileged mode, host network/PID/IPC, Docker socket mounts, sensitive directory mounts, overly broad capabilities, seccomp/AppArmor/SELinux, device passthrough; containers with missing detail fields show "could not be evaluated" rather than being treated as safe
- Falco integration: kernel/eBPF capability probing that distinguishes compatible, unsupported, insufficient permissions, and configuration-required states; read-only install plan and independent token-based event ingestion; an unverified process is never shown as "protected"
- YARA: rule pack install/verify/version activation/deletion, `yarac` compile validation, read-only enumeration and rule scans, hits written to the unified event center; rules are never downloaded automatically
- Wazuh (optional): read-only probing for a local Agent, Manager configuration, and registration info; optionally reads new lines from the local `alerts.json` and normalizes them. Explicitly not a Wazuh Manager: it never contacts the Manager or manages other Agents
- Update signature verification: after a `freshclam` update, the CVD digital signature is re-verified with `sigtool --info`; the result is written to the update response and audit log. Unverified is never displayed as verified
- Release engineering: deb package (hardened systemd unit, install/upgrade/uninstall scripts), source tarball, SHA256SUMS, and optional detached GPG signatures
- Containerd: detects the binary and socket only; explicitly provides no inventory and does not pretend to be a Docker inventory
- Structured logging, environment self-check (`lsec doctor`), operation audit
- Docker Compose deployment; binds to the host loopback by default; container monitoring uses a separate GET-only proxy override file

## UI preview

| YARA rule detection | Component status |
| --- | --- |
| <img src="docs/images/yara.png" alt="YARA rule detection page"> | <img src="docs/images/components.png" alt="Component management page"> |

## Explicitly unsupported

| Capability | Status | Notes |
| --- | --- | --- |
| Containerd container inventory | Not supported | Only the binary and socket are probed; inventory comes solely from the connected Docker runtime |
| Falco auto-install/start | Not supported | Only capability probing and a read-only install plan; does not install, load drivers, or start Falco |
| Wazuh Manager capabilities | Not supported | Only local Agent status and local alerts; no Manager API, cluster management, or other-Agent management |
| YARA rule auto-download | Not supported | Rule packs must be supplied by an administrator, signature-verified, and installed/activated manually |
| Automatic remediation | Not supported | Does not auto-delete, auto-quarantine, kill processes, or stop/restart/modify containers |
| ClamAV real-time protection | Not supported | fanotify/On-Access is not enabled in the container; the UI shows `unsupported` |

## Quick start (Docker)

```bash
# 1. Prepare a directory to scan (example)
mkdir -p scan-data

# 2. Build and start (the first run downloads ClamAV signatures and may take several minutes)
docker compose build
docker compose up -d
docker compose logs -f lsec

# 3. Read the auto-generated admin token (do not paste it into chats or tickets)
docker compose exec -T lsec cat /data/secrets/admin.token
```

Open `http://127.0.0.1:8080/` (binds to host loopback by default) and log in with the admin token.

### Enable container monitoring (optional)

The base deployment deliberately does **not** mount the Docker socket, and the containers page will honestly show "not enabled". To get container inventory and risky-configuration checks, start a read-only proxy with the override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d --build
```

This adds an `lsec-docker-proxy` service: it mounts `/var/run/docker.sock:ro` but only forwards `GET /version`, `GET /info`, `GET /containers/json`, and `GET /containers/<id>/json`; all write operations such as start/stop/remove are rejected. It runs on a private `internal: true` network. lsec itself still does not mount the Docker socket.

> The Docker socket is effectively host-level privilege. The proxy container will therefore be flagged as "critical" by the container checks (it mounts docker.sock) — that is a true risk finding, not a false positive. Treat the proxy as a trusted, high-privilege component and never expose it on a host port or another network.

For remote browsers, prefer an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<server>
# then open http://127.0.0.1:8080/ locally
```

If you must expose it directly on a trusted LAN, set explicitly:

```bash
LSEC_LISTEN_ADDR=0.0.0.0 LSEC_PORT=8080 docker compose up -d
```

> Without TLS, the token is sent over plain HTTP. For production, use a TLS reverse proxy or configure `server.tls_cert/tls_key` in `lsec.toml`.

## Scan the EICAR test file

EICAR is the industry-standard antivirus test sample and contains no malicious code.

```bash
./scripts/seed-eicar.sh ./scan-data
# Web: Antivirus → Quick scan
# or CLI:
docker compose exec -T lsec lsec scan quick --wait
docker compose exec -T lsec lsec events list
```

Expected result:

- Task status `completed`, detections 1, event severity `medium`
- Event source `clamav`, category `malware`, detection name as returned by ClamAV (1.4.x returns `Eicar-Signature`; older versions may return `Eicar-Test-Signature`)
- You can manually quarantine from the event or scan detail; quarantine, restore, and delete all require confirmation and are written to the audit log

You can also run the automated E2E script:

```bash
./scripts/e2e-eicar.sh
```

## CLI examples

Inside the container:

```bash
docker compose exec -T lsec lsec status
docker compose exec -T lsec lsec components list
docker compose exec -T lsec lsec doctor
docker compose exec -T lsec lsec scan quick --wait
docker compose exec -T lsec lsec task list
docker compose exec -T lsec lsec events list --severity medium
docker compose exec -T lsec lsec events export --format csv --output /data/events.csv
docker compose exec -T lsec lsec quarantine list
docker compose exec -T lsec lsec quarantine add --path /scan/eicar.txt --confirm
docker compose exec -T lsec lsec quarantine restore <item_id> --confirm
docker compose exec -T lsec lsec audit list              # operation audit log
docker compose exec -T lsec lsec audit run --wait        # run the read-only host audit
docker compose exec -T lsec lsec audit report            # latest audit report
docker compose exec -T lsec lsec audit history           # audit history
docker compose exec -T lsec lsec containers list         # container inventory and risk
docker compose exec -T lsec lsec containers inspect <id> # risk details for one container
docker compose exec -T lsec lsec containers refresh      # admin-triggered refresh (read-only)
docker compose exec -T lsec lsec falco status            # Falco capability and event ingestion
docker compose exec -T lsec lsec falco install-plan      # read-only install plan
docker compose exec -T lsec lsec yara status             # YARA and rule pack status
docker compose exec -T lsec lsec yara packs              # rule pack versions and activation state
docker compose exec -T lsec lsec scan path /scan/sample --engine clamav --engine yara --wait
docker compose exec -T lsec lsec wazuh status            # local Wazuh Agent status (optional)
docker compose exec -T lsec lsec wazuh install-plan      # read-only install plan
```

> `--engine` can be repeated; currently `clamav` and `yara` are supported. A task is marked failed only when both engines fail; a single-engine failure is marked partially completed with the error retained.

## Install the deb package (host deployment)

```bash
# Build release artifacts on a Debian/Ubuntu build host
scripts/build-release.sh

# Verify and install
sha256sum -c dist/SHA256SUMS
sudo apt install ./dist/lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo cat /var/lib/lsec/secrets/admin.token      # admin token; do not paste it into chats or tickets
```

It listens on `127.0.0.1:8080` by default and can be reached through an SSH tunnel. Upgrade, uninstall, rollback, and signature verification are covered in [Deployment and Operations](docs/DEPLOYMENT.md) and [Release Notes](docs/RELEASE.md).

Using the CLI directly on the host:

```bash
PYTHONPATH=src python3 -m lsec.cli --server http://127.0.0.1:8080 --token "$(cat token)" status
```

`lsec` reads the token from `--token`, `LSEC_TOKEN`, `--token-file`, `/data/secrets/admin.token`, and `~/.config/lsec/token`, in that order.

## Tests

```bash
./scripts/test.sh
```

Coverage includes:

- Strict config validation and environment variable overrides
- Path traversal, symlink, and out-of-bounds path rejection
- Event severity mapping, deduplication, and state machine
- Scan task state machine and restart recovery
- Authentication, roles, CSRF, Origin validation, and security headers against the real HTTP server
- Full scan → event → quarantine → restore → delete chain using a fake clamd UNIX socket (test double only)
- Settings validation, rejection of unsupported capabilities, doctor self-check
- Host checks: UID 0, empty passwords, duplicate UIDs, permissions, SSH, ports, ASLR, missing files and execution failures kept distinct on a fixed root filesystem
- Lynis report parsing (real 3.0.8 format), read-only invocation arguments, 0600 report/log permissions
- Audit API: admin initiates, read-only user gets 403, background completion, evidence written, host baseline status, and `audit.run` recorded
- YARA signing, hashing, compile validation, version management, and scan deduplication
- Wazuh alert file ingestion: offsets, rotation, truncation, and boundary handling

The current full suite reports `160 tests OK`; real Linux + ClamAV/YARA E2E validation is described in [Testing](docs/TESTING.md) and the [Security/Performance Test Report](docs/TEST-REPORT.md). The EICAR validation script is `scripts/e2e-eicar.sh`.

## Repository layout

```text
src/lsec/
  common/      config, errors, command execution, logging, path validation, host info
  storage/     SQLite migrations and repositories
  adapters/    adapter contracts, ClamAV, Lynis, Falco, YARA, Wazuh, probing component adapters
  core/        scanning, host checks and audit, container checks, unified events, YARA rule packs, Wazuh ingestion, quarantine, status, self-check, updates, maintenance
  api/         auth, HTTP routes, and web static assets
  web/         index.html / style.css / app.js
  daemon.py    daemon entry point
  cli/         lsec CLI
packaging/     Dockerfile, read-only Docker proxy, container config, entrypoint, debian/ packaging metadata
tests/         unit and integration tests
docs/          architecture, API, security, deployment, release, testing, and test report
scripts/       test, EICAR, E2E, release build/verification scripts
```

## Key design constraints

- No shell-string command execution; every subprocess uses an argv list
- Never fabricate scan results, component state, or protection status; "installed" does not mean "protecting"
- No automatic delete/quarantine; high-risk actions require explicit confirmation and are audited
- Tokens, sessions, and CSRF values are never written to logs
- Quarantine and restore verify hashes, reject symlinks, and stay within allowed directories
- Single-node deployment; no central management server

Further reading:

- [Architecture](docs/ARCHITECTURE.md)
- [HTTP API](docs/API.md)
- [Security model](docs/SECURITY.md)
- [Security policy and vulnerability reporting](SECURITY.md)
- [Deployment and operations](docs/DEPLOYMENT.md)
- [Release notes](docs/RELEASE.md)
- [Testing](docs/TESTING.md)
- [Security/Performance Test Report](docs/TEST-REPORT.md)

## Known limitations

- The container deployment does not provide ClamAV real-time protection; the overall status shows "protection incomplete"
- Processes inside the container run as root to read mounted scan directories; the Docker socket is not mounted
- Listens on host loopback by default; direct LAN access requires opting in explicitly and should be paired with TLS
- A full scan uses the container-visible filesystem as root and excludes host paths that are not mounted
- Restored quarantined files are written back as 0600 by container root; original permissions and ownership are not preserved
- Host audit scope is the container-visible filesystem, network namespace, and kernel parameters; unmounted host paths and the host network are out of scope
- The audit is read-only and never remediates findings; Lynis warning severity comes from fixed keyword mapping, not vulnerability scoring
- Container inventory only covers the Docker runtime the proxy is connected to; Containerd is probed but not inventoried
- Container configuration checks are heuristic rules, not equivalent to vulnerability/image scanning or runtime behavior detection; containers missing detail fields show "could not be evaluated"
- With container monitoring enabled, the proxy container is flagged critical for mounting the Docker socket; this is a true risk and should not be ignored
- Falco is not installed or started automatically; `compatible` only means the environment prerequisites are present, `running_verified` is always false and must be confirmed on the host side
- YARA rule scanning is rule matching, not full malware determination; rule quality and signature trust depend entirely on the rule packs supplied by the administrator
- Wazuh reads only the local Agent and local `alerts.json`; Manager connectivity cannot be verified from this client and the UI always shows "unverified"
- `sigtool` can only verify the CVD signature of `.cvd` files; `.cld` directory format has no CVD signature and shows "unverified/not applicable"
- The deb package starts the service by default but does not bundle ClamAV/YARA/Lynis binaries (Recommends); install them and wait for signature downloads before the first scan

## License

[MIT](LICENSE)
