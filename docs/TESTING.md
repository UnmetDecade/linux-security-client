# Testing guide

**English** | [简体中文](TESTING.zh-CN.md)

## 1. Running

No third-party Python packages are required (standard library only):

```bash
./scripts/test.sh
# equivalent to
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

Requires Python 3.11+ (uses `tomllib` and `X | None` type syntax).

## 2. Coverage

### Unit tests

| File | Content |
| --- | --- |
| `tests/unit/test_config.py` | Secure default configuration, rejection of unknown keys/sections, type validation, TLS pairing, absolute paths, environment variable overrides, concurrency limits |
| `tests/unit/test_paths.py` | Rejection of relative paths/newlines/NUL/overlong paths, allowed-root containment checks, symlink and directory rejection |
| `tests/unit/test_events.py` | Severity mapping (EICAR=medium, trojan=critical, PUP=low), deduplication merging, counting, state transitions, retention policy |
| `tests/unit/test_scans.py` | Queue cancellation, cancellation while running, invalid transitions, unsupported types, interrupted tasks marked failed after restart |
| `tests/unit/test_hostchecks.py` | Fixed root filesystem: additional UID 0, empty passwords, duplicate UIDs, sensitive file permissions, SSH directives and Match exclusion, dangerous ports, ASLR, missing files as error/skipped rather than finding, shadow hashes never written to disk |
| `tests/unit/test_db_migration.py` | Schema v1 → v2 upgrade, `audit_runs` creation, existing data preserved, pre-migration backup exists |
| `tests/unit/test_lynis.py` | Real 3.0.8 report format parsing, no guessing for missing keys, warning severity, read-only argv, report/log 0600, behavior when disabled/missing binary |
| `tests/unit/test_containers.py` | Privileged/host namespaces, Docker Socket read-only still critical, longest-match sensitive paths, root read-only, capabilities/seccomp/AppArmor, no false positives for normal containers, missing fields as unknown, environment variables not retained, Docker API read-only and 403 distinction, URL/ID rejection, failures do not retain fabricated inventories |
| `tests/unit/test_falco.py` | Modern/old kernels, BTF, CAP_BPF+CAP_PERFMON, insufficient permissions, setup required, missing binary, install plan not installable from the UI, token 0600/stable/not created when disabled, event priority mapping, unknown priority, invalid payloads, invalid container IDs, stable deduplication keys |
| `tests/unit/test_docker_proxy.py` | Real HTTP proxy against a fake Unix Socket: GET allowlist, POST/PUT/PATCH/DELETE 405, unknown paths/extra query 403, short IDs/path traversal/non-hex rejection, health check upstream `/version` |
| `tests/unit/test_yara.py` | Rule pack manifest/SHA-256/signature (real OpenSSL), rejection of zip traversal/symlinks/undeclared files/hash mismatch/compile failure, same version not overwritable, activation/deletion and state corruption, output parsing and severity, argv budget batching, read-only scanning and symlink skipping |
| `tests/unit/test_wazuh.py` | Wazuh level/category mapping, event fields and evidence, deduplication, oversized payload rejection, starting at EOF on first run, offset resume, rotation/truncation reset, parse errors, oversized lines producing no fragment events, paused on state corruption, symlink alert file rejection, Agent probe degradation paths, key files never read, read-only install plan |
| `tests/unit/test_clamav_update.py` | `sigtool --info` CVD signature verification success/failure, sigtool missing and `.cld` explicitly "unverified/not applicable", update response includes the verification result |

### Integration tests

`tests/integration/test_api_workflow.py` starts a real daemon, a real `ThreadingHTTPServer`, and a temporary SQLite database, and uses a **test-only fake clamd UNIX Socket** (implementing `PING/VERSION/SCAN/SHUTDOWN` with NUL framing) to drive the full pipeline:

- Health check, static pages, security response headers, static asset path traversal rejection
- Unauthenticated access rejected; wrong token 401
- viewer read-only: reads succeed, creating a scan/reading logs 403
- Missing CSRF, cross-site Origin rejection
- Status truthfulness: on-demand scanning `ready`, real-time protection `unsupported`, overall not `healthy`
- EICAR scan: task succeeds, 2 files, 1 detection, evidence report written, event fields correct
- Repeated scan: events deduplicated, `occurrences` accumulated
- Quarantine: missing confirmation rejected; file disappears after quarantine; hash length; refuses to overwrite when the original path is occupied; restored content matches; quarantine again and permanently delete; audit includes create/restore/delete
- Quarantine security: symlink rejection, out-of-root path rejection
- Event status transitions and invalid transitions; CSV/JSON export
- Settings: `auto` returns 501, scheduled scan merging, viewer modification 403
- doctor self-check includes database and virus database checks
- Invalid scan requests: `paths` not an array, unsupported type, out-of-bounds custom path
- Host security audit: viewer initiation 403; admin creation 202; background completion; check states valid; `errors_count` consistent with error checks; evidence report exists; history and details readable; the status page `host_baseline` correlates with the latest audit; operation audit includes `audit.run`
- Container inventory: a fake Docker API injects privileged + host network + docker.sock containers; viewer can read the inventory and details but cannot refresh (403); admin refresh succeeds and writes `container.refresh`; all Docker requests are GET; 3 configuration risk events correctly correlate with containers; no stop/restart endpoints exist (404)
- Falco ingestion: the separate token writes successfully (202), repeated events merge; administrator token calling the ingestion endpoint 401; the Falco token cannot read `/status` (401); `/falco` shows event counts

`tests/integration/test_yara_api.py` uses the real API/storage/scan queue with fake `yara`/`yarac`:

- viewer can read rule status/versions; install/activate/delete return 403
- Install missing `confirm` returns 400; a valid install returns 201 and writes the `yara.pack.install` audit
- Multiple versions coexist, activation switches, deleting a specified version
- Invalid packs (hash mismatch/traversal/compile failure) are rejected and leave no version
- YARA scanning produces `source=yara` events; repeated scans deduplicate; nothing is written to quarantine
- Scanning returns `component_unavailable` when no rule pack is active

`tests/integration/test_wazuh_api.py` uses a fake `wazuh-control`, a local `alerts.json`, and real event storage:

- viewer can read `/wazuh` and sees `scope=local_agent_only`, `connection_verified=false`
- In capabilities, the Wazuh state is at most `degraded`; the Manager address is visible; registration key contents appear in no response
- The install plan is read-only (`installable_from_ui=false`)
- New alert lines generate unified events; duplicate alerts merge `occurrences`; no automatic quarantine records

### Truthfulness notes

The fake clamd in tests is used only to verify protocol adaptation and business pipelines on development machines without ClamAV installed. It lives under `tests/`, never enters the image, and never returns results in production. Real scan results must come from clamd.

## 3. Test results

| Environment | Command | Result |
| --- | --- | --- |
| macOS (Darwin 27.0.0, Python 3.15.2) | `./scripts/test.sh` | `Ran 160 tests ... OK` |
| Ubuntu 24.04 test environment (Python 3.12.3) | `PYTHONPATH=src python3 -m unittest discover -s tests -t .` | `Ran 160 tests ... OK` |

## 4. Real Linux + ClamAV E2E

Actually ran `./scripts/e2e-eicar.sh` in the Ubuntu 24.04 test environment (2026-11-10):

- ClamAV 1.4.6, virus database daily 28179 / main 63, `service_status=running`, `health_status=ok`
- Before the fix, a real protocol problem was found: the client sent `zSCAN path\n`, which clamd rejected with `COMMAND READ TIMED OUT`; after switching to the documented `zSCAN path\0` NUL framing it passed
- After the fix, the quick scan: task `completed`, 1 file scanned, 1 detection, 0 errors
- Event: `source=clamav`, `category=malware`, `severity=medium`, detection name `Eicar-Signature` (the actual return value of ClamAV 1.4.6)
- Quarantine → restore (content/hash match) → quarantine again → permanent delete all succeeded
- Audit records include `quarantine.create`, `quarantine.restore`, `quarantine.delete`, actor `admin`
- `lsec components stop clamav` / `start clamav` and `lsec components update clamav` all returned real states
- Real viewer token: `GET /status` 200, creating a scan 403 `forbidden`

Manual verification:

```bash
docker compose exec -T lsec lsec status
docker compose exec -T lsec lsec scan quick --wait
docker compose exec -T lsec lsec events list
docker compose exec -T lsec lsec quarantine list
```

### Host security audit E2E

Executed on the real image (Lynis 3.0.8) in the Ubuntu 24.04 test environment:

```bash
docker exec lsec lsec audit run --wait
docker exec lsec lsec audit report
docker exec lsec lsec audit history
```

Results:

- Audit `succeeded`, scope `container`, took about 7 seconds
- 10 checks: 6 passed, 1 finding, 0 not executed, 3 skipped
- SSH, systemd, and AppArmor/SELinux are explicitly `skipped` because they are not visible inside the container, not `pass`
- Finding `LOGG-2138` (klogd not running), level `medium`, generated 1 unified event; the 39 Lynis suggestions are kept only in the evidence report
- Hardening index 56, raw report and log 0600, output directory 0700
- On a repeated audit the same `LOGG-2138` finding merged by deduplication key with no repeated noise
- `lsec audit list` includes `audit.run` and `audit.complete`, actor `admin`
- viewer can read history/details but starting an audit is 403

### Container monitoring E2E

Executed after starting the real proxy with `docker-compose.container.yml` in the Ubuntu 24.04 test environment (2026-11-10):

```bash
cd /opt/lsec
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d --build
docker exec lsec lsec containers list
docker exec lsec lsec containers inspect lsec-docker-proxy
docker exec lsec lsec falco status
docker exec lsec lsec doctor
```

Results:

- Both `lsec:0.4.0` and `lsec-docker-proxy:0.4.0` built successfully; the proxy is `healthy`
- The proxy mounts only `/var/run/docker.sock:ro`, with `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `Privileged=false`, is on `lsec_lsec-internal` only, and has no host ports
- The lsec container mounts only `/data`, `/var/lib/clamav`, and `/scan`; `/var/run/docker.sock` does not exist inside the container (`NO_DOCKER_SOCKET_IN_LSEC`)
- Real inventory: 4 test containers (including lsec, the read-only proxy, and the monitoring component); 3 running, 1 stopped, 3 risky, 0 not evaluable
- Risks: the scan directory bind mount is high; the proxy is critical because of the Docker Socket; the privileged monitoring container is critical because of host PID, the Docker Socket, and `/proc`/`/sys` mounts, and produces multiple findings
- Unified events: 11 running-container findings, source `docker`, category `configuration`; after restart, repeated risks merged by deduplication key (`occurrences=2`) with no duplicate event flood
- Manual refresh `POST /containers/refresh` returned 200, and the audit shows `container.refresh` (admin, success)
- Real Falco event ingestion: the separate token returned `202 created=true`; resubmitting the same event returned `202 created=false`; the target is `container_id` + name, and priority Warning→medium
- Token isolation: administrator token calling the ingestion endpoint 401; the Falco token reading `/status` and `/containers` both 401; viewer reading containers 200, refresh 403
- No container mutation capability: `POST /containers/<id>/stop|restart` and `DELETE /containers/<id>` all 404; the proxy returns 405 for `POST /containers/<id>/stop`
- Real Falco state: not installed; host kernel 6.8.0-142, BTF present, but the lsec process has `CAP_SYS_ADMIN=false`, `CAP_BPF/PERFMON=false`, capability state `requires_privileges`, health `unavailable`; not disguised as enabled
- Containerd: not installed, component state `not_installed/unavailable`, and explicitly "no inventory collection"
- `lsec doctor`: 7 passed, 1 warning (binding 0.0.0.0 without TLS), 0 failed, 2 info; container monitoring and Falco state are included in the self-check
- Schema is v2; no database migrations were added this time

### YARA and unified event center E2E

Executed on `lsec:0.4.0` (YARA 4.2.3, OpenSSL 3.0.22) in the Ubuntu 24.04 test environment:

- Generated a signed rule pack with a temporary key pair and installed it: `e2e-test@1.0.0`, `signature_verified=true`, activated successfully
- All invalid packs rejected: unsigned, bad signature, rule hash mismatch, and `yarac` compile failure all returned 400 and left no version/staging directory
- Single-file hit: task `succeeded`, 1 file, 1 detection, 0 errors; event `source=yara`, `category=malware`, `severity=high`
- Event evidence includes the file SHA-256, `rule_id`, rule pack ID/version, rule name, tags, file size, and task ID
- After 3 repeated scans there is still 1 event, `occurrences=3`, and `source_refs` retains 3 different scan tasks
- No automatic quarantine; the event description explicitly states "a rule hit is not equivalent to confirmed malware"
- 1000-file YARA scan: `succeeded`, 1000 files, 0 detections, 0 errors, about 2.229 seconds
- 1000-file ClamAV scan: `succeeded`, 1000 files, 0 detections, 0 errors, about 4.227 seconds
- Rule pack install/activate/delete audit and viewer read-only all passed
- Web UI: the rule pack shows `Verified`, `Scan ready`; viewer shows a read-only indicator

Testing found and fixed two real defects:

1. When invoking `yara` on `yarac` compile output, `-C` must be added; otherwise it is parsed as a text rule and reports a non-ascii syntax error.
2. `yara` accepts only one target argument; batch files must be passed through a temporary list and `--scan-list`, otherwise a 1000-file scan becomes `partial` with 5 errors.

### Wazuh optional integration and release E2E

The main deployment did not install the Wazuh Agent, and the real state is:

- `installed=false`, `health_status=unavailable`, `error_code=disabled`
- `scope=local_agent_only`, `connection_verified=false`
- Manager not configured, address empty
- Event ingestion not enabled; the UI shows `Not enabled`, `Unverified`, and the note "lsec is not a Wazuh Manager"

Verified with a separate temporary daemon at `/tmp/lsec-wazuh-test` and a real local `alerts.json`:

- Starts at EOF on first run and does not backfill historical alerts
- A level 10 alert generates an event with `source=wazuh`, `severity=high`, `category=auth`, and target IP `203.0.113.7`
- Duplicate alerts merge `occurrences=2`; after restart the ingestion counter resets to zero, but the persisted offset prevents duplicate collection
- After log rotation with `max_bytes=8192/backups=3`, the active file is 2756 bytes, and `.1/.2/.3` are 8056 bytes each

The deb lifecycle was verified in a disposable Debian 12 container (no systemd):

- When `python3` is missing, installation fails and remains unconfigured, with no user/data directory created; after installing the dependency, configuration succeeds
- 0.4.0 → 0.4.1 upgrade preserves local changes to `/etc/lsec/lsec.toml` and the `/var/lib/lsec` data marker
- After `--force-downgrade` back to 0.4.0, configuration and data are still preserved
- `dpkg -r` preserves data and logs and prints the retained paths; `dpkg -P` cleans up data, logs, configuration, and the system user
- No GPG private key was available this time, so the release artifacts were unsigned, and `BUILD-MANIFEST.txt` records `signed=no`

See `docs/TEST-REPORT.md` for details.

### Web UI smoke test

Used Playwright + local Chrome to access the real deployment through an SSH tunnel, covering:

- Administrator token login, session Cookie remains valid after refresh, logout
- All 10 navigation pages render, and unsupported capabilities show clear explanations
- Container page: really displays 4 containers, 3 risky containers, 11 findings, Docker 29.0.2/API 1.52, the monitoring API, Falco capability state, and event ingestion; administrators can refresh, viewer has no refresh button
- The container details modal shows risks, mounts, ports, and the "no start/stop operations provided" note; the Falco install plan modal explicitly says "cannot be installed from the UI"
- Created a quick scan through the UI, waited for the real task to complete, and the task list showed the new task and detection count
- Quarantined from the event page, restored in quarantine, quarantined again, and permanently deleted; all went through confirmation dialogs and showed success prompts
- Marked two EICAR test events as "resolved" with notes; the list status updated in real time, and the audit shows `event.status`
- The host security audit page shows the real hardening index, risk findings, system information, audit history, and Lynis suggestions; after an administrator runs an audit, it auto-refreshes to the completed state
- viewer sees no run button on the host security audit page and shows a read-only hint
- YARA page: really displays the installed rule pack `e2e-test`, `Verified`, `Scan ready`; viewer shows a read-only indicator
- Host page: the Wazuh card shows `Not enabled`, `Unverified`, and the `local_agent_only` scope note, and does not describe local alert ingestion as Manager capability
- Event center: filtering, details, and export work on real data
- No console errors, page errors, or failed requests on the pages (the 404 disappeared after adding a favicon)
- Real viewer login is read-only, and write endpoints return 403

## 5. Protocol and test doubles

The fake clamd in integration tests reads commands strictly according to the NUL framing protocol and returns NUL-terminated responses. If the client regresses to newline framing, the test blocks/fails, preventing a recurrence of "the test double is too lenient and hides real clamd incompatibility".

The Lynis unit tests use a temporary script that writes only a fixed `lynis-report.dat`, solely to verify argv, report reading, and parsing; the parsing sample comes from a real Lynis 3.0.8 report (`hardening_index=56`, `lynis_tests_done=230`, `warning[]=LOGG-2138|...|-|-|`). The production image installs real Lynis and does not use this script.

## 6. Security test checklist

| Item | Coverage method |
| --- | --- |
| Ordinary user calling privileged endpoints | Integration tests: viewer POST/DELETE/log 403 |
| CSRF / cross-site Origin | Integration tests: missing CSRF, malicious Origin 403 |
| Path traversal / out-of-bounds | Unit + integration tests |
| Symlinks | Unit + integration tests |
| Quarantine directory permissions | Forced 0700; doctor checks data directory and token permissions |
| Token permissions | 0600; doctor checks overly broad permissions |
| Command injection | Global argv execution, no shell; clamd commands reject control characters |
| Malformed requests | Non-JSON, non-object, wrong types, oversized request bodies |
| Queue/state conflicts | State machine unit tests; scan queue limits |
| Update failure | Keeps the old virus database, returns the real exit code and output tail |
| Docker Socket misuse | Integration tests confirm all Docker APIs are GET; proxy tests confirm write methods 405; the product has no container mutation interface |
| Container sensitive information | Unit tests confirm environment variables never appear in check results; event evidence size is bounded |
| Falco token privilege escalation | Integration tests: administrator token cannot write to the ingestion endpoint, Falco token cannot read other APIs |
| Container ID/path injection | Unit tests reject short IDs, non-hex, path traversal; the proxy validates again |
| Permission failure false positives | Container monitoring separates `permission_denied` and `unavailable`; Docker 403 tests; failures return no fabricated inventory |

## 7. Performance and long-run boundaries

One-off benchmarks have been run on the test host (see `docs/TEST-REPORT.md` for details):

- 5000 unique events written in 2.459 seconds (2032.9 events/second), list 13.59 ms, export 70.81 ms
- 200 synthetic container inventory refresh in 0.576 seconds (about 2.9 ms/container)
- Idle container CPU 0.07%–0.11%, memory 981.1–981.3 MiB; 12 samples over about 5 minutes 41 seconds were stable

Not yet automated or not executed:

- Multi-day/multi-week endurance, memory leak, and long-term disk growth tests
- High-concurrency event writes and sustained Falco event floods
- Jitter of a real Docker daemon at the scale of hundreds of containers
- Continuous regression of the browser-side UI (a one-off Playwright smoke test was run, but the script is not in the repository/CI)
- TLS mutual configuration and reverse proxy integration tests
- Real containerd API integration (currently probe-only)
- Real Wazuh Manager/Agent registration, Manager API, and TLS connection (the product does not provide Manager capability)
- Long-term operation of the deb package on a real systemd host, automatic restart, and apt interaction (install/upgrade/downgrade/uninstall scripts and payload have been verified in a Debian container)
- GPG-signed release (no private key was available on the build host, so this release's artifacts are unsigned)

## 8. Test data and cleanup

- Unit/integration tests use `tempfile` and delete automatically on completion
- The E2E script writes an EICAR file into the container's `/scan` for verification; it was deleted after this acceptance run, and both `/scan` and the host `scan-data/` are empty
- The two EICAR events produced by testing were marked "resolved" through the UI and retained in the audit records; history was not deleted
- The `LOGG-2138` event really produced by the host security audit remains in the "new event" state for the user to confirm; audit evidence is kept in `/data/evidence/audits/`
- YARA tests use a temporary key and a test rule pack; the test private key is in a temporary directory and was deleted after acceptance; invalid rule packs never become installed versions
- Wazuh tests use a separate daemon at `/tmp/lsec-wazuh-test` and a temporary data directory, stopped and deleted after acceptance without affecting the main deployment
- Tests do not scan, modify, or fix paths outside the test directories
