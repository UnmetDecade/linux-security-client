# Security and performance test report

**English** | [简体中文](TEST-REPORT.zh-CN.md)

Version: 0.4.0  
Test date: 2026-11-10  
Test host: Ubuntu 24.04.3 LTS test environment

This report records the acceptance tests for YARA and the unified event center, optional Wazuh integration, and release hardening, and summarizes the real-environment results of earlier capabilities. The report states only tests that were actually executed; tests that were not executed are explicitly listed under "Scope and limitations" and are not treated as passed items.

## 1. Summary of conclusions

- Unit/integration tests: `Ran 160 tests ... OK` on both the local machine and the test host.
- Real YARA: signed rule pack installation, activation, compile validation, batch scanning, and event deduplication all passed; all four types of invalid packs—unsigned, bad signature, hash mismatch, and rule compile failure—were rejected.
- Real ClamAV: 1000-file scan `succeeded`, 1000 files, 0 detections, 0 errors, taking about 4.227 seconds.
- Real YARA: 1000-file scan `succeeded`, 1000 files, 0 detections, 0 errors, taking about 2.229 seconds; a single-file hit produced 1 high-severity event, and repeated scans merged into `occurrences=3` while retaining 3 `source_refs`.
- Wazuh: the main deployment did not install the Agent, and the state truthfully shows `disabled`, `connection_verified=false`, and explicitly "lsec is not a Wazuh Manager". A temporary local Agent alert file verified ingestion, deduplication, restart offsets, and log rotation; no Manager capability is claimed.
- Performance: 5000 unique events written in 2.459 seconds (about 2033 events/second), list query 13.59 ms, export of 5000 events 70.81 ms; 200 synthetic container inventory refresh in 0.576 seconds (about 2.9 ms/container).
- Stability: the main container was sampled 12 times consecutively (about 5 minutes 41 seconds), with CPU 0.07%–0.11% and memory steady at 981.1–981.3 MiB. This result does not constitute proof of multi-day long-term stability.
- Release package: deb install → 0.4.1 upgrade → 0.4.0 downgrade → remove → purge all passed; upgrade and downgrade both preserved configuration and data, remove preserved data, and purge cleaned up data, configuration, and the system user.
- Release signature: the build host had no usable GPG private key, so the artifacts are an **unsigned build**, and `BUILD-MANIFEST.txt` records `signed=no`; no signed release is claimed.

## 2. Test environment

### 2.1 Host machine

| Item | Value |
| --- | --- |
| Operating system | Ubuntu 24.04.3 LTS |
| Kernel | 6.8.0-142-generic |
| CPU | AMD Ryzen 9 9950X3D 16-Core / 32 threads |
| Memory | 123 GiB |
| Docker | 29.0.2 |
| Compose | v2.40.3 |
| Host Python | 3.12.3 |
| dpkg | 1.22.6 |

### 2.2 Deployment environment

| Item | Value |
| --- | --- |
| Image | `lsec:0.4.0` |
| Container system | Debian GNU/Linux 12 (bookworm), Python 3.12.16 |
| ClamAV | 1.4.6, virus database daily 28179 / main 63 |
| Lynis | 3.0.8 |
| YARA / yarac | 4.2.3 |
| OpenSSL | 3.0.22 |
| Database | SQLite, schema v2, WAL |
| Access method | Host `127.0.0.1:8080`, tests through SSH tunnel `127.0.0.1:18080` |

## 3. Automated tests

```bash
./scripts/test.sh
# equivalent to
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

| Environment | Result |
| --- | --- |
| macOS (Darwin 27.0.0, Python 3.15.2) | `Ran 160 tests ... OK` |
| Clean copy of the Ubuntu 24.04 test environment (Python 3.12.3) | `Ran 160 tests ... OK` |

The full test suite on the test host was run from a temporary clean copy to avoid a legacy `lsec/` directory in the deployment directory shadowing `src/lsec`. That legacy directory was not deleted because it is outside this project's test cleanup scope.

Coverage highlights:

- Configuration validation, path traversal, symlinks, allowlist roots.
- Event severity mapping, deduplication, state transitions, retention policy.
- Scan queue, cancellation, interrupted tasks marked failed after restart.
- Host security audit's distinction between "could not execute" and "real finding".
- Container read-only API, sensitive paths, privileged/host namespaces, no start/stop capability.
- Falco token isolation, event mapping, and deduplication.
- YARA manifest, SHA-256, OpenSSL signature, zip traversal, compile validation, version management, scan batching, and output parsing.
- Wazuh level/category mapping, offset resume, rotation/truncation, oversized lines, symlink alert files, Agent probe degradation.
- ClamAV CVD signature verification and the explicit state on verification failure.

## 4. YARA and unified event center

### 4.1 Rule packs and signatures

A temporary OpenSSL key pair was used to construct signed rule packs, submitted one by one:

| Case | Expected | Actual |
| --- | --- | --- |
| Valid zip (manifest + manifest.sig + rule hashes match + `yarac` compile passes) | Install and activate | 201, `signature_verified=true`, `pack_id=e2e-test`, `version=1.0.0` |
| Unsigned pack (missing `manifest.sig`) | Reject | 400, does not appear in the version list |
| Bad signature (content tampered with or wrong private key) | Reject | 400, `openssl` reports bad signature |
| Rule file SHA-256 does not match the manifest | Reject | 400, no staging version left behind |
| Rule syntax error causing `yarac` compile failure | Reject | 400, no staging version left behind |

Installation, activation, and deletion are all written to the audit log (`yara.pack.install`, `yara.pack.activate`, `yara.pack.delete`). viewer reads rule status successfully, and write operations return 403.

### 4.2 Single-file scan and events

The activated `e2e-test@1.0.0` was used to scan a file containing marker content:

- Task state `succeeded`, 1 file scanned, 1 detection, 0 errors.
- Event: `source=yara`, `category=malware`, `severity=high`.
- Evidence includes the file SHA-256, `rule_id=e2e-test:LsecE2EMarker`, rule pack version, rule name, tags, file size, and task ID.
- The description explicitly states "a rule hit is not equivalent to confirmed malware" and explains that no automatic quarantine or deletion occurred.
- After 3 consecutive scans there is still only 1 event, `occurrences=3`, and `source_refs` retains the original evidence of 3 different `task_id`s.
- The quarantine area is empty, confirming no automatic quarantine.

### 4.3 Batch scanning

Scanned 1000 files inside the real container:

| Engine | State | Files | Detections | Errors | Duration |
| --- | --- | --- | --- | --- | --- |
| YARA 4.2.3 | `succeeded` | 1000 | 0 | 0 | about 2.229 seconds |
| ClamAV 1.4.6 | `succeeded` | 1000 | 0 | 0 | about 4.227 seconds |

Two real defects were found and fixed during testing:

1. `yara` by default parses `yarac` compile output as source and reports `syntax error / non-ascii character`; fixed by using `-C` for compiled rules.
2. When multiple file arguments were passed to `yara` at once, it treated all but the last as rule files, and the 1000-file scan returned `partial` with 5 errors; fixed by writing batches to a temporary list and using `--scan-list`, with the list file deleted in `finally`.

After the fix, `lsec:0.4.0` was rebuilt and retested, and the 1000-file scans above had no errors.

### 4.4 Event center

- The event list, severity/source/status filters, keyword search, details, and CSV/JSON export were verified through the real API; the event page list, status transitions, and details were additionally verified with Playwright.
- Deduplication keys are stable; repeated events accumulate `occurrences` and retain evidence from different source tasks.
- State transitions allow only legal paths; every response action is written to the audit log.
- viewer can read; write operations return 403.
- The YARA page was verified with Playwright: it shows `e2e-test`, `Verified`, `Scan ready`, and viewer shows a read-only indicator.

## 5. Optional Wazuh integration

### 5.1 Real state of the main deployment

The main deployment did not install the Wazuh Agent. `GET /api/v1/wazuh` returns:

- Component `installed=false`, `health_status=unavailable`, `error_code=disabled`.
- `scope=local_agent_only`, `connection_verified=false`.
- `manager.manager_configured=false`, `manager.address=null`.
- `ingest.enabled=false`, `running=false`.
- The explanatory text explicitly states: only local Agent status and the local alert file are read; lsec is not a Wazuh Manager and does not verify or claim Manager connection capability.

The Web UI host page shows the Wazuh card, `Not enabled`, `Unverified`, and a scope note. It does not show "not installed" as "running", nor does it describe local alert file ingestion as Manager capability.

### 5.2 Temporary local Agent test

To verify the optional ingestion path, a separate temporary daemon and temporary data directory were started at `/tmp/lsec-wazuh-test` using a real local `alerts.json`:

- On first start it begins at the file EOF and does not backfill historical alerts.
- After writing a level 10 alert, a unified event is generated: `source=wazuh`, `severity=high`, `category=auth`, with target IP `203.0.113.7`.
- After writing the same alert again, `occurrences=2`, with no second event produced.
- After restarting the daemon the ingestion counter resets to zero, but the persisted offset prevents duplicate collection, and the event remains `occurrences=2`.
- After log rotation (`max_bytes=8192`, `backups=3`), the active file is 2756 bytes and `.1/.2/.3` are 8056 bytes each; rotation is recognized and produces no parse flood.
- Negative cases such as oversized lines, invalid JSON, file truncation, and symlink alert files are covered by unit tests; an unreadable or unparsable input never generates a fabricated event.

Limitation: the temporary test verifies only local Agent alert file ingestion and does not include a real Wazuh Manager, real Agent registration, TLS connection, or Manager API calls. The product does not claim to provide these capabilities either.

## 6. Release and upgrade tests

### 6.1 Build

Two test versions were built from the current source on the test host:

- `lsec_0.4.0_all.deb`
- `lsec_0.4.1_all.deb` (used only for upgrade/downgrade path testing)

Checked with `dpkg-deb`:

- `Architecture: all`
- `Depends: python3 (>= 3.10), adduser`
- `Recommends: clamav, clamav-daemon, clamav-freshclam, yara, lynis`
- `Suggests: wazuh-agent`
- Includes `conffiles`, `postinst`, `prerm`, `postrm`

### 6.2 Install/upgrade/downgrade/uninstall

Executed in a disposable Debian 12 container with no systemd, so the systemd branch of postinst is skipped by design:

| Step | Result |
| --- | --- |
| `dpkg -i 0.4.0` with `python3` missing | Dependency failure, the package remains unconfigured, and no system user or data directory is created; after installing the dependency, reconfiguration succeeds |
| Install 0.4.0 | Creates the `lsec` system user/group and `/var/lib/lsec` plus `clamav/evidence/logs/quarantine/secrets/wazuh/yara` subdirectories, with permissions as expected |
| After modifying configuration and writing a data marker, upgrade to 0.4.1 | Upgrade succeeds, the local configuration marker is preserved, `/var/lib/lsec/upgrade-marker` is preserved, and the user/group is unchanged |
| `dpkg --force-downgrade` to 0.4.0 | Downgrade succeeds, and configuration and data are still preserved |
| `dpkg -r lsec` | Removes the program, explicitly prints that `/var/lib/lsec` and `/var/log/lsec` are retained, and the data remains |
| `dpkg -P lsec` | Deletes data, logs, configuration, and the `lsec` system user/group; `dpkg-query` no longer finds the package |

Test environment note: the test container came from the `lsec:0.4.0` image, whose `/usr/local/bin/lsec` is a development launcher that shadows the package-installed `/usr/bin/lsec`; testing used `/usr/bin/lsec` and verified in an environment without `PYTHONPATH`. An ordinary deb host does not have this development launcher. Boot autostart, service restart, and automatic rollback after a failed upgrade were not verified on a real systemd host; the related recovery steps are documented in `docs/RELEASE.md` and `docs/DEPLOYMENT.md`.

### 6.3 Artifact verification

The release scripts generate:

- `.deb`
- source tar
- `SHA256SUMS`
- `BUILD-MANIFEST.txt`

`scripts/verify-release.sh` verifies the release `SHA256SUMS` and the deb metadata. The build host had no GPG private key, so there are no `.asc` signature files this time, and `BUILD-MANIFEST.txt` explicitly records `signed=no`. The signing process itself is supported by the scripts but was not executed this time, so these artifacts must not be described as "signed".

## 7. Performance testing

### 7.1 Event writes and queries

A temporary SQLite database inside the deployment container was used to write 5000 unique Falco events (without polluting the production database):

| Metric | Result |
| --- | --- |
| Total write time | 2.459 seconds |
| Write throughput | 2032.9 events/second |
| Write latency p50 / p95 / max | 0.403 ms / 0.432 ms / 11.562 ms |
| Latest event list | 13.59 ms |
| Severe event filter | 3.97 ms |
| Keyword search | 2.87 ms |
| Export 5000 events | 70.81 ms |
| Count aggregation | 0.9 ms |
| Database size | 7,872,512 bytes |
| Peak process RSS | 63,300 KB |

Note: this is a synthetic single-machine, single-process, sequential-write workload; it does not represent high-concurrency or long-run limits.

### 7.2 Container inventory scale

A test-only fake Docker API generated 10/50/100/200 containers and refreshed the read-only inventory:

| Container count | Refresh time | Per container |
| --- | --- | --- |
| 10 | 0.007 seconds | 0.7 ms |
| 50 | 0.123 seconds | 2.46 ms |
| 100 | 0.242 seconds | 2.42 ms |
| 200 | 0.576 seconds | 2.88 ms |

At 200 containers, 203 HTTP requests were made in total, the state was `monitored`, there were no inspect errors, and all containers were monitored. This test uses a local synthetic API and does not include jitter of a real Docker daemon at large container counts.

### 7.3 Idle resources and short-term stability

When the main deployment is idle:

| Metric | Value |
| --- | --- |
| Container CPU | 0.07%–0.11% |
| Container memory | 981.1–981.3 MiB / 123.4 GiB |
| Container process count | 10 |
| clamd RSS | about 965 MiB |
| lsec Python process RSS | about 34 MiB |

Sampled 12 times over about 5 minutes 41 seconds (30-second intervals); CPU and memory were stable, with no restarts, no OOM, and no health check failures. No multi-hour or multi-day endurance test was executed, so no claim is made that long-term stability acceptance has been met.

## 8. Security test results

| Control objective | Verification result |
| --- | --- |
| Authentication and roles | Unauthenticated 401; viewer write operations 403; Falco token can only write to the ingestion endpoint |
| CSRF / Origin | Missing CSRF or cross-site Origin rejected |
| Path traversal / symlinks | Scan, quarantine, rule pack, and alert file paths all have negative tests |
| Command execution | All external commands use argv arrays; no shell string concatenation |
| Quarantine operations | Explicit confirmation required; audit written; no automatic quarantine/deletion |
| Container security | Read-only Docker API; proxy write methods 405; the product has no stop/restart/delete routes |
| Secret protection | Token files 0600; responses and logs never return tokens; Wazuh registration key contents are never read/returned |
| Truthfulness | Component states, scan results, container inventory, and Wazuh capabilities all come from real probing; failures are distinguished as `unavailable`/`permission_denied`/`error`, and no fabricated data is returned |
| Update failure | Keeps the old virus database and returns the real exit code and output tail |
| Alert input | Oversized payloads, invalid JSON, oversized lines, and file rotation/truncation all have boundary handling |

## 9. Defects and fix record

| Defect | Impact | Fix |
| --- | --- | --- |
| clamd used newline framing, causing `COMMAND READ TIMED OUT` | Real ClamAV scans failed | Switched to NUL framing `zSCAN path\0` |
| YARA parsed `yarac` compile output as source | All real YARA scans failed | Added `-C` |
| Multiple file arguments were treated by YARA as multiple rule files | Batch scan `partial`, producing errors | Used a temporary list + `--scan-list` |
| At build time, the official Debian repositories stalled on large file downloads | The image could not be built | Used a reachable mirror during build (SJTU this time); runtime network unchanged |
| Playwright waited for hidden elements incorrectly | UI smoke test falsely reported timeouts | Changed to `state: 'hidden'` and asserted on real page text |

## 10. Scope and limitations

Items not executed or not provable by this test:

- No multi-day/multi-week endurance, memory leak, or long-term disk growth tests were executed.
- Service boot autostart, crash auto-restart, and real apt upgrade interaction were not verified on a real systemd host; the deb lifecycle was verified in a disposable container without systemd.
- Real Wazuh Manager/Agent registration, Manager API, TLS, and cluster capabilities were not verified; the product explicitly does not provide Manager capability.
- Real containerd API integration was not verified (currently probe-only).
- TLS mutual authentication, reverse proxy, and external identity provider integration were not verified.
- No GPG-signed release was executed; this release's artifacts are unsigned.
- Container performance testing used a synthetic Docker API; a real daemon at hundreds of containers may behave differently.
- The browser UI received only a one-off Playwright smoke test and is not part of continuous CI regression.
- The host security audit runs inside the container; when host capabilities such as SSH/systemd/AppArmor are not visible, they are explicitly marked skipped, which does not mean the host passed the checks.

## 11. Acceptance mapping

### YARA and unified event center

| Acceptance item | Evidence |
| --- | --- |
| YARA Adapter | Real 4.2.3 scanning; 1000 files succeeded after the `-C` + `--scan-list` fixes |
| Rule pack validation/version management | Signature, hash, and compile validation; multi-version install/activate/delete; invalid packs rejected |
| Event list/deduplication/filtering/details/audit/export | Verified via API and Playwright; `occurrences=3` with 3 source tasks retained |
| Invalid rule pack rejection | All four types of invalid packs returned 400 and left no version |
| Unified fields | `source/category/severity/target/evidence/dedup_key/source_refs` verified in practice |
| Deduplication retains source evidence | All 3 `task_id`s of the same event are in `source_refs` |

### Wazuh and release hardening

| Acceptance item | Evidence |
| --- | --- |
| Wazuh Agent state/event ingestion based on actual architecture | Truthfully shows disabled when not installed in the test deployment; a temporary local Agent verified alert file ingestion |
| Does not claim full Wazuh capability | `scope=local_agent_only`, `connection_verified=false`, UI scope note |
| Update signature verification | ClamAV CVD `sigtool` verification success/failure/not-applicable paths covered by tests |
| Complete deb package | Install/upgrade/downgrade/remove/purge all passed |
| Install/upgrade/uninstall documentation | `docs/RELEASE.md`, `docs/DEPLOYMENT.md` |
| Security/performance test report | This document |
| Recovery path after failed upgrade | Dependency failure keeps the package unconfigured; the documentation records database backup and rollback package steps |
| Source/signature/dependency traceability | `BUILD-MANIFEST.txt`, `SHA256SUMS`, `dpkg-deb -I`; explicitly unsigned this time |
