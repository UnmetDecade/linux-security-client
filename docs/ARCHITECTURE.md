# Architecture

**English** | [简体中文](ARCHITECTURE.zh-CN.md)

## 1. Form and boundaries

lsec takes the form of a **single-node daemon + HTTP API + web UI + CLI**, deployed as a container.

The original requirements assumed a desktop Qt GUI, Unix Socket IPC, systemd, and a deb package; per the user's explicit request, this project changed to:

- No Qt; the web management interface is served as static assets by the daemon itself
- Containerized deployment (Docker Compose), with ClamAV installed in the image
- The daemon and web UI communicate over a local HTTP API; the CLI reuses the same API
- The lsec process does not mount the Docker Socket directly; optional container monitoring is read through a separate GET-only proxy
- No central management server

These are product form adjustments and do not change the core security constraints: a single daemon, a unified event model, adapter isolation, no fabricated data, and confirmation plus audit for high-risk operations.

## 2. Layers

```
Web UI / CLI
     │  HTTP JSON (Bearer or session Cookie + CSRF)
     ▼
API layer (authentication, authorization, routing, static assets, security response headers)
     ▼
Core service layer (scanning, host audit, container monitoring, events, quarantine, status, self-check, updates, maintenance)
     ▼
Adapter layer (ClamAV / Lynis / Falco / YARA / Wazuh / Docker / Containerd / systemd)
     ▼
Local system (clamd, freshclam, filesystem, SQLite, logs)
     │
     └── Optional: GET-only Docker API proxy ── unix:///var/run/docker.sock
```

Module responsibilities:

| Module | Responsibility |
| --- | --- |
| `common/config.py` | Strict TOML validation, environment variable overrides, secure defaults |
| `common/paths.py` | Absolute path, out-of-bounds, symlink, and regular file validation |
| `common/executor.py` | Run subprocesses with an argv list; kill the process group on timeout; truncate output |
| `storage/db.py` | SQLite connection, WAL, transactional migrations, pre-migration backups, integrity checks |
| `storage/*.py` | Component, task, event, quarantine, session, settings, and audit repositories |
| `adapters/base.py` | Adapter contract, `ProbeResult`, `Detection`, `ScanOutcome` |
| `adapters/clamav.py` | clamd UNIX Socket protocol, freshclam, scanning, and hashing |
| `adapters/misc.py` | Probe-only component adapters, Docker permission distinction, Containerd probing |
| `adapters/falco.py` | Falco binary/kernel/eBPF capability probing, read-only install plan |
| `core/docker_api.py` | GET-only Docker Engine API client (http/unix) |
| `core/container_checks.py` | Pure-function container configuration risk assessment |
| `core/containers.py` | Read-only container inventory, background refresh, risk events persisted |
| `core/falco.py` | Falco JSON event validation, bounded normalization, deduplication keys |
| `core/scans.py` | Task queue, worker threads, progress, cancellation, scheduling, evidence |
| `core/events.py` | Detection normalization, severity mapping, deduplication keys, event persistence |
| `core/quarantine.py` | Quarantine/restore/delete, hash re-verification, inode replacement detection, audit |
| `core/status.py` | Aggregate the real protection state; never show a missing capability as normal |
| `api/auth.py` | Tokens, sessions, roles, login rate limiting, CSRF |
| `api/server.py` | HTTP routing, access levels, security response headers, CSV/JSON export |
| `daemon.py` | Initialization, single-instance lock, background threads, signal handling, HTTP service |
| `cli/__main__.py` | Unprivileged CLI client |

## 3. Key data models

### SecurityEvent

Unified fields: `event_id`, `timestamp`, `source`, `category`, `severity`, `title`, `description`, `host`, `target`, `evidence`, `status`, `recommended_actions`, `dedup_key`, `first_seen_at`, `last_seen_at`, `occurrences`, `source_refs`.

Deduplication: build a deterministic `dedup_key` from the source (for example, ClamAV uses `clamav|category|path|detection_name`, Wazuh uses Agent + rule + description + target, and YARA uses rule + target), then hash the whole thing with SHA-256. Within the deduplication window, while the event is still in `new/acknowledged/investigating`, merge it by accumulating the occurrence count, updating the latest time, and retaining all source references (up to 10) and the first evidence; different sources never swallow each other.

### ScanTask

State machine:

```
queued ──▶ running ──▶ succeeded
   │          │  └────▶ partial
   │          ├───────▶ failed
   │          └───────▶ cancel_requested ──▶ cancelled
   └──────▶ cancelled / failed
```

Terminal states cannot transition again. When the daemon restarts, leftover `running/cancel_requested` tasks are uniformly marked `failed`; it never pretends they are still running.

Progress is given as a percentage only when the total number of files is known; when enumeration fails or is unknown it returns `null`, and the UI shows "progress unknown".

### AuditRun

States: `queued → running → succeeded/partial/failed`. Stores the scope, requester, start/end time, total checks, findings count, not-executed count, severity counts, Lynis hardening index/version, evidence path, and error. The detailed check list and system information are stored in `report.json`; the database stores only a bounded summary.

Check result states: `pass`, `finding`, `error`, `skipped`. Only `finding` enters the event center; `error` counts as not executed; `skipped` means the current environment cannot evaluate it (for example, no systemd inside a container). The three are never conflated.

### ComponentStatus

`installed`, `service_status`, `health_status`, `capabilities`, `error_code`, `error_message`, `details`, `last_check_at`.

Health states are distinguished as: `ok`, `degraded`, `unavailable`, `unknown`, `incompatible`, `check_failed`, `permission_denied`. "Installed" alone never produces "protection normal".

### ContainerSnapshot

In-memory snapshot (not persisted): `state` (`disabled/initializing/monitored/degraded/unavailable/permission_denied`), `note`, engine information, container array, summary, `checked_at`, `last_success_at`, `stale`, `truncated`, `inspect_errors`, scope and limitation notes, and event ingestion counters.

A single container includes: ID, name, image, state, time, PID, restart count, OOM, runtime user, `privileged`, network/PID/IPC/userns modes, CapAdd/CapDrop, SecurityOpt, read-only root filesystem, devices, mounts, ports, `findings`, `risk_level`, `risk_count`, `evaluated`, `evaluation_error`. **Environment variables are not retained.**

Risk levels: `critical/high/medium/low/none/unknown`. When required fields such as `Config/HostConfig/State` are missing, `evaluated=false` and the level is `unknown`; it is never treated as `none`.

### Falco capabilities and events

Capability states: `compatible`, `unsupported`, `requires_privileges`, `requires_setup`, `unknown`. `compatible` only means the kernel, BTF, and capability prerequisites are present; `running_verified` is fixed at false because lsec cannot confirm the host-side Falco process or rule loading state.

Falco events are normalized to `source=falco`, `category=runtime`, retaining only bounded rule, priority, output, container ID/name/image, and process fields. Priority mapping: Emergency/Alert/Critical→critical, Error→high, Warning→medium, Notice→low, Informational/Debug→info; unknown priorities→medium with the original value retained.

### QuarantineItem

Stores the original path, stored file name, SHA-256, size, detection name, engine, associated event, quarantiner, state (`quarantined/restored/deleted/missing`), and timestamps. The file itself is stored in the data volume under `quarantine/` (0700).

### AuditRecord

Records the request ID, actor, client, action, target, before/after state (truncated at 16 KB), whether confirmed, result, error, and time.

## 4. Scan pipeline

1. The API validates the role, CSRF, task type, and target path.
2. `ScanManager` resolves the target (quick scan directories / `/` / custom allowlisted roots) and probes whether ClamAV is installed and clamd is running.
3. The task is written to SQLite; a worker thread takes it and sets it to `running`.
4. The ClamAV Adapter first walks the files to count them (for real progress), then scans file by file through clamd `zSCAN path\0` (NUL framing).
5. On a `FOUND` detection, it computes the SHA-256, builds a Detection, and the event service normalizes/deduplicates and persists it.
6. When the task ends, it writes statistics, error samples, and an evidence JSON; the state is `succeeded/partial/failed/cancelled`.
7. Progress is persisted through SQLite and read by web/CLI polling; it never relies on fabricated in-memory state.

File traversal rules: do not follow symlinks; skip configured directories and the data volume's quarantine and evidence directories; files exceeding the size limit count as "skipped" rather than scanned.

## 5. Host security audit pipeline

1. `POST /audits` has an administrator create an `audit_runs` record (`queued`); the service allows only one audit to be queued/running at a time.
2. A single background worker sets it to `running`, first runs the built-in read-only checks, then runs Lynis according to configuration.
3. The built-in checks cover: additional UID 0 accounts, empty passwords, duplicate UIDs, sensitive file permissions, explicit SSH directives, dangerous listening ports, legacy systemd services, ASLR, AppArmor/SELinux. All file reads are based on an injectable root directory for unit testing.
4. Check results are `pass/finding/error/skipped`. Only `finding` produces a unified event through `EventService.ingest_finding`; `error` counts as "not executed" and produces no risk event. Lynis `warning[]` entries map to findings, while `suggestion[]` entries are kept only in the report.
5. Lynis runs with the fixed argv `audit system --quick --no-colors --quiet`; the raw report and log are written to the evidence directory and restricted to 0600; parsing uses the stable keys `hardening_index`, `lynis_tests_done`, `lynis_version`.
6. A summary of system information, check details, and limitation notes is written to `report.json`; the database stores counts, severities, the hardening index, the evidence path, and the state.
7. Status aggregation reads the latest completed audit and computes `current/stale/failed/not_run`; audit findings affect the overall risk state through the event center.
8. When the daemon restarts, leftover `queued/running` audits are marked `failed` with an interruption explanation rather than disguised as complete.

## 6. Container monitoring and Falco pipeline

### 6.1 Read-only proxy

- The lsec process does **not** mount `/var/run/docker.sock`.
- The optional `lsec-docker-proxy` container mounts the Socket (read-only) and forwards only:
  `GET /version`, `GET /info`, `GET /containers/json?all=0|1`,
  `GET /containers/<12-64 hex char ID>/json`.
- Other paths return 403, and all non-GET methods return 405; responses are capped at 8 MB, with an 8-second upstream timeout.
- The proxy runs on an `internal: true` network with `cap_drop: ALL`, `no-new-privileges`, and a read-only root filesystem, and publishes no host ports.
- The proxy remains a highly privileged component (Socket equals host root), so container checks truthfully mark it as a critical risk.

### 6.2 Collection and evaluation

1. The `ContainerService` background thread calls the Docker API according to `containers.refresh_seconds`; an administrator can also refresh manually (audited as `container.refresh`).
2. It reads `/version`, `/info`, and the container list in order, then inspects each container; the list count is limited by `max_containers` and marked truncated.
3. `evaluate_container()` is a pure function that checks privileged mode, host network/PID/IPC/userns, Docker Socket mounts, sensitive directory mounts, overly broad capabilities, seccomp/AppArmor/SELinux, device passthrough, root user, and so on.
4. Sensitive paths are matched by longest prefix (for example, `/etc/ssh` matches `/etc`), read-write mounts are more severe than read-only, and even a read-only Docker Socket mount is treated as critical.
5. A failure to read a single container's details shows "could not be evaluated" without failing the whole refresh; the overall state degrades to `degraded`.
6. On a refresh failure, the last successful snapshot is retained and marked `stale=true`; if it has never succeeded, the inventory is cleared, never showing old data as the current state.

### 6.3 Event correlation

- Only findings from "running" containers with `evaluated=true` are written to the unified event center: `source=docker`, `category=configuration`.
- The deduplication hint is `<container_id>:<finding_key>`; risks already reported within the same process are not recreated every round.
- The event target includes the container ID and name, and the evidence includes the engine, rule, image, state, and bounded check details.
- A configuration risk that disappears and later reappears can be merged/created again, reflecting the real state change.

### 6.4 Falco

- The Adapter reads the kernel version, BTF, `/sys/fs/bpf`, tracefs, `CapEff`, and `unprivileged_bpf_disabled`, distinguishing unsupported, insufficient permissions, configuration required, and compatible.
- When Falco is missing the component is `unavailable`; an incompatible kernel is `incompatible`; insufficient permissions is `permission_denied`; with prerequisites present it remains `unknown` with `running_verified=false`.
- The install plan is read-only with `installable_from_ui=false`; lsec does not install, start, or load drivers.
- After `falco.ingest_enabled` is enabled, a separate token `/data/secrets/falco.token` (0600) is generated. That token can only POST to `/api/v1/integrations/falco` and cannot read any other API; administrator/read-only tokens also cannot write to that endpoint.
- Before writing an event, the size, JSON object, rule/output, and output field types are validated; an invalid container ID is not used as the target container ID.

### 6.5 YARA rule packs and scanning

- Rule pack format: a zip or directory containing `manifest.json` (`schema_version`, `pack_id`, `version`, rule files and their SHA-256) and an optional `manifest.sig` (OpenSSL detached signature).
- The source path must be inside `yara.inbox_dir`; symlinks, zip entry traversal, undeclared files, duplicate versions, and packs exceeding count/size limits are rejected.
- Each declared rule file's SHA-256 is re-verified one by one; when `require_signature=true`, the manifest signature is verified with the configured public key, and a missing key or invalid signature is rejected outright.
- Only after `yarac` compile validation passes is the pack written to the version directory `<rules_dir>/packs/<pack_id>/<version>/`; the same version is never overwritten.
- `state.json` is updated atomically and records the active version; activation/deletion both require administrator confirmation and write an audit record.
- Scanning enumerates only regular files inside the allowed roots, does not follow symlinks, skips abnormal file names, and invokes `yara -w -g` in batches by file count (`scan_batch_files`) and a 128 KiB argv budget.
- Output parsing accepts only the `rule [tags] target` form, and the target must be within the current scan scope; severity is determined by the rule tags (`severity_critical/high/medium/low/info`, default medium).
- Hit events are `source=yara`, `category=malware`, and the evidence retains the rule, tags, target, pack ID/version, and compiled-rule hash; no automatic quarantine occurs.

### 6.6 Wazuh local integration

- The Adapter read-only probes `wazuh-agentd`/`wazuh-control`, the installation directory, the Manager address/port in `ossec.conf`, and whether `client.keys` exists along with its permission bits; it **does not read the key contents**.
- Health determination distinguishes: configuration disabled, not installed, missing configuration, Manager not configured, Agent stopped, and Manager connection unverified. Even when the Agent runs normally, the health state is `unknown` with `error_code=manager_connection_unverified`, and the capability state is at most `degraded`.
- Optional `alerts.json` ingestion is polled by a single-threaded `WazuhAlertIngester`: it persists the inode and byte offset; on first enable it starts at the end of the file and does not import the historical backlog; it resets on an inode change or file truncation; it processes only complete lines and limits the per-read and per-event size.
- An oversized single line is continuously discarded up to the next newline; a truncated fragment is never parsed as a complete alert.
- Event mapping: level 12+→critical, 8–11→high, 4–7→medium, 1–3→low, 0→info; group tags map to malware/intrusion/integrity/vulnerability/configuration, with the rest as runtime.
- Events have `source=wazuh`, and `source_ref.manager_connection_verified` is fixed at false; recommended actions only prompt manual verification and never trigger automatic response.

## 7. Quarantine pipeline

- `confirm=true` is required; restore/delete likewise require confirmation.
- The original path must be a regular file (symlinks/directories/devices/FIFOs are rejected).
- The real path must be inside `response.quarantine_roots`; quarantine capacity is limited by `quarantine_max_mb`.
- Open the source file with `O_NOFOLLOW`, hash it, copy it to a new file (0600, `O_EXCL`), and re-verify the hash.
- Before deleting the source file, use `(st_dev, st_ino)` to confirm the path still points to the same file, preventing replacement attacks.
- On restore, re-verify the stored file's hash, refuse to overwrite an existing original path, and verify the hash again after writing.
- Every step's success/failure is written to the audit log.

## 8. Threads and concurrency

- `ThreadingHTTPServer` handles concurrent requests, with an independent SQLite connection per request.
- `ScanManager` starts `scan.max_parallel_tasks` worker threads (1–4) and one scheduler thread.
- The task queue is capped at 50 `queued` tasks; exceeding it returns a conflict.
- `UpdateManager` uses a single-flight lock to avoid concurrent freshclam runs; after an update completes, it re-verifies the CVD digital signature with `sigtool --info`.
- `WazuhAlertIngester` polls on a single background thread, writing state and offsets to a 0600 `state.json`; a single tick is also invoked directly in tests.
- `AuditService` runs audits serially on a single worker thread; creation uses a lock plus database state to prevent concurrent audits.
- `ContainerService` refreshes periodically on a single background thread, and `_refresh_lock` prevents a manual refresh from racing a scheduled one; snapshot reads and writes use a separate lock.
- `MaintenanceService` periodically cleans up expired sessions, terminal events, and evidence quotas.
- The single instance is guaranteed by a `flock` on `/data/daemon.lock`.

## 9. Truthfulness principles

- The status summary `overall` has only three values: `healthy`, `at_risk`, `protection_incomplete`.
- Real-time protection inside the container is fixed at `unsupported`, so the overall state never shows "protection normal".
- Unimplemented capabilities return `not_implemented` via `/capabilities`; the web page shows an explanation instead of a blank "secure" page.
- A failed component probe shows `check_failed`, and insufficient permissions shows `permission_denied`; neither degrades to "normal".
- Scan results come only from real clamd responses; the fake clamd in tests exists only under `tests/` and never enters the product image.
- Audit scope notes come from real container probe results; when Lynis is missing it explicitly states "built-in checks only" and never fabricates a hardening index or suggestions.
- The container inventory comes only from real Docker Engine API responses; when disabled, under-privileged, or unavailable, it is cleared or marked stale rather than showing fabricated containers.
- When container checks cannot read details, they show `unknown`/"could not be evaluated" and never classify it as "no risk".
- Falco's `compatible` does not mean running; `running_verified` is always false, and not installed/incompatible/insufficient permissions are shown separately rather than disguised as protected.
- Containerd reports only probe results and never passes off the Docker inventory as a Containerd inventory.
- YARA scanning is available only when a rule pack compiles successfully and an active version exists; packs with unverified signatures/missing public keys are not loaded and are not shown as "rule protection ready".
- The Wazuh capability state is at most `degraded`, and `connection_verified` is always false; "local Agent installed" is never described as "full Wazuh capability".
- When `sigtool` is not installed or the database is `.cld`, the signature verification result shows "unverified/not applicable" and never appears as passed.

## 10. Extension points

- A new engine implements `Adapter` and registers with `ComponentManager`; events are persisted through the unified `EventService`.
- Containerd: if inventory collection is added later, it should reuse the read-only proxy approach and implement a separate containerd API/Socket client with explicit capability states; Docker data must not be passed off as containerd data.
- A new event source must provide a deterministic `dedup_key`, bounded evidence, and an explicit `source_ref`, and must state which capabilities are unverified.
- A new rule/signature format should reuse the YARA rule pack flow of "verify first, compile next, then activate atomically", and must never overwrite an active version in place.
- Any newly added container operation (stop/restart/delete) must be independently authorized, state its impact, require two-step confirmation, and be audited; the current version explicitly does not provide them.
- The release process is described in `docs/RELEASE.md`: the deb, source package, SHA256SUMS, and detached GPG signatures must be released together.
