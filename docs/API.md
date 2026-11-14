# HTTP API

**English** | [简体中文](API.zh-CN.md)

Base path: `/api/v1`. All responses are JSON (except export endpoints). Successful responses contain `"ok": true`; failure responses look like:

```json
{
  "ok": false,
  "error": {
    "code": "invalid_argument",
    "message": "human-readable description",
    "details": {"...": "optional"},
    "request_id": "..."
  }
}
```

## Authentication

### Bearer Token (CLI)

```http
Authorization: Bearer <token>
```

### Web session

After a successful `POST /api/v1/auth/login`, the server sets an HttpOnly, SameSite=Strict `lsec_session` Cookie and returns a one-time `csrf_token` in the response body. Subsequent write operations (POST/PATCH/DELETE) must also carry:

```http
X-LSEC-CSRF: <csrf_token>
```

For write requests on a Cookie session, if an `Origin` header is present, its host must match `Host`.

### Roles

| Role | Permissions |
| --- | --- |
| `admin` | Read + scan/cancel, component start/stop/update, event status, quarantine/restore/delete, container refresh, policy changes, logs |
| `viewer` | Read status, components, tasks, events, quarantine, audit, self-check, settings, container inventory |
| `integration` | Falco event ingestion only; cannot read any other API |

Token files: `/data/secrets/admin.token`, `/data/secrets/viewer.token`, mode 0600. They can also be overridden with `LSEC_ADMIN_TOKEN` / `LSEC_VIEWER_TOKEN` (at least 16 characters).

Falco uses a separate token `/data/secrets/falco.token` (created automatically when `falco.ingest_enabled` is enabled, 0600). It is not in the administrator/read-only token table, and conversely administrator/read-only tokens are not allowed to call the Falco ingestion endpoint.

## General

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/health` | public | Liveness check |
| POST | `/auth/login` | public | Log in, returns the role and CSRF |
| POST | `/auth/logout` | logged in | Log out the current session |
| GET | `/version` | logged in | Daemon/API version |
| GET | `/system/info` | logged in | Host and daemon information |
| GET | `/status` | logged in | Aggregated protection status |
| GET | `/capabilities` | logged in | Capability matrix |

`/status` example (excerpt):

```json
{
  "ok": true,
  "status": {
    "overall": "protection_incomplete",
    "overall_label": "Protection incomplete",
    "protection": {
      "on_demand": {"state": "ready", "reason": "ClamAV on-demand scanning available"},
      "real_time": {"state": "unsupported", "supported": false, "reason": "..."},
      "virus_database": {"state": "current", "updated_at": "...", "age_hours": 1.2}
    },
    "events": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total_open": 1},
    "last_scan": {"task_type": "quick", "status": "succeeded", "...": "..."}
  }
}
```

## Components

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/components` | logged in | Real component state |
| POST | `/components/probe` | admin | Re-probe all components |
| GET | `/components/{id}/install-plan` | logged in | Install source and permission notes |
| POST | `/components/clamav/start` | admin | Start clamd |
| POST | `/components/clamav/stop` | admin | Stop clamd |
| POST | `/components/clamav/update` | admin | Update the virus database with freshclam |

An update returns `{"ok": true, "update": {"ok": true, "exit_code": 0, "duration_seconds": 12.3, "output_tail": "...", "database": {...}}}`.

## Scan tasks

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/scans?status=&limit=&offset=` | logged in | Task list |
| POST | `/scans` | admin | Create a task |
| GET | `/scans/{task_id}` | logged in | Task details |
| POST | `/scans/{task_id}/cancel` | admin | Request cancellation |

Create requests:

```json
{"type": "quick", "engines": ["clamav"]}
{"type": "full", "engines": ["clamav", "yara"]}
{"type": "custom", "paths": ["/scan/downloads"], "engines": ["clamav", "yara"]}
{"type": "yara", "paths": ["/scan/downloads"], "engines": ["yara"]}
```

`type` supports `quick/full/custom/yara`; `engines` supports `clamav` and `yara`, defaulting to `["clamav"]`. `type=yara` allows only the YARA engine and requires `paths`. Custom paths must exist and be inside `scan.allowed_roots`. For multi-engine scans, failure of a single engine is recorded as partial completion with each engine's error retained; only failure of all engines is `failed`. Task states:

`queued`, `running`, `cancel_requested`, `cancelled`, `succeeded`, `failed`, `partial`.

`progress` is `null` when the total file count is unknown. `result_summary.detections_sample` holds at most 500 entries; the evidence report path is `result_summary.evidence_path`.

## Security events

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/events?severity=&source=&category=&status=&q=&since=&until=&limit=&offset=` | logged in | List |
| GET | `/events/{event_id}` | logged in | Details |
| PATCH | `/events/{event_id}` | admin | Status transition and note |
| GET | `/events/export?format=json|csv&...` | logged in | Export (at most 5000 entries) |

Status transitions:

```
new -> acknowledged | investigating | resolved | ignored
acknowledged -> investigating | resolved | ignored
investigating -> resolved | ignored
resolved -> new
ignored -> new
```

PATCH request: `{"status": "acknowledged", "note": "manually verified"}`.

For CSV export, cells beginning with `= + - @` are prefixed with `'` to prevent spreadsheet formula injection.

## Quarantine

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/quarantine?status=&limit=&offset=` | logged in | List |
| POST | `/quarantine` | admin | Quarantine a file |
| GET | `/quarantine/{item_id}` | logged in | Details (including `file_exists`, `stored_path`) |
| POST | `/quarantine/{item_id}/restore` | admin | Restore |
| POST | `/quarantine/{item_id}/delete` | admin | Permanently delete |

A quarantine request must include `"confirm": true`:

```json
{
  "path": "/scan/eicar.txt",
  "detection_name": "Eicar-Signature",
  "engine": "clamav",
  "event_id": "<optional>",
  "confirm": true
}
```

Restore/delete request body: `{"confirm": true}`.

## Host security audit

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/audits?limit=20&offset=0` | logged in | Audit history (without large fields), also returns the currently queued/running audit |
| POST | `/audits` | admin | Create a read-only host security audit, returns 202; returns 409 when an audit is already running |
| GET | `/audits/{audit_id}` | logged in | Audit details, including `result_summary.checks`, Lynis results, and the evidence path |

Audit states: `queued`, `running`, `succeeded`, `partial`, `failed`. Check states: `pass`, `finding`, `error`, `skipped`; only `finding` produces a unified event, while `error` means the check could not be executed and does not imply a risk.

`POST /audits` needs no request body and returns:

```json
{"ok": true, "audit": {"audit_id": "...", "status": "queued", "scope": "container"}}
```

Audits run serially in the background; clients should poll `GET /audits/{audit_id}` until the state reaches `succeeded/partial/failed`. Key fields in the details:

- `findings_count`, `errors_count`, `severity_counts`
- `hardening_index`, `lynis_available`, `lynis_version`
- `evidence_path`: the directory containing `report.json` and the raw `lynis-report.dat` / `lynis.log`
- `result_summary.scope_note`, `limitations`, `system_info`, `counts`

The audit does not modify system configuration and does not automatically fix or remediate anything.

## Container security

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/containers` | logged in | Container monitoring snapshot: state, engine information, inventory, summary, limitation notes |
| GET | `/containers/{ref}` | logged in | Single container details; `ref` can be the full ID, a unique ID prefix, or the container name |
| POST | `/containers/refresh` | admin | Perform one immediate read-only collection and write the audit `container.refresh` |
| GET | `/falco` | logged in | Falco component, capabilities, event ingestion statistics |
| POST | `/integrations/falco` | integration | Receive Falco JSON alerts, returns 202 |

Container monitoring states: `disabled`, `initializing`, `monitored`, `degraded`, `unavailable`, `permission_denied`. On failure, the retained last snapshot carries `stale: true`; if it has never succeeded, the inventory is empty and no fabricated data is returned.

Single-container risk levels: `critical`, `high`, `medium`, `low`, `none`, `unknown`. `evaluated: false` means the detail fields are insufficient or the read failed, and `risk_level` is `unknown`, which **must not** be interpreted as safe.

`GET /containers` response excerpt:

```json
{
  "ok": true,
  "containers": {
    "state": "monitored",
    "note": "Read 3 containers, 2 running; 3 have configuration risks",
    "engine": {"runtime": "docker", "server_version": "27.1.1", "api_version": "1.46"},
    "summary": {
      "total": 3, "running": 2, "stopped": 1, "risky": 3, "unknown": 0,
      "findings": 5,
      "by_risk": {"critical": 1, "high": 2, "medium": 0, "low": 0, "none": 0, "unknown": 0}
    },
    "checked_at": "2026-11-10T10:00:00Z",
    "last_success_at": "2026-11-10T10:00:00Z",
    "stale": false,
    "truncated": false,
    "containers": [{"container_id": "...", "name": "web", "image": "nginx:latest", "state": "running", "risk_level": "high", "findings": []}],
    "scope_note": "The container inventory comes from the Docker Engine API…",
    "limitations": ["…"]
  }
}
```

`GET /falco` returns the component probe result (`component.details.capability` includes kernel, BTF, and capability states) plus `event_ingest.enabled/endpoint/token_path/events_total/last_event_at`. Only the token path is shown, never the token contents.

### Falco event ingestion

```http
POST /api/v1/integrations/falco
Authorization: Bearer <falco.token>
Content-Type: application/json
```

```json
{
  "uuid": "3f8c7e2a-0a0b-4c3d-8e9f-1234567890ab",
  "time": "2026-11-10T09:00:00Z",
  "rule": "Terminal shell in container",
  "priority": "Warning",
  "output": "A shell was spawned in a container (user=root)",
  "output_fields": {
    "container.id": "aaaaaaaa...",
    "container.name": "web",
    "container.image.repository": "nginx",
    "container.image.tag": "latest",
    "proc.name": "bash",
    "proc.pid": 1234
  }
}
```

Success returns `202`:

```json
{"ok": true, "event_id": "...", "created": true}
```

When the same rule, container, and process are reported repeatedly within the deduplication window, `created` is `false` and the event's `occurrences` are accumulated. The request body limit is controlled by `falco.max_event_bytes` (default 32 KB); invalid JSON, a non-object, a missing rule/output, or a non-object `output_fields` returns 400. Ingestion is rate-limited to 240 requests/minute.

This version has **no** API for stopping, restarting, or deleting containers or executing commands; any such request returns 404.

## YARA rule packs

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/yara` | logged in | Component, active rule pack, signature configuration, and scan readiness |
| GET | `/yara/packs` | logged in | All rule packs and versions (including the activation flag and signature verification result) |
| POST | `/yara/packs` | admin | Install a rule pack from the inbox |
| POST | `/yara/packs/{pack_id}/{version}/activate` | admin | Activate the specified version |
| DELETE | `/yara/packs/{pack_id}/{version}` | admin | Delete the specified version |

Install request:

```json
{"path": "/data/yara/inbox/pack.zip", "activate": true, "confirm": true}
```

- `confirm` must be `true`, otherwise 400; installation/activation/deletion are all written to the audit log.
- The source file must be inside `yara.inbox_dir`; symlinks, path traversal, undeclared files, SHA-256 mismatches, `yarac` compile failures, and same-version overwrites are rejected.
- When `yara.require_signature=true`, a valid `manifest.sig` and a configured public key must exist; a failed signature verification returns 400.
- A successful install returns 201: `{"ok":true,"pack":{...},"component":{...}}`.
- For the rule pack format and signing steps, see [Deployment and operations](DEPLOYMENT.md).

## Wazuh (optional, local only)

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/wazuh` | logged in | Local Agent probe, Manager configuration summary, alert ingestion status |
| GET | `/wazuh/install-plan` | logged in | Read-only install/registration plan (never executed automatically) |

The `state` returned by `/wazuh` is only ever `disabled/unavailable/degraded/unknown/available`, and `connection_verified` is always `false`. `ingest` describes only ingestion of new lines from the local `alerts.json`:

```json
{
  "enabled": true,
  "ingest_enabled": true,
  "running": true,
  "events_total": 12,
  "parse_errors": 0,
  "rejected": 0,
  "offset": 84512,
  "file_present": true,
  "scope": "local_agent_alert_file",
  "note": "Only ingests new lines from the local Wazuh Agent alerts.json; it is not a Wazuh Manager and does not verify the Manager connection"
}
```

- This client does not contact the Wazuh Manager, does not provide a Manager API, and does not manage other Agents.
- Ingested events have `source=wazuh`; `source_ref.manager_connection_verified=false`.
- On first enable it starts at the end of the file and does not import historical alerts; an Agent that is not running, an unconfigured Manager, or an unverified connection are all shown as degraded.
- The install plan has `installable_from_ui=false` and only lists the steps an administrator must perform on the host.

## Audit, settings, self-check, logs

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/audit?limit=&offset=&action=` | logged in | Operation audit |
| GET | `/doctor` | logged in | Runtime environment self-check (triggers component probing) |
| GET | `/settings` | logged in | Runtime settings and editable scope |
| PATCH | `/settings` | admin | Modify policy |
| GET | `/logs?lines=200` | admin | Tail of the daemon log |

The only settings are: `response_mode` (`alert/suggest`; `auto` returns 501), `auto_quarantine_enabled` (true returns 501), and `scheduled_scan` (`enabled`, `type`, `interval_hours` 1–720, `last_run_at`).

## Error codes

| code | HTTP | Meaning |
| --- | --- | --- |
| `invalid_argument` | 400 | Invalid parameter/path/state transition |
| `unauthorized` | 401 | Not authenticated or invalid token |
| `forbidden` | 403 | Insufficient role, CSRF/Origin validation failed |
| `not_found` | 404 | Resource does not exist |
| `conflict` | 409 | State conflict, queue full, path in use, hash mismatch |
| `rate_limited` | 429 | Too many login attempts |
| `component_unavailable` | 503 | ClamAV not installed/not running/virus database missing |
| `not_implemented` | 501 | Capability for a later phase or unimplemented automatic response |
| `internal_error` | 500 | Internal error; the response includes the request ID |

## curl examples

```bash
TOKEN=$(docker compose exec -T lsec cat /data/secrets/admin.token)

curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/status
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/components
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"type":"quick","engines":["clamav"]}' http://127.0.0.1:8080/api/v1/scans
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/audits
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/audits
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/containers
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/falco
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/containers/refresh
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/yara
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/yara/packs
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"path":"/data/yara/inbox/pack.zip","activate":true,"confirm":true}' \
     http://127.0.0.1:8080/api/v1/yara/packs
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/wazuh
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/wazuh/install-plan

# Falco ingestion must use the separate token (do not use the administrator token for ingestion)
FALCO_TOKEN=$(docker compose exec -T lsec cat /data/secrets/falco.token)
curl -s -X POST -H "Authorization: Bearer $FALCO_TOKEN" -H 'Content-Type: application/json' \
     -d @falco-event.json http://127.0.0.1:8080/api/v1/integrations/falco
```
