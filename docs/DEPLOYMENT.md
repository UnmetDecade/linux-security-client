# Deployment and operations

**English** | [简体中文](DEPLOYMENT.zh-CN.md)

## 1. Prerequisites

- Linux x86_64 (this project is verified on Ubuntu 24.04)
- Docker 24+ and Docker Compose v2
- Access to the Debian package repositories (at build time) and the official ClamAV virus database mirror (at first start/update)
- If the build user is not in the `docker` group, use sudo or add the user to the `docker` group

## 2. Directories and files

```
docker-compose.yml
docker-compose.container.yml   # optional container monitoring override
packaging/Dockerfile
packaging/Dockerfile.proxy     # read-only Docker API proxy
packaging/docker_proxy.py
packaging/lsec.toml
packaging/entrypoint.sh
src/
scan-data/          # created by the deployer, mounted into the container at /scan
```

Fixed paths inside the image:

| Path | Purpose |
| --- | --- |
| `/data` | SQLite, tokens, logs, evidence, quarantined files, clamd configuration |
| `/data/secrets` | admin/viewer tokens, Falco ingestion token (0600) |
| `/data/quarantine` | Quarantined files (0700) |
| `/data/evidence` | Scan evidence (0700) |
| `/var/lib/clamav` | ClamAV virus database (named volume) |
| `/run/clamav/clamd.ctl` | clamd UNIX Socket |
| `/scan` | Scan/quarantine directory (bind mount) |
| `/etc/lsec/lsec.toml` | In-container configuration |

## 3. First deployment

```bash
# On the target host
install -d -m 0755 /opt/lsec
# Sync the project to /opt/lsec (example)
rsync -az ./ user@host:/opt/lsec/

cd /opt/lsec
mkdir -p scan-data

docker compose build
docker compose up -d
```

If the target host is slow to reach the official Debian repositories, specify a mirror (for example, USTC):

```bash
LSEC_DEBIAN_MIRROR=http://mirrors.ustc.edu.cn docker compose build
```

The first start downloads the virus database, which may take several minutes:

```bash
docker compose logs -f lsec
```

Health check:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8080/api/v1/health
```

Read the administrator token:

```bash
docker compose exec -T lsec cat /data/secrets/admin.token
```

> Do not paste the token value into chats, tickets, or logs. For rotation, see section 8.

### 3.1 Enable container monitoring (optional)

The base `docker-compose.yml` does not mount the Docker Socket. To enable the container inventory and risky-configuration checks:

```bash
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d --build
```

The override file:

- Builds and starts `lsec-docker-proxy` (`lsec-docker-proxy:0.4.0`), mounting only `/var/run/docker.sock:ro`
- The proxy allows only `GET /version`, `/info`, `/containers/json`, `/containers/<id>/json`; write methods always return 405
- The proxy sits on an `internal: true` network with no host ports; lsec reaches it through `http://docker-proxy:2375`
- `cap_drop: ALL`, `no-new-privileges`, `read_only: true`
- Sets `LSEC_CONTAINERS_ENABLED=1`, `LSEC_CONTAINERS_API_URL`, and `LSEC_FALCO_INGEST_ENABLED=1` for lsec

Once enabled, the Falco ingestion token is created at `/data/secrets/falco.token`. Read it with:

```bash
docker compose exec -T lsec cat /data/secrets/falco.token
```

> The proxy container is marked "critical" by its own checks because it mounts the Docker Socket. This is a real risk warning. Do not publish host ports for the proxy, and do not attach it to other networks.

Check the proxy:

```bash
docker compose -f docker-compose.yml -f docker-compose.container.yml ps
docker compose logs --tail=100 docker-proxy
docker compose exec -T lsec lsec containers list
docker compose exec -T lsec lsec falco status
```

### 3.2 Host deb deployment

To install the deb on Debian/Ubuntu without containers, see [Release notes](RELEASE.md) for the full steps, upgrades, rollback, and uninstall; the minimal flow is:

```bash
sha256sum -c SHA256SUMS
sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo cat /var/lib/lsec/secrets/admin.token
```

The deb installation creates the system user `lsec`, the state directory `/var/lib/lsec`, and the log directory `/var/log/lsec`, and enables a hardened `lsec.service`. ClamAV/YARA/Lynis are `Recommends`; when not installed, the component status truthfully shows "not installed" and does not block the daemon from starting.

## 4. Access methods

### Recommended: SSH tunnel

```bash
ssh -L 8080:127.0.0.1:8080 user@host
```

Open `http://127.0.0.1:8080/` locally.

### Direct access on a trusted LAN

```bash
LSEC_LISTEN_ADDR=0.0.0.0 LSEC_PORT=8080 docker compose up -d
```

Open `http://<host>:8080/`. Note: plain HTTP exposes tokens; use it only on an isolated lab network, or configure TLS.

### TLS

**Option A: reverse proxy**

- The reverse proxy listens on 443 and forwards to `127.0.0.1:8080`
- Keep the Compose port published on the loopback address
- The proxy must pass `Host` through correctly (CSRF Origin validation depends on Host matching)
- Set `client_max_body_size` ≥ 1 MB (the default request body limit)

**Option B: direct TLS in the daemon**

In `packaging/lsec.toml` (or the mounted configuration):

```toml
[server]
bind = "0.0.0.0"
port = 8443
tls_cert = "/data/tls/server.crt"
tls_key = "/data/tls/server.key"
allow_insecure_remote = false
```

Mount the certificate into `/data/tls`, adjust the port mapping, and restart the container. The minimum TLS version is 1.2, and responses carry HSTS.

## 5. Scan directories

By default, only `scan-data/` under the Compose project is mounted at `/scan`. To scan other directories, modify `docker-compose.yml`:

```yaml
volumes:
  - /srv/downloads:/scan/downloads:rw
  - /home/user/Documents:/scan/documents:ro
```

Notes:

- Quarantine/restore requires write permission (`:rw`); read-only mounts can only be scanned, not quarantined
- `allowed_roots`, `quick_scan_paths`, and `quarantine_roots` must include these paths as well (restart after modifying `packaging/lsec.toml`)
- Do not mount `/`, `/etc`, `~/.ssh`, or `/var/run/docker.sock` directly

You can also set an environment variable:

```bash
LSEC_SCAN_DIR=/srv/scan-data docker compose up -d
```

## 6. Configuration

The container configuration lives in `packaging/lsec.toml` and is copied into the image at build time. After changing it, rebuild the image or mount an override:

```yaml
volumes:
  - ./my-lsec.toml:/etc/lsec/lsec.toml:ro
```

Environment variable overrides:

| Variable | Description |
| --- | --- |
| `LSEC_DATA_DIR` | Data directory |
| `LSEC_BIND` | Listen address |
| `LSEC_PORT` | Listen port |
| `LSEC_LOG_LEVEL` | Log level |
| `LSEC_ALLOW_INSECURE_REMOTE` | Allow non-loopback listening without TLS |
| `LSEC_ADMIN_TOKEN` | Administrator token (≥16 characters) |
| `LSEC_VIEWER_TOKEN` | Read-only token (≥16 characters) |
| `LSEC_CONTAINERS_ENABLED` | Enable container monitoring (`1/true/yes`) |
| `LSEC_CONTAINERS_API_URL` | Docker API address, usually `http://docker-proxy:2375` |
| `LSEC_FALCO_INGEST_ENABLED` | Enable Falco event ingestion and generate a separate token |
| `LSEC_YARA_ENABLED` | Enable/disable YARA (`1/true/yes` or `0/false/no`) |
| `LSEC_YARA_PUBLIC_KEY` | Override the rule pack signature verification public key path |
| `LSEC_YARA_REQUIRE_SIGNATURE` | `0/false/no` disables mandatory signatures (not recommended) |
| `LSEC_WAZUH_ENABLED` | Enable local Wazuh Agent probing |
| `LSEC_WAZUH_INGEST_ENABLED` | Enable ingestion of new lines from the local `alerts.json` |
| `LSEC_WAZUH_ALERTS_PATH` | Override the local alert file path |

Container monitoring configuration section:

```toml
[containers]
enabled = false
api_url = "http://docker-proxy:2375"
timeout_seconds = 8       # 2–30
refresh_seconds = 60      # 15–3600
max_containers = 200      # 1–1000
include_stopped = true

[falco]
binary = "falco"
enabled = true
ingest_enabled = false
max_event_bytes = 32768   # 4096–262144

[yara]
enabled = true
rules_dir = "/data/yara"
inbox_dir = "/data/yara/inbox"
public_key = "/data/yara/trusted.pem"
require_signature = true
max_pack_mb = 20
max_rule_files = 200
scan_batch_files = 200
scan_timeout_seconds = 120

[wazuh]
enabled = false
install_dir = "/var/ossec"
alerts_path = "/var/ossec/logs/alerts/alerts.json"
ingest_enabled = false
poll_seconds = 30          # 5–3600
max_event_bytes = 32768
max_read_bytes = 1048576
state_dir = "/data/wazuh"
```

`api_url` accepts only a `unix://` absolute path or an `http://` address; URL user information and query parameters are not allowed. Production deployments should use the proxy; do not hand the Unix Socket directly to lsec.

Unknown configuration keys cause startup to be refused, preventing typos from silently weakening security settings.

## 7. Routine operations

```bash
docker compose ps
docker compose logs --tail=200 lsec
docker compose exec -T lsec lsec status
docker compose exec -T lsec lsec doctor
docker compose restart lsec
docker compose down            # stop and remove containers, keep named volumes
```

### Update the virus database

- The daemon checks every 30 minutes; a virus database older than 24 hours triggers freshclam
- On first start `startup_update = true`, checked after 15 seconds
- Web: Component management → ClamAV → Update virus database
- CLI: `lsec components update clamav`

A failed update keeps the old virus database, degrades the component health state, and records the real error.

### YARA rule packs

1. Generate and safeguard the signing key; put the public key at the configured `yara.public_key` (default inside the container: `/data/yara/trusted.pem`).
2. Package the rules in a trusted environment, generate `manifest.json` (including the SHA-256 of each file), generate `manifest.sig` for the manifest with the private key, and put the zip into `inbox`.
3. An administrator installs and activates it on the Web "Rule detection" page or via the CLI:

```bash
docker compose exec -T lsec lsec yara status
docker compose exec -T lsec lsec yara install /data/yara/inbox/pack.zip --confirm --activate
docker compose exec -T lsec lsec yara packs
docker compose exec -T lsec lsec scan path /scan/sample --engine yara --wait
```

4. Rule hits enter the event center (`source=yara`) and are not quarantined automatically. Deleting/switching versions likewise requires `--confirm`.

### Local Wazuh Agent (optional)

The Wazuh Agent must be installed and registered separately by an administrator on the host; lsec does not install the Agent, contact the Manager, or read key contents.

```toml
[wazuh]
enabled = true
ingest_enabled = true
alerts_path = "/var/ossec/logs/alerts/alerts.json"
state_dir = "/data/wazuh"
```

- Container deployments must mount the host's `/var/ossec/logs/alerts` read-only at the same path in the container; otherwise the alert file is invisible.
- On first enable it starts at the end of the file and does not import historical alerts; after a restart it resumes from the persisted offset.
- `lsec wazuh status` / the Web host page shows the Agent, Manager configuration, whether registration information exists, ingested events, and parse errors. `connection_verified` is always false.

### Host security audit

- Web: Host security audit → Run host audit (administrator)
- CLI: `lsec audit run --wait`, `lsec audit report`, `lsec audit history`
- Only one audit is allowed at a time; a duplicate request returns a conflict
- The audit is read-only; it does not modify accounts, permissions, services, sysctl, or the firewall
- The scope is the container-visible filesystem, network namespace, and kernel parameters; host paths that are not mounted are out of scope
- Evidence is stored in `/data/evidence/audits/<audit_id>/` (`report.json`, `lynis-report.dat`, `lynis.log`)
- Risk findings are written to the unified event center; checks that could not be executed are counted separately and not treated as risks
- Configuration section `[audit]`: `lynis_enabled`, `lynis_timeout_seconds` (10–1800), `stale_after_hours` (1–8760), `max_findings` (1–500)
- Once an audit result is older than `stale_after_hours`, its status shows as stale and it must be run again

### Container monitoring

- Web: Container protection → view state, inventory, and risk details; administrators can "Refresh now"
- CLI: `lsec containers list`, `lsec containers inspect <id>`, `lsec containers refresh`
- The background refresh runs every 60 seconds by default; a manual refresh writes the audit `container.refresh`
- Only running containers that were evaluated successfully generate configuration risk events; stopped containers remain in the inventory but generate no active events
- A failed detail read for a single container shows "could not be evaluated" and the overall state becomes `degraded`; when the API is unavailable, the last snapshot is retained and marked `stale`
- There are no stop/restart/delete container operations. When response is needed, an administrator performs it independently on the host and bears the impact
- Checks include: privileged mode, host network/PID/IPC/userns, Docker Socket mounts, sensitive directory mounts, overly broad capabilities, seccomp/AppArmor/SELinux, device passthrough, root user, and so on
- Configuration checks are heuristic rules, not vulnerability scanning; `none` only means these rules were not hit

### Falco integration

lsec does not install or start Falco, nor does it load kernel drivers. The host-side administrator must:

1. Confirm the kernel/eBPF capabilities (the Web container protection page or `lsec falco status` shows the real probe results)
2. Install Falco from a trusted source, and have the administrator load the driver
3. Configure Falco JSON output to forward to `POST http://<lsec>:8080/api/v1/integrations/falco`
4. Use `/data/secrets/falco.token` as the Bearer token; do not reuse the administrator token
5. Trigger a test rule and confirm the event enters the unified event center with container correlation information

Falco capability states:

| State | Meaning |
| --- | --- |
| `compatible` | Kernel 5.8+, BTF, and required capabilities present; still does not mean Falco is running |
| `unsupported` | Kernel below 4.14; Falco eBPF cannot be used |
| `requires_privileges` | Missing CAP_SYS_ADMIN or CAP_BPF + CAP_PERFMON |
| `requires_setup` | Missing BTF, or legacy eBPF/kernel headers required |
| `unknown` | Kernel information could not be read |

Install plan: Web "View install plan" or `lsec falco install-plan`, read-only, cannot be installed from the UI. `running_verified` is always false.

## 8. Token rotation

```bash
# Stop the service, delete the token file, then start it again (a new token is generated)
docker compose stop lsec
docker compose run --rm --entrypoint sh lsec -c 'rm -f /data/secrets/admin.token'
docker compose start lsec
docker compose exec -T lsec cat /data/secrets/admin.token
```

The Falco ingestion token is rotated separately:

```bash
docker compose stop lsec
docker compose run --rm --entrypoint sh lsec -c 'rm -f /data/secrets/falco.token'
docker compose start lsec
docker compose exec -T lsec cat /data/secrets/falco.token
# Then update the host-side Falco output configuration
```

Existing web sessions remain valid until they expire. To log out all sessions immediately:

```bash
docker compose exec -T lsec python3 -c \
  "from lsec.storage.db import Database; from lsec.storage import sessions; \
   db=Database('/data/lsec.db'); print(sessions.prune_expired(db))"
docker compose restart lsec
```

(This deletes expired sessions only; to delete all sessions, run `DELETE FROM sessions` directly.)

## 9. Backup and restore

Back up the data volume (database, tokens, logs, evidence, quarantined files):

```bash
docker compose exec -T lsec tar -czf - -C /data . > lsec-data-$(date +%F).tgz
```

Restore:

```bash
docker compose stop lsec
docker compose run --rm --entrypoint sh lsec -c 'tar -xzf - -C /data' < lsec-data-2026-11-10.tgz
docker compose start lsec
```

The virus database volume can be downloaded again and need not be backed up. Backup files contain tokens and quarantined samples and must be handled as sensitive data (0600 recommended).

## 10. Upgrade

### Containers

```bash
cd /opt/lsec
# Sync the new code
docker compose build
docker compose up -d

# If container monitoring is enabled, rebuild and start with the same set of override files:
docker compose -f docker-compose.yml -f docker-compose.container.yml build
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d
```

Database migrations run automatically at startup; before migrating, `lsec.db.pre-vN.bak` is created, and on failure the migration rolls back automatically and restores the backup. The current schema is v2.

### deb package

```bash
sudo dpkg -i lsec_0.4.0_all.deb        # or sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
```

Upgrades preserve `/etc/lsec/lsec.toml` (conffile) and the `/var/lib/lsec` data; `postinst` restarts the service only if it was already running, and a service stopped manually by the operator is not started again. If the new version fails to start, roll back in the following order:

1. `sudo systemctl stop lsec`
2. `sudo apt install ./lsec_<old version>_all.deb --allow-downgrades`
3. If a database migration has already occurred and is incompatible, restore the pre-upgrade `/var/lib/lsec/lsec.db.pre-vN.bak`
4. `sudo systemctl start lsec`, and confirm with `lsec doctor` and `journalctl -u lsec`

The rollback package must come from the same release channel and have its SHA256SUMS/GPG signatures verified.

## 11. Uninstall

### Containers

```bash
# When container monitoring is enabled, use the same set of override files to ensure the proxy container is removed too
docker compose -f docker-compose.yml -f docker-compose.container.yml down
docker volume rm lsec-data lsec-clamav-db
docker image rm lsec:0.4.0 lsec-docker-proxy:0.4.0 2>/dev/null || true
# Optional: delete the project directory and scan-data
```

### deb package

```bash
sudo apt remove lsec       # stop and disable the service, keep /var/lib/lsec, /var/log/lsec
sudo apt purge lsec        # additionally delete data, logs, configuration, system user/group
```

`remove` prints the retained data paths; confirm you no longer need the quarantined samples, evidence, and audit records before running `purge`. Deleting volumes/data directories permanently deletes events, audits, quarantined files, and tokens.

## 12. Troubleshooting

| Symptom | Check |
| --- | --- |
| Container keeps restarting | `docker compose logs lsec`; confirm no other instance holds `/data/daemon.lock` |
| 8080 unreachable | `docker compose ps`; confirm `LSEC_LISTEN_ADDR` and the port mapping; firewall |
| Scan button unavailable | Component management: check whether ClamAV is running and the virus database exists; `lsec doctor` |
| Virus database download fails | Container egress/DNS; proxy; `docker compose exec lsec freshclam --datadir=/var/lib/clamav --stdout` |
| Base image pull times out | When Docker Hub is unreachable, pull through a reachable mirror and tag it: `docker pull docker.m.daocloud.io/library/python:3.12-slim-bookworm && docker tag docker.m.daocloud.io/library/python:3.12-slim-bookworm python:3.12-slim-bookworm` |
| Debian package download is slow | Set `LSEC_DEBIAN_MIRROR=http://mirrors.ustc.edu.cn` at build time |
| clamd fails to start | Check `/data/logs/clamd-boot.log`, `/data/logs/clamd.log`; confirm the virus database exists |
| Login 401 | Use the latest `/data/secrets/admin.token`; check whether a conflicting `LSEC_ADMIN_TOKEN` is set |
| Write operation 403 | Log in again to obtain a new CSRF; check whether a reverse proxy rewrites Host/Origin |
| Quarantine returns 409 | The original path is already occupied, the file was replaced, or the quarantine area is full |
| Container page shows "not enabled" | Not started with `docker-compose.container.yml`, or `LSEC_CONTAINERS_ENABLED` did not take effect |
| Container page shows "permission denied" | The proxy cannot read `/var/run/docker.sock`; check the proxy logs and Socket permissions |
| Container page shows "unavailable" | The proxy is not running/unhealthy, `LSEC_CONTAINERS_API_URL` is wrong, or the internal network is unreachable |
| Container inventory is empty but Docker has containers | Monitoring state is `initializing/degraded` or the API read failed; wait for a refresh and check `lsec doctor` |
| Falco state is `incompatible` | The host kernel is below 4.14; this is explicitly unsupported, not a permission issue |
| Falco state is `requires_privileges` | The current lsec container process lacks CAP_SYS_ADMIN or CAP_BPF+CAP_PERFMON; Falco should run on the host |
| Falco ingestion 401 | An administrator/read-only token was used; `/data/secrets/falco.token` is required |
| Falco ingestion 429 | More than 240 requests/minute; check whether Falco output loops or repeats |
| Proxy container marked as critical risk | Expected behavior: the proxy mounts the Docker Socket; confirm this is a trusted component |
| Disk usage grows | Check `/data/evidence`, `/data/quarantine`, and log rotation; adjust `storage.*_max_mb` |

## 13. Reference deployment verification

The following results come from a reference deployment in an Ubuntu 24.04 test environment (Docker 29.0.2 / Compose v2.40.3), used to verify this document and the release process; they are not a production baseline.

| Item | Value |
| --- | --- |
| Deployment method | Docker Compose; application image plus a separate read-only Docker proxy |
| Container ports | Host `127.0.0.1:8080` → container `8080`; the proxy publishes no ports (internal network `2375` only) |
| Data | Named volumes `lsec_lsec-data` (`/data`), `lsec_lsec-clamav-db` (`/var/lib/clamav`) |
| ClamAV | 1.4.6, daily virus database updating normally |
| Lynis | 3.0.8 |
| YARA | 4.2.3 / yarac 4.2.3; signed test rule pack activated |
| Wazuh | Optional, not installed/not enabled; local Agent ingestion only, not a Manager |
| Container monitoring | `monitored`, 4 test containers / 3 running / 3 risky / 11 findings; proxy healthy, internal network only |
| Falco | Not installed; capability `requires_privileges` (the test container lacks the required capabilities); event ingestion enabled |
| Database | Schema v2, automatic backup before migration; health check passed |

When the build environment cannot reliably reach the official Debian repositories, the mirror can be switched through a build argument; the build section of `docker-compose.yml`
sets a build-time-only `network: host` to work around Docker's embedded
DNS failing to resolve the mirror on some hosts. The runtime network is unchanged; if the build host's DNS works normally, this setting can be removed.

```bash
LSEC_DEBIAN_MIRROR=http://mirror.sjtu.edu.cn docker compose build
```

The first start may take several minutes to download the virus database; when done, the daemon starts clamd automatically.

Verification results:

- `docker compose ps` is healthy; `lsec status` is "at risk" (there are unhandled high-severity events; real-time protection remains `unsupported`, as designed)
- `lsec components list`: ClamAV installed/running/ok; Lynis 3.0.8 ok; YARA 4.2.3 installed/ok; Docker installed/running/ok (through the read-only proxy); Falco, Containerd, Wazuh, and system not installed or not enabled, with clear reasons
- `lsec doctor`: 8 passed / 1 warning (non-loopback binding inside the container without TLS enabled) / 0 failed / 3 info
- Real EICAR scanning, quarantine, restore, delete, and audit all passed; see `docs/TESTING.md` for details
- The Web UI completed real scanning, quarantine, restore, delete, and event status transitions through an SSH tunnel, with no front-end errors
- The test EICAR event was marked "resolved" after acceptance; the test scan files were cleaned up
- Real host security audits (one each via CLI and Web) were both `succeeded`: 10 checks, 1 finding, 0 not executed, 3 skipped, 6 passed, Lynis hardening index 56
- The only finding was Lynis `LOGG-2138` (klogd not running), which generated a medium-severity event with source `lynis` and category `configuration`
- Suggestions are kept only in the audit evidence report and do not generate per-item events; the evidence directory is 0700, and the report and log are 0600
- viewer can read audit history and details, while starting an audit returns 403 `forbidden`
- After container monitoring is started with the override file, the proxy is healthy; there is no `/var/run/docker.sock` inside the lsec container
- The proxy has `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `Privileged=false`, no host ports, and internal network only
- The test inventory contains 4 containers; 3 are risky (scan directory bind mount, proxy Docker Socket, privileged monitoring container)
- 11 container configuration risk events were written to the unified event center; after restart, repeated risks were merged by deduplication with no duplicate flood
- The manual refresh audit `container.refresh` succeeded; a viewer refresh returned 403
- The separate Falco token really ingested 202 (created=true), and a repeated submission produced created=false; administrator-token ingestion returned 401, and the Falco token reading other APIs returned 401
- The container stop/restart/delete APIs all returned 404; proxy write methods returned 405, confirming no path exists for automatically stopping containers
- The container page and the Falco install plan were verified with Playwright (once each as administrator/read-only), with no console/page errors

YARA and unified event center verification:

- The image ships YARA/yarac 4.2.3; the signed rule pack was installed and activated with `signature_verified=true`
- All four types of invalid packs—unsigned, bad signature, rule hash mismatch, and rule compile failure—were rejected with 400 and left no installed version
- A single-file hit produced one event with `source=yara`, `category=malware`, `severity=high`; a repeated scan was merged and the source task evidence retained
- No automatic quarantine; the event description explicitly states that a rule hit is not equivalent to confirmed malware
- Real 1000-file scan: YARA `succeeded` 1000/0/0 in about 2.229 seconds; ClamAV `succeeded` 1000/0/0 in about 4.227 seconds
- Real adapter fixes: compiled rules use `yara -C`; batched files are passed through `--scan-list`

Wazuh and release verification:

- The test deployment did not install the Wazuh Agent: `installed=false`, `health_status=unavailable`, `scope=local_agent_only`, `connection_verified=false`; the UI shows "Not enabled" and "Unverified"
- Temporary local Agent alert file verification: level 10 → high / auth event; duplicate alerts merged; after restart the persisted offset prevented duplicate collection; log rotation worked normally
- It does not verify and does not claim Wazuh Manager, Agent registration, Manager API, or TLS connection capabilities
- deb 0.4.0 install, upgrade, downgrade, remove, and purge all passed; upgrade/downgrade preserved configuration and data, remove preserved data, and purge cleaned up
- The build host had no GPG private key, so this release's artifacts were unsigned and `BUILD-MANIFEST.txt` records `signed=no`
- Idle resource sampling (about 5 minutes 41 seconds, 12 samples): CPU 0.07%–0.11%, memory 981.1–981.3 MiB; see `docs/TEST-REPORT.md` for the full performance and security results

Remote browser access:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<server>
# Open http://127.0.0.1:8080/
```

If direct LAN access is genuinely required, create `.env` in the deployment directory:

```bash
printf 'LSEC_LISTEN_ADDR=0.0.0.0\n' > .env
docker compose up -d
```

This exposes tokens over plain HTTP; use it only on a controlled lab network, and prefer TLS.
