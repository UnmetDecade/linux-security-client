# Release, installation, upgrade, and rollback

**English** | [简体中文](RELEASE.zh-CN.md)

This document covers the deb artifacts, host installation, upgrade, rollback, and uninstall for lsec 0.4.0. For container deployment, see [Deployment and operations](DEPLOYMENT.md).

## 1. Release artifacts

`scripts/build-release.sh` produces the following on a Debian/Ubuntu build machine:

| File | Description |
| --- | --- |
| `dist/lsec_<version>_all.deb` | Architecture-independent deb package (Python standard library, no third-party dependencies) |
| `dist/lsec-<version>-source.tar.gz` | Corresponding source package (src/tests/docs/scripts/packaging/Compose/README/LICENSE/SECURITY) |
| `dist/SHA256SUMS` | SHA-256 of the two files above |
| `dist/lsec_<version>_all.deb.asc` | Optional, detached GPG signature of the deb |
| `dist/SHA256SUMS.asc` | Optional, detached GPG signature of SHA256SUMS |
| `dist/BUILD-MANIFEST.txt` | Version, build time, platform, Python/dpkg versions, whether signed |

Build:

```bash
scripts/build-release.sh                       # unsigned
scripts/build-release.sh --sign-key <KEYID>    # detached GPG signature
# or
LSEC_GPG_KEY=<KEYID> scripts/build-release.sh
```

Signatures are self-checked immediately at build time with `gpg --verify`; the build environment's private key never enters the release artifacts.

Verify:

```bash
scripts/verify-release.sh dist
sha256sum -c dist/SHA256SUMS
gpg --verify dist/SHA256SUMS.asc dist/SHA256SUMS
gpg --verify dist/lsec_0.4.0_all.deb.asc dist/lsec_0.4.0_all.deb
dpkg-deb --info dist/lsec_0.4.0_all.deb
```

> When no signing key is provided, `BUILD-MANIFEST.txt` records `signed=no`, and `verify-release.sh` explicitly reports that the build is unsigned. Do not distribute an unsigned build as a trusted release.

## 2. Package contents

| Path | Description |
| --- | --- |
| `/usr/lib/lsec/src/lsec/` | Python application |
| `/usr/bin/lsec` | CLI (sets `PYTHONDONTWRITEBYTECODE=1`, writes no `__pycache__` to `/usr`) |
| `/usr/bin/lsec-daemon` | Daemon launcher |
| `/etc/lsec/lsec.toml` | Default configuration, a dpkg conffile (upgrades do not overwrite administrator changes) |
| `/lib/systemd/system/lsec.service` | Hardened systemd unit |
| `/usr/share/doc/lsec/` | README, docs, copyright |

Dependencies:

- `Depends`: `python3 (>= 3.10)`, `adduser`
- `Recommends`: `clamav`, `clamav-daemon`, `clamav-freshclam`, `yara`, `lynis`
- `Suggests`: `wazuh-agent`

When ClamAV/YARA/Lynis are not installed, the daemon still starts, and the component page and `lsec doctor` show "not installed/unavailable" rather than pretending to be protected.

## 3. First installation

```bash
sha256sum -c SHA256SUMS
sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo journalctl -u lsec -n 100 --no-pager
sudo cat /var/lib/lsec/secrets/admin.token
```

The installation scripts will:

1. Create the system user/group `lsec` (shell `nologin`, home directory `/var/lib/lsec`)
2. Create `/var/lib/lsec` (0750), `secrets/evidence/quarantine` (0700), `clamav/`, `yara/inbox`, `wazuh/`, `/var/log/lsec`, `/run/lsec`
3. Enable and start `lsec.service`

After the first start, `startup_update=true` checks the virus database after about 15 seconds; if ClamAV is not installed or the database is missing, `freshclam` starts downloading (tens to hundreds of MB, depending on the network). The daemon runs normally during the download, and the status shows the database as missing/updating rather than "protection normal".

Access: open `http://127.0.0.1:8080/` in a browser, or use an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 user@host
```

For token rotation, see [Deployment and operations](DEPLOYMENT.md) section 8. Token files have mode 0600 and require root/lsec privileges to read.

### Boundaries of the systemd unit

- `User=lsec`, `CapabilityBoundingSet=` (empty), `NoNewPrivileges=yes`
- `ProtectSystem=strict`, with only `/var/lib/lsec`, `/var/log/lsec`, and `/run/lsec` writable
- `ProtectHome=read-only`: `/home` can be read for scanning but not modified
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- `UMask=0077`, `PYTHONDONTWRITEBYTECODE=1`
- No kernel capabilities required for real-time protection are granted; container/fanotify real-time protection remains `unsupported`

To expand the scan scope, modify `scan.allowed_roots` and `response.quarantine_roots` in `/etc/lsec/lsec.toml`, then run `sudo systemctl restart lsec`. Do not grant the service write permissions by loosening anything other than systemd `ProtectHome`.

## 4. Upgrade

```bash
sha256sum -c SHA256SUMS
sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo lsec doctor
```

- Data and configuration are preserved: `/var/lib/lsec`, `/var/log/lsec`, `/etc/lsec/lsec.toml` (conffile).
- During an upgrade, `postinst` runs `try-restart` only for a service that was already running; a service stopped manually by an administrator stays stopped.
- Database migrations run when the daemon starts; `lsec.db.pre-vN.bak` is created before migrating, and a failure rolls back. 0.4.0 adds no migrations, and the schema remains v2.
- If the service fails to start after an upgrade: check `journalctl -u lsec` first; do not delete `/var/lib/lsec`.
- Upgrades do not automatically install new components from `Recommends`; when needed, explicitly run `sudo apt install clamav clamav-daemon clamav-freshclam yara lynis`.

## 5. Rollback

1. Record the current version and the failure symptom:

```bash
lsec --version
journalctl -u lsec -n 200 --no-pager
```

2. Stop the service:

```bash
sudo systemctl stop lsec
```

3. Install the old version package still in the release channel (SHA256SUMS / GPG must be verified):

```bash
sudo apt install ./lsec_<old>_all.deb --allow-downgrades
```

4. If the new version has already run a database migration and the old version is incompatible, restore the pre-upgrade backup:

```bash
sudo cp -a /var/lib/lsec/lsec.db.pre-vN.bak /var/lib/lsec/lsec.db
# Also check for leftover -wal/-shm files; remove them with the service stopped if necessary
```

5. Start and confirm:

```bash
sudo systemctl start lsec
sudo lsec doctor
```

Rollback does not delete events, evidence, or quarantined files; if a YARA rule pack that only the new version supports was used, the old version may be unable to read it, and the rules directory shows a status error rather than pretending to be normal.

## 6. Uninstall

```bash
sudo apt remove lsec
```

`remove` stops and disables the service and preserves:

- `/var/lib/lsec` (database, tokens, evidence, quarantine, ClamAV database, YARA rules, Wazuh offset)
- `/var/log/lsec`
- `/etc/lsec/lsec.toml`

After confirming they are no longer needed, clean up completely:

```bash
sudo apt purge lsec
```

`purge` additionally deletes the above data/logs/configuration and the `lsec` system user and group. **This step is irreversible**; quarantined samples and audit records are lost permanently.

## 7. Service diagnostics

```bash
sudo systemctl status lsec
sudo journalctl -u lsec -f
sudo lsec status
sudo lsec doctor
sudo lsec components list
sudo ss -ltnp | grep 8080
```

Common issues:

| Symptom | Diagnosis |
| --- | --- |
| Service fails to start | `journalctl -u lsec`; a misspelled configuration key causes startup to be refused |
| Port already in use | Change `server.port`; or stop the conflicting service |
| Cannot read the scan directory | `ProtectHome=read-only` allows reading; confirm directory permissions and `scan.allowed_roots` |
| ClamAV not installed/virus database missing | `sudo apt install clamav clamav-daemon clamav-freshclam`, then trigger an update in the Web/CLI |
| YARA not ready | Requires an activated rule pack that passed verification; check the reason with `lsec yara status` |
| Wazuh degraded | Local Agent not installed/not running/Manager not configured or connection unverified; all are expected states |
| Signature shows unverified | `sigtool` is missing or the database is `.cld`; install `clamav` and update again |
