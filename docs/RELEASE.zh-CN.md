# 发布、安装、升级与回滚

[English](RELEASE.md) | **简体中文**

本文覆盖 lsec 0.4.0 的 deb 发布物、宿主机安装、升级、回滚与卸载。容器部署见 [部署与运维](DEPLOYMENT.zh-CN.md)。

## 1. 发布物

`scripts/build-release.sh` 在 Debian/Ubuntu 构建机上生成：

| 文件 | 说明 |
| --- | --- |
| `dist/lsec_<version>_all.deb` | 架构无关的 deb 包（Python 标准库，无第三方依赖） |
| `dist/lsec-<version>-source.tar.gz` | 对应源码包（src/tests/docs/scripts/packaging/Compose/README/LICENSE/SECURITY） |
| `dist/SHA256SUMS` | 上述两个文件的 SHA-256 |
| `dist/lsec_<version>_all.deb.asc` | 可选，deb 的 GPG 分离签名 |
| `dist/SHA256SUMS.asc` | 可选，SHA256SUMS 的 GPG 分离签名 |
| `dist/BUILD-MANIFEST.txt` | 版本、构建时间、平台、Python/dpkg 版本、是否签名 |

构建：

```bash
scripts/build-release.sh                       # 不签名
scripts/build-release.sh --sign-key <KEYID>    # GPG 分离签名
# 或
LSEC_GPG_KEY=<KEYID> scripts/build-release.sh
```

签名在构建时立即用 `gpg --verify` 自检；构建环境的私钥不会进入发布物。

校验：

```bash
scripts/verify-release.sh dist
sha256sum -c dist/SHA256SUMS
gpg --verify dist/SHA256SUMS.asc dist/SHA256SUMS
gpg --verify dist/lsec_0.4.0_all.deb.asc dist/lsec_0.4.0_all.deb
dpkg-deb --info dist/lsec_0.4.0_all.deb
```

> 未提供签名密钥时，`BUILD-MANIFEST.txt` 会记录 `signed=no`，`verify-release.sh` 会明确提示未签名。不要把未签名构建当作可信发布物分发。

### 自动发布

推送匹配 `v*` 的 tag 后，`.github/workflows/ci.yml` 中的 `release` job 会在所有检查
通过后运行：使用无签名密钥的方式构建 deb 与源码归档，并自动生成发布说明上传：

```bash
git tag -a v0.4.0 -m "v0.4.0"
git push origin v0.4.0
```

CI 不持有 GPG 私钥。若发布需要签名，请在可信机器上用 `--sign-key` 构建并签名，
再把分离签名附加到 GitHub Release。tag 规则集会阻止后续删除或强推发布 tag。

## 2. 包内容

| 路径 | 说明 |
| --- | --- |
| `/usr/lib/lsec/src/lsec/` | Python 应用 |
| `/usr/bin/lsec` | CLI（设置 `PYTHONDONTWRITEBYTECODE=1`，不向 `/usr` 写 `__pycache__`） |
| `/usr/bin/lsec-daemon` | 守护进程启动器 |
| `/etc/lsec/lsec.toml` | 默认配置，dpkg conffile（升级不会覆盖管理员修改） |
| `/lib/systemd/system/lsec.service` | 加固的 systemd 单元 |
| `/usr/share/doc/lsec/` | README、docs、版权 |

依赖：

- `Depends`: `python3 (>= 3.10)`、`adduser`
- `Recommends`: `clamav`、`clamav-daemon`、`clamav-freshclam`、`yara`、`lynis`
- `Suggests`: `wazuh-agent`

未安装 ClamAV/YARA/Lynis 时守护进程仍会启动，组件页与 `lsec doctor` 会显示“未安装/不可用”，不会伪装成已防护。

## 3. 首次安装

```bash
sha256sum -c SHA256SUMS
sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo journalctl -u lsec -n 100 --no-pager
sudo cat /var/lib/lsec/secrets/admin.token
```

安装脚本会：

1. 创建系统用户/组 `lsec`（shell 为 `nologin`，家目录 `/var/lib/lsec`）
2. 创建 `/var/lib/lsec`（0750）、`secrets/evidence/quarantine`（0700）、`clamav/`、`yara/inbox`、`wazuh/`、`/var/log/lsec`、`/run/lsec`
3. 启用并启动 `lsec.service`

首次启动后 `startup_update=true` 会在约 15 秒后检查病毒库；若未安装或病毒库缺失，`freshclam` 会开始下载（数十至上百 MB，取决于网络）。下载期间守护进程正常运行，状态显示病毒库缺失/更新中，不会显示“防护正常”。

访问：浏览器打开 `http://127.0.0.1:8080/`，或使用 SSH 隧道：

```bash
ssh -L 8080:127.0.0.1:8080 user@host
```

令牌轮换见 [部署与运维](DEPLOYMENT.zh-CN.md) 第 8 节。令牌文件权限为 0600，读取需要 root/lsec 权限。

### systemd 单元的边界

- `User=lsec`、`CapabilityBoundingSet=`（空）、`NoNewPrivileges=yes`
- `ProtectSystem=strict`，仅 `/var/lib/lsec`、`/var/log/lsec`、`/run/lsec` 可写
- `ProtectHome=read-only`：可读取 `/home` 做扫描，但不能修改
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- `UMask=0077`、`PYTHONDONTWRITEBYTECODE=1`
- 不授予实时防护所需的内核能力；容器/fanotify 实时防护仍为 `unsupported`

如需扩大扫描范围，修改 `/etc/lsec/lsec.toml` 的 `scan.allowed_roots` 与 `response.quarantine_roots`，然后 `sudo systemctl restart lsec`。不要通过放宽 systemd `ProtectHome` 以外的方式给服务授予写权限。

## 4. 升级

```bash
sha256sum -c SHA256SUMS
sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo lsec doctor
```

- 数据与配置保留：`/var/lib/lsec`、`/var/log/lsec`、`/etc/lsec/lsec.toml`（conffile）。
- `postinst` 在升级时只对原本运行中的服务执行 `try-restart`；管理员手动停止的服务保持停止。
- 数据库迁移在守护进程启动时执行；迁移前生成 `lsec.db.pre-vN.bak`，失败会回滚。0.4.0 未新增迁移，schema 仍为 v2。
- 若升级后服务无法启动：先看 `journalctl -u lsec`；不要删除 `/var/lib/lsec`。
- 升级不会自动安装 `Recommends` 中的新组件；需要时显式执行 `sudo apt install clamav clamav-daemon clamav-freshclam yara lynis`。

## 5. 回滚

1. 记录当前版本与失败现象：

```bash
lsec --version
journalctl -u lsec -n 200 --no-pager
```

2. 停止服务：

```bash
sudo systemctl stop lsec
```

3. 安装仍在发布渠道中的旧版本包（必须校验 SHA256SUMS / GPG）：

```bash
sudo apt install ./lsec_<old>_all.deb --allow-downgrades
```

4. 如新版本已执行数据库迁移且旧版不兼容，恢复升级前备份：

```bash
sudo cp -a /var/lib/lsec/lsec.db.pre-vN.bak /var/lib/lsec/lsec.db
# 同时检查 -wal/-shm 残留；必要时在服务停止状态下移除
```

5. 启动并确认：

```bash
sudo systemctl start lsec
sudo lsec doctor
```

回滚不会删除事件、证据或隔离文件；如使用了新版本才有的 YARA 规则包，旧版本可能无法读取，规则目录会显示状态错误而不是假装正常。

## 6. 卸载

```bash
sudo apt remove lsec
```

`remove` 会停止并禁用服务，保留：

- `/var/lib/lsec`（数据库、令牌、证据、隔离区、ClamAV 库、YARA 规则、Wazuh 偏移）
- `/var/log/lsec`
- `/etc/lsec/lsec.toml`

确认不再需要后彻底清理：

```bash
sudo apt purge lsec
```

`purge` 额外删除上述数据/日志/配置以及 `lsec` 系统用户和组。**这一步不可恢复**，隔离样本与审计记录会永久丢失。

## 7. 服务诊断

```bash
sudo systemctl status lsec
sudo journalctl -u lsec -f
sudo lsec status
sudo lsec doctor
sudo lsec components list
sudo ss -ltnp | grep 8080
```

常见问题：

| 现象 | 排查 |
| --- | --- |
| 服务启动失败 | `journalctl -u lsec`；配置键拼写错误会导致拒绝启动 |
| 端口被占用 | 修改 `server.port`；或停止冲突服务 |
| 无法读取扫描目录 | `ProtectHome=read-only` 允许读取；确认目录权限与 `scan.allowed_roots` |
| ClamAV 未安装/病毒库缺失 | `sudo apt install clamav clamav-daemon clamav-freshclam`，然后在 Web/CLI 触发更新 |
| YARA 未就绪 | 需要激活且校验通过的规则包；`lsec yara status` 查看原因 |
| Wazuh 降级 | 本地 Agent 未安装/未运行/Manager 未配置或连接未验证，均为预期状态 |
| 签名显示未验证 | `sigtool` 缺失或数据库为 `.cld`；安装 `clamav` 后重新更新 |
