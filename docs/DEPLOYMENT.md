# 部署与运维

## 1. 前提

- Linux x86_64（本项目在 Ubuntu 24.04 上验证）
- Docker 24+ 与 Docker Compose v2
- 可访问 Debian 软件源（构建时）与 ClamAV 官方病毒库镜像（首次启动/更新时）
- 如果构建用户不在 `docker` 组，需要使用 sudo 或加入 `docker` 组

## 2. 目录与文件

```
docker-compose.yml
docker-compose.container.yml   # 可选容器监控覆盖
packaging/Dockerfile
packaging/Dockerfile.proxy     # 只读 Docker API 代理
packaging/docker_proxy.py
packaging/lsec.toml
packaging/entrypoint.sh
src/
scan-data/          # 由部署者创建，挂载到容器 /scan
```

镜像内固定路径：

| 路径 | 用途 |
| --- | --- |
| `/data` | SQLite、令牌、日志、证据、隔离文件、clamd 配置 |
| `/data/secrets` | admin/viewer 令牌、Falco 接入令牌（0600） |
| `/data/quarantine` | 隔离文件（0700） |
| `/data/evidence` | 扫描证据（0700） |
| `/var/lib/clamav` | ClamAV 病毒库（命名卷） |
| `/run/clamav/clamd.ctl` | clamd UNIX Socket |
| `/scan` | 扫描/隔离目录（绑定挂载） |
| `/etc/lsec/lsec.toml` | 容器内配置 |

## 3. 首次部署

```bash
# 在目标主机上
install -d -m 0755 /opt/lsec
# 将项目同步到 /opt/lsec（示例）
rsync -az ./ user@host:/opt/lsec/

cd /opt/lsec
mkdir -p scan-data

docker compose build
docker compose up -d
```

如果目标主机访问 Debian 官方源较慢，可指定镜像（例如 USTC）：

```bash
LSEC_DEBIAN_MIRROR=http://mirrors.ustc.edu.cn docker compose build
```

首次启动会下载病毒库，可能持续数分钟：

```bash
docker compose logs -f lsec
```

健康检查：

```bash
docker compose ps
curl -fsS http://127.0.0.1:8080/api/v1/health
```

读取管理员令牌：

```bash
docker compose exec -T lsec cat /data/secrets/admin.token
```

> 令牌值不要贴到聊天、工单或日志中。需要轮换时见第 8 节。

### 3.1 启用容器监控（可选）

基础 `docker-compose.yml` 不挂载 Docker Socket。启用容器清单与危险配置检查：

```bash
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d --build
```

该覆盖文件：

- 构建并启动 `lsec-docker-proxy`（`lsec-docker-proxy:0.4.0`），只挂载 `/var/run/docker.sock:ro`
- 代理仅允许 `GET /version`、`/info`、`/containers/json`、`/containers/<id>/json`；写方法一律 405
- 代理位于 `internal: true` 网络，无宿主机端口；lsec 通过 `http://docker-proxy:2375` 访问
- `cap_drop: ALL`、`no-new-privileges`、`read_only: true`
- 为 lsec 设置 `LSEC_CONTAINERS_ENABLED=1`、`LSEC_CONTAINERS_API_URL`、`LSEC_FALCO_INGEST_ENABLED=1`

启用后 Falco 接入令牌会创建在 `/data/secrets/falco.token`。读取方式：

```bash
docker compose exec -T lsec cat /data/secrets/falco.token
```

> 代理容器会被自身检查标记为“严重”，因为它挂载了 Docker Socket。这是真实风险提示。不要给代理发布宿主机端口，也不要把它接入其他网络。

检查代理：

```bash
docker compose -f docker-compose.yml -f docker-compose.container.yml ps
docker compose logs --tail=100 docker-proxy
docker compose exec -T lsec lsec containers list
docker compose exec -T lsec lsec falco status
```

### 3.2 宿主机 deb 部署

不使用容器时，可在 Debian/Ubuntu 上安装 deb。完整步骤、升级、回滚与卸载见 [发布说明](RELEASE.md)；最小流程：

```bash
sha256sum -c SHA256SUMS
sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
sudo cat /var/lib/lsec/secrets/admin.token
```

deb 安装会创建系统用户 `lsec`、状态目录 `/var/lib/lsec`、日志目录 `/var/log/lsec`，并启用加固的 `lsec.service`。ClamAV/YARA/Lynis 为 `Recommends`，未安装时组件状态会如实显示“未安装”，不会阻止守护进程启动。

## 4. 访问方式

### 推荐：SSH 隧道

```bash
ssh -L 8080:127.0.0.1:8080 user@host
```

本地打开 `http://127.0.0.1:8080/`。

### 可信局域网直连

```bash
LSEC_LISTEN_ADDR=0.0.0.0 LSEC_PORT=8080 docker compose up -d
```

打开 `http://<host>:8080/`。注意：HTTP 明文会暴露令牌，建议只在隔离的实验网络中使用，或配置 TLS。

### TLS

**方式 A：反向代理**

- 反向代理监听 443，转发到 `127.0.0.1:8080`
- 保持 Compose 端口发布在回环地址
- 代理需正确传递 `Host`（CSRF Origin 校验依赖 Host 一致）
- 设置 `client_max_body_size` ≥ 1 MB（默认请求体上限）

**方式 B：守护进程直接 TLS**

在 `packaging/lsec.toml`（或挂载的配置）中：

```toml
[server]
bind = "0.0.0.0"
port = 8443
tls_cert = "/data/tls/server.crt"
tls_key = "/data/tls/server.key"
allow_insecure_remote = false
```

将证书挂载到 `/data/tls`，调整端口映射，重启容器。TLS 最低版本 1.2，响应带 HSTS。

## 5. 扫描目录

默认只把 Compose 项目下的 `scan-data/` 挂载到 `/scan`。要扫描其他目录，修改 `docker-compose.yml`：

```yaml
volumes:
  - /srv/downloads:/scan/downloads:rw
  - /home/user/Documents:/scan/documents:ro
```

注意：

- 隔离/恢复需要写权限（`:rw`）；只读挂载只能扫描，不能隔离
- `allowed_roots`、`quick_scan_paths`、`quarantine_roots` 需要同步包含这些路径（修改 `packaging/lsec.toml` 后重启）
- 不要把 `/`、`/etc`、`~/.ssh`、`/var/run/docker.sock` 直接挂载进来

也可以设置环境变量：

```bash
LSEC_SCAN_DIR=/srv/scan-data docker compose up -d
```

## 6. 配置

容器配置位于 `packaging/lsec.toml`，构建时复制到镜像。修改后需重建镜像或挂载覆盖：

```yaml
volumes:
  - ./my-lsec.toml:/etc/lsec/lsec.toml:ro
```

环境变量覆盖：

| 变量 | 说明 |
| --- | --- |
| `LSEC_DATA_DIR` | 数据目录 |
| `LSEC_BIND` | 监听地址 |
| `LSEC_PORT` | 监听端口 |
| `LSEC_LOG_LEVEL` | 日志级别 |
| `LSEC_ALLOW_INSECURE_REMOTE` | 允许无 TLS 的非回环监听 |
| `LSEC_ADMIN_TOKEN` | 管理员令牌（≥16 字符） |
| `LSEC_VIEWER_TOKEN` | 只读令牌（≥16 字符） |
| `LSEC_CONTAINERS_ENABLED` | 启用容器监控（`1/true/yes`） |
| `LSEC_CONTAINERS_API_URL` | Docker API 地址，通常为 `http://docker-proxy:2375` |
| `LSEC_FALCO_INGEST_ENABLED` | 启用 Falco 事件接入并生成独立令牌 |
| `LSEC_YARA_ENABLED` | 启用/禁用 YARA（`1/true/yes` 或 `0/false/no`） |
| `LSEC_YARA_PUBLIC_KEY` | 覆盖规则包验签公钥路径 |
| `LSEC_YARA_REQUIRE_SIGNATURE` | `0/false/no` 关闭强制签名（不建议） |
| `LSEC_WAZUH_ENABLED` | 启用本地 Wazuh Agent 探测 |
| `LSEC_WAZUH_INGEST_ENABLED` | 启用本地 `alerts.json` 新增行接入 |
| `LSEC_WAZUH_ALERTS_PATH` | 覆盖本地告警文件路径 |

容器监控配置节：

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

`api_url` 只接受 `unix://` 绝对路径或 `http://` 地址；不允许 URL 用户信息或查询参数。生产部署应使用代理，不建议把 Unix Socket 直接交给 lsec。

未知配置键会拒绝启动，避免拼写错误静默削弱安全设置。

## 7. 日常操作

```bash
docker compose ps
docker compose logs --tail=200 lsec
docker compose exec -T lsec lsec status
docker compose exec -T lsec lsec doctor
docker compose restart lsec
docker compose down            # 停止并删除容器，保留命名卷
```

### 更新病毒库

- 守护进程每 30 分钟检查一次；病毒库超过 24 小时会触发 freshclam
- 首次启动 `startup_update = true`，15 秒后检查
- Web：组件管理 → ClamAV → 更新病毒库
- CLI：`lsec components update clamav`

更新失败会保留旧病毒库，组件健康状态降级，并记录真实错误。

### YARA 规则包

1. 生成并保管签名密钥；把公钥放到配置的 `yara.public_key`（容器内默认 `/data/yara/trusted.pem`）。
2. 在受信环境打包规则，生成 `manifest.json`（含每个文件的 SHA-256），用私钥对 manifest 生成 `manifest.sig`，把 zip 放入 `inbox`。
3. 管理员在 Web “规则检测”页或 CLI 安装并激活：

```bash
docker compose exec -T lsec lsec yara status
docker compose exec -T lsec lsec yara install /data/yara/inbox/pack.zip --confirm --activate
docker compose exec -T lsec lsec yara packs
docker compose exec -T lsec lsec scan path /scan/sample --engine yara --wait
```

4. 规则命中进入事件中心（`source=yara`），不会自动隔离。删除/切换版本同样需要 `--confirm`。

### 本地 Wazuh Agent（可选）

Wazuh Agent 需由管理员在宿主机单独安装并注册；lsec 不安装 Agent、不联系 Manager、不读取密钥内容。

```toml
[wazuh]
enabled = true
ingest_enabled = true
alerts_path = "/var/ossec/logs/alerts/alerts.json"
state_dir = "/data/wazuh"
```

- 容器部署需要把宿主机 `/var/ossec/logs/alerts` 只读挂载到容器同一路径，否则告警文件不可见。
- 首次启用从文件末尾开始，不导入历史告警；重启后按持久化偏移继续。
- `lsec wazuh status` / Web 主机页显示 Agent、Manager 配置、注册信息是否存在、接入事件与解析错误。`connection_verified` 恒为 false。

### 主机安全体检

- Web：安全体检 → 运行主机体检（管理员）
- CLI：`lsec audit run --wait`、`lsec audit report`、`lsec audit history`
- 同一时间只允许一个体检；重复发起返回冲突
- 体检只读，不会修改账户、权限、服务、sysctl 或防火墙
- 检查范围是容器可见文件系统、网络命名空间与内核参数；未挂载的宿主机路径不在范围内
- 证据位于 `/data/evidence/audits/<audit_id>/`（`report.json`、`lynis-report.dat`、`lynis.log`）
- 风险发现写入统一事件中心；未能执行的检查单独计数，不当作风险
- 配置项 `[audit]`：`lynis_enabled`、`lynis_timeout_seconds`（10–1800）、`stale_after_hours`（1–8760）、`max_findings`（1–500）
- 体检结果超过 `stale_after_hours` 后状态显示为过期，需要重新运行

### 容器监控

- Web：容器防护 → 查看状态、清单、风险详情；管理员可“立即刷新”
- CLI：`lsec containers list`、`lsec containers inspect <id>`、`lsec containers refresh`
- 后台默认每 60 秒刷新；手动刷新会写审计 `container.refresh`
- 只有运行中且评估成功的容器生成配置风险事件；停止的容器仍显示在清单中但不产生活动事件
- 单个容器详情失败显示“未能评估”，整体 `degraded`；API 不可用时保留上次快照并标记 `stale`
- 没有停止/重启/删除容器操作。需要处置时由管理员在宿主机独立执行，并自行承担影响
- 检查项包括：特权模式、host 网络/PID/IPC/userns、Docker Socket 挂载、敏感目录挂载、过宽 capabilities、seccomp/AppArmor/SELinux、设备直通、root 用户等
- 配置检查是启发式规则，不是漏洞扫描；`none` 只表示未命中这些规则

### Falco 接入

lsec 不安装、不启动 Falco，也不加载内核驱动。宿主侧管理员需要：

1. 确认内核/eBPF 能力（Web 容器防护页或 `lsec falco status` 会显示真实探测结果）
2. 从受信来源安装 Falco，并由管理员加载驱动
3. 配置 Falco JSON 输出，转发到 `POST http://<lsec>:8080/api/v1/integrations/falco`
4. 使用 `/data/secrets/falco.token` 作为 Bearer 令牌；不要复用管理员令牌
5. 触发测试规则，确认事件进入统一事件中心并带容器关联信息

Falco 能力状态：

| 状态 | 含义 |
| --- | --- |
| `compatible` | 内核 5.8+、BTF 与所需 capability 具备；仍不代表 Falco 正在运行 |
| `unsupported` | 内核低于 4.14，无法使用 Falco eBPF |
| `requires_privileges` | 缺少 CAP_SYS_ADMIN 或 CAP_BPF + CAP_PERFMON |
| `requires_setup` | 缺少 BTF，或需要 legacy eBPF/内核头文件 |
| `unknown` | 无法读取内核信息 |

安装计划：Web “查看安装计划”或 `lsec falco install-plan`，只读，不能从界面安装。`running_verified` 始终为 false。

## 8. 令牌轮换

```bash
# 停止服务，删除令牌文件，再启动（会生成新令牌）
docker compose stop lsec
docker compose run --rm --entrypoint sh lsec -c 'rm -f /data/secrets/admin.token'
docker compose start lsec
docker compose exec -T lsec cat /data/secrets/admin.token
```

Falco 接入令牌独立轮换：

```bash
docker compose stop lsec
docker compose run --rm --entrypoint sh lsec -c 'rm -f /data/secrets/falco.token'
docker compose start lsec
docker compose exec -T lsec cat /data/secrets/falco.token
# 然后更新宿主侧 Falco 输出配置
```

已有 Web 会话仍然有效直到过期。需要立即注销全部会话时：

```bash
docker compose exec -T lsec python3 -c \
  "from lsec.storage.db import Database; from lsec.storage import sessions; \
   db=Database('/data/lsec.db'); print(sessions.prune_expired(db))"
docker compose restart lsec
```

（这会删除已过期会话；若要删除全部会话，可直接执行 `DELETE FROM sessions`。）

## 9. 备份与恢复

备份数据卷（数据库、令牌、日志、证据、隔离文件）：

```bash
docker compose exec -T lsec tar -czf - -C /data . > lsec-data-$(date +%F).tgz
```

恢复：

```bash
docker compose stop lsec
docker compose run --rm --entrypoint sh lsec -c 'tar -xzf - -C /data' < lsec-data-2026-11-10.tgz
docker compose start lsec
```

病毒库卷可重新下载，不必备份。备份文件包含令牌和隔离样本，必须按敏感数据保管（建议 0600）。

## 10. 升级

### 容器

```bash
cd /opt/lsec
# 同步新代码
docker compose build
docker compose up -d

# 如启用了容器监控，使用同一组覆盖文件重建与启动：
docker compose -f docker-compose.yml -f docker-compose.container.yml build
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d
```

数据库迁移在启动时自动执行；迁移前会创建 `lsec.db.pre-vN.bak`，失败时自动回滚并恢复备份。当前 schema 为 v2。

### deb 包

```bash
sudo dpkg -i lsec_0.4.0_all.deb        # 或 sudo apt install ./lsec_0.4.0_all.deb
sudo systemctl status lsec
```

升级会保留 `/etc/lsec/lsec.toml`（conffile）与 `/var/lib/lsec` 数据；`postinst` 只在服务原本运行时重启它，操作员手动停止的服务不会被重新拉起。若新版本启动失败，按以下顺序回滚：

1. `sudo systemctl stop lsec`
2. `sudo apt install ./lsec_<旧版本>_all.deb --allow-downgrades`
3. 如果数据库迁移已发生且不兼容，恢复升级前的 `/var/lib/lsec/lsec.db.pre-vN.bak`
4. `sudo systemctl start lsec`，用 `lsec doctor` 与 `journalctl -u lsec` 确认

回滚包必须来自同一发布渠道并校验 SHA256SUMS/GPG 签名。

## 11. 卸载

### 容器

```bash
# 启用容器监控时使用同一组覆盖文件，确保代理容器也被删除
docker compose -f docker-compose.yml -f docker-compose.container.yml down
docker volume rm lsec-data lsec-clamav-db
docker image rm lsec:0.4.0 lsec-docker-proxy:0.4.0 2>/dev/null || true
# 可选：删除项目目录与 scan-data
```

### deb 包

```bash
sudo apt remove lsec       # 停止并禁用服务，保留 /var/lib/lsec、/var/log/lsec
sudo apt purge lsec        # 额外删除数据、日志、配置、系统用户/组
```

`remove` 会打印保留的数据路径；确认不再需要隔离样本、证据与审计后再执行 `purge`。删除卷/数据目录会永久删除事件、审计、隔离文件和令牌。

## 12. 故障排查

| 现象 | 检查 |
| --- | --- |
| 容器不断重启 | `docker compose logs lsec`；确认没有其他实例占用 `/data/daemon.lock` |
| 8080 无法访问 | `docker compose ps`；确认 `LSEC_LISTEN_ADDR` 与端口映射；防火墙 |
| 扫描按钮不可用 | 组件管理查看 ClamAV 是否运行、病毒库是否存在；`lsec doctor` |
| 病毒库下载失败 | 容器出网/DNS；代理；`docker compose exec lsec freshclam --datadir=/var/lib/clamav --stdout` |
| 拉取基础镜像超时 | Docker Hub 不可达时，可通过可达镜像拉取后打标签：`docker pull docker.m.daocloud.io/library/python:3.12-slim-bookworm && docker tag docker.m.daocloud.io/library/python:3.12-slim-bookworm python:3.12-slim-bookworm` |
| Debian 包下载慢 | 构建时设置 `LSEC_DEBIAN_MIRROR=http://mirrors.ustc.edu.cn` |
| clamd 启动失败 | 查看 `/data/logs/clamd-boot.log`、`/data/logs/clamd.log`；确认病毒库存在 |
| 登录 401 | 使用最新 `/data/secrets/admin.token`；检查是否设置了冲突的 `LSEC_ADMIN_TOKEN` |
| 写操作 403 | 重新登录获取新 CSRF；检查反向代理是否改写了 Host/Origin |
| 隔离返回 409 | 原路径已被占用、文件被替换、或隔离区容量已满 |
| 容器页显示“未启用” | 未使用 `docker-compose.container.yml` 启动，或 `LSEC_CONTAINERS_ENABLED` 未生效 |
| 容器页显示“权限不足” | 代理无法读取 `/var/run/docker.sock`；检查代理日志与 Socket 权限 |
| 容器页显示“不可用” | 代理未启动/不健康、`LSEC_CONTAINERS_API_URL` 错误、或内部网络未连通 |
| 容器清单为空但 Docker 有容器 | 监控状态为 `initializing/degraded` 或 API 读取失败；等待刷新并查看 `lsec doctor` |
| Falco 状态为 `incompatible` | 宿主内核低于 4.14；这是明确不支持，不是权限问题 |
| Falco 状态为 `requires_privileges` | 当前 lsec 容器进程缺少 CAP_SYS_ADMIN 或 CAP_BPF+CAP_PERFMON；Falco 应在宿主侧运行 |
| Falco 接入 401 | 使用了管理员/只读令牌；必须使用 `/data/secrets/falco.token` |
| Falco 接入 429 | 超过 240 次/分钟；检查 Falco 输出是否循环或重复 |
| 代理容器被标为严重风险 | 预期行为：代理挂载了 Docker Socket；确认这是受信任组件 |
| 磁盘占用增长 | 检查 `/data/evidence`、`/data/quarantine`、日志轮转；调整 `storage.*_max_mb` |

## 13. 参考部署验证

以下结果来自 Ubuntu 24.04 测试环境（Docker 29.0.2 / Compose v2.40.3）的参考部署，用于验证本文档与发布流程，不是生产环境基线。

| 项目 | 值 |
| --- | --- |
| 部署方式 | Docker Compose；应用镜像与独立只读 Docker 代理 |
| 容器端口 | 宿主机 `127.0.0.1:8080` → 容器 `8080`；代理不发布端口（仅内部网络 `2375`） |
| 数据 | 命名卷 `lsec_lsec-data`（`/data`）、`lsec_lsec-clamav-db`（`/var/lib/clamav`） |
| ClamAV | 1.4.6，daily 病毒库正常更新 |
| Lynis | 3.0.8 |
| YARA | 4.2.3 / yarac 4.2.3；签名测试规则包已激活 |
| Wazuh | 可选，未安装/未启用；仅本地 Agent 接入，不是 Manager |
| 容器监控 | `monitored`，4 个测试容器 / 运行中 3 / 风险 3 / 11 项发现；代理 healthy，仅内部网络 |
| Falco | 未安装；能力 `requires_privileges`（测试容器缺少所需 capability）；事件接入已启用 |
| 数据库 | schema v2，迁移前自动备份；健康检查通过 |

构建环境无法稳定访问 Debian 官方源时，可通过构建参数切换镜像；`docker-compose.yml`
的构建段设置了仅构建期生效的 `network: host`，用于绕过部分主机上 Docker 内嵌
DNS 无法解析镜像站的问题。运行期网络不变；若构建主机 DNS 正常，可删除该设置。

```bash
LSEC_DEBIAN_MIRROR=http://mirror.sjtu.edu.cn docker compose build
```

首次启动下载病毒库可能需要数分钟，完成后守护进程自动启动 clamd。

验证结果：

- `docker compose ps` 为 healthy；`lsec status` 为“存在风险”（存在未处理的高危事件；实时防护仍为 `unsupported`，符合设计）
- `lsec components list`：ClamAV installed/running/ok；Lynis 3.0.8 ok；YARA 4.2.3 installed/ok；Docker installed/running/ok（经只读代理）；Falco、Containerd、Wazuh、system 未安装或未启用，原因明确
- `lsec doctor`：8 通过 / 1 警告（容器内绑定非回环地址且未启用 TLS）/ 0 失败 / 3 信息
- EICAR 真实扫描、隔离、恢复、删除、审计全部通过，详见 `docs/TESTING.md`
- Web UI 通过 SSH 隧道完成真实扫描、隔离、恢复、删除与事件状态流转，无前端错误
- 测试 EICAR 事件在验收后标记“已解决”；测试扫描文件已清理
- 真实主机体检（CLI 与 Web 各一次）均为 `succeeded`：检查 10、发现 1、未能执行 0、跳过 3、通过 6，Lynis 加固指数 56
- 唯一发现为 Lynis `LOGG-2138`（klogd 未运行），已生成中危事件，来源 `lynis`、类别 `configuration`
- 建议仅保存在体检证据报告中，不逐条生成事件；证据目录 0700，报告与日志 0600
- viewer 可读取体检历史与详情，发起体检返回 403 `forbidden`
- 容器监控使用覆盖文件启动后代理 healthy；lsec 容器内无 `/var/run/docker.sock`
- 代理 `ReadonlyRootfs=true`、`CapDrop=[ALL]`、`Privileged=false`、无宿主端口、仅内部网络
- 测试清单包含 4 个容器；风险容器 3 个（扫描目录绑定挂载、代理 Docker Socket、特权监控容器）
- 11 条容器配置风险事件写入统一事件中心；重启后重复风险按去重合并，没有重复洪泛
- 手动刷新审计 `container.refresh` 成功；viewer 刷新 403
- Falco 独立令牌真实接入 202（created=true），重复提交 created=false；管理员令牌接入 401，Falco 令牌读取其他 API 401
- 容器 stop/restart/delete API 均 404；代理 POST 写方法 405，确认不存在自动停止容器路径
- 容器页与 Falco 安装计划通过 Playwright 验证（管理员/只读各一次），无 console/page error

YARA 与统一事件中心验证：

- 镜像内置 YARA/yarac 4.2.3；签名规则包安装并激活，`signature_verified=true`
- 未签名、签名错误、规则哈希不符、规则编译失败四类非法包全部 400 拒绝，未留下已安装版本
- 单文件命中产生 1 条 `source=yara`、`category=malware`、`severity=high` 事件；重复扫描合并并保留来源任务证据
- 无自动隔离；事件说明明确规则命中不等同于已确认恶意软件
- 真实 1000 文件扫描：YARA `succeeded` 1000/0/0，约 2.229 秒；ClamAV `succeeded` 1000/0/0，约 4.227 秒
- 真实适配修复：编译规则使用 `yara -C`；批量文件通过 `--scan-list` 传入

Wazuh 与发布验证：

- 测试部署未安装 Wazuh Agent：`installed=false`、`health_status=unavailable`、`scope=local_agent_only`、`connection_verified=false`，UI 显示 `未启用`、`未验证`
- 临时本地 Agent 告警文件验证：level 10 → high / auth 事件；重复告警合并；重启后持久化偏移阻止重复采集；日志轮转正常
- 未验证也不声称 Wazuh Manager、Agent 注册、Manager API 或 TLS 连接能力
- deb 0.4.0 安装、升级、降级、remove、purge 全流程通过；升级/降级保留配置与数据，remove 保留数据，purge 清理
- 构建主机无 GPG 私钥，本次发布产物未签名，`BUILD-MANIFEST.txt` 记录 `signed=no`
- 空闲资源采样（约 5 分 41 秒，12 次）：CPU 0.07%–0.11%，内存 981.1–981.3 MiB；完整性能与安全结果见 `docs/TEST-REPORT.md`

远程浏览器使用：

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<server>
# 打开 http://127.0.0.1:8080/
```

如确需局域网直连，在部署目录创建 `.env`：

```bash
printf 'LSEC_LISTEN_ADDR=0.0.0.0\n' > .env
docker compose up -d
```

这会以明文 HTTP 暴露令牌，仅建议在受控实验网络使用，并优先配置 TLS。
