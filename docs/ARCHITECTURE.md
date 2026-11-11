# 架构设计

## 1. 形态与边界

lsec 采用 **单节点守护进程 + HTTP API + Web UI + CLI** 的形态，以容器方式部署。

原需求假定桌面 Qt GUI、Unix Socket IPC、systemd 与 deb 包；本项目按用户明确要求改为：

- 不使用 Qt，Web 管理界面由守护进程自身提供静态资源
- 容器化部署（Docker Compose），ClamAV 随镜像安装
- Daemon 与 Web UI 之间使用本机 HTTP API；CLI 复用同一 API
- lsec 进程不直接挂载 Docker Socket；可选容器监控通过独立 GET-only 代理读取
- 不提供中心管理端

这些是产品形态调整，不改变核心安全约束：唯一守护进程、统一事件模型、适配器隔离、无伪造数据、高危操作确认与审计。

## 2. 分层

```
Web UI / CLI
     │  HTTP JSON（Bearer 或会话 Cookie + CSRF）
     ▼
API 层（认证、授权、路由、静态资源、安全响应头）
     ▼
核心服务层（扫描、体检、容器监控、事件、隔离、状态、自检、更新、维护）
     ▼
适配器层（ClamAV / Lynis / Falco / YARA / Wazuh / Docker / Containerd / systemd）
     ▼
本地系统（clamd、freshclam、文件系统、SQLite、日志）
     │
     └── 可选：GET-only Docker API 代理 ── unix:///var/run/docker.sock
```

模块职责：

| 模块 | 职责 |
| --- | --- |
| `common/config.py` | TOML 严格校验、环境变量覆盖、默认安全配置 |
| `common/paths.py` | 绝对路径、越界、符号链接、普通文件校验 |
| `common/executor.py` | argv 列表执行子进程；超时杀进程组；输出截断 |
| `storage/db.py` | SQLite 连接、WAL、事务化迁移、迁移前备份、完整性检查 |
| `storage/*.py` | 组件、任务、事件、隔离、会话、设置、审计仓储 |
| `adapters/base.py` | Adapter 契约、`ProbeResult`、`Detection`、`ScanOutcome` |
| `adapters/clamav.py` | clamd UNIX Socket 协议、freshclam、扫描与哈希 |
| `adapters/misc.py` | 仅探测的组件适配器、Docker 权限区分、Containerd 探测 |
| `adapters/falco.py` | Falco 二进制/内核/eBPF 能力探测、只读安装计划 |
| `core/docker_api.py` | 仅 GET 的 Docker Engine API 客户端（http/unix） |
| `core/container_checks.py` | 纯函数容器配置风险评估 |
| `core/containers.py` | 只读容器清单、后台刷新、风险事件入库 |
| `core/falco.py` | Falco JSON 事件校验、有界归一化、去重键 |
| `core/scans.py` | 任务队列、工作线程、进度、取消、调度、证据 |
| `core/events.py` | 检测归一化、严重程度映射、去重键、事件入库 |
| `core/quarantine.py` | 隔离/恢复/删除、哈希复核、inode 替换检测、审计 |
| `core/status.py` | 汇总真实防护状态，绝不把缺失能力显示为正常 |
| `api/auth.py` | 令牌、会话、角色、登录限速、CSRF |
| `api/server.py` | HTTP 路由、访问级别、安全响应头、CSV/JSON 导出 |
| `daemon.py` | 初始化、单实例锁、后台线程、信号处理、HTTP 服务 |
| `cli/__main__.py` | 非特权 CLI 客户端 |

## 3. 关键数据模型

### SecurityEvent

统一字段：`event_id`、`timestamp`、`source`、`category`、`severity`、`title`、`description`、`host`、`target`、`evidence`、`status`、`recommended_actions`、`dedup_key`、`first_seen_at`、`last_seen_at`、`occurrences`、`source_refs`。

去重：按来源构造确定性的 `dedup_key`（例如 ClamAV 使用 `clamav|category|path|detection_name`，Wazuh 使用 Agent + 规则 + 描述 + 目标，YARA 使用规则 + 目标），整体再做 SHA-256。在去重窗口内且事件仍处于 `new/acknowledged/investigating` 时合并，累加次数、更新最近时间、保留全部来源引用（最多 10 条）与首次证据；不同来源不会互相吞并。

### ScanTask

状态机：

```
queued ──▶ running ──▶ succeeded
   │          │  └────▶ partial
   │          ├───────▶ failed
   │          └───────▶ cancel_requested ──▶ cancelled
   └──────▶ cancelled / failed
```

终态不可再次转换。守护进程重启时，遗留的 `running/cancel_requested` 任务统一标记 `failed`，不会假装仍在运行。

进度仅在文件总数已知时给出百分比；枚举失败或未知时返回 `null`，UI 显示“进度未知”。

### AuditRun

状态：`queued → running → succeeded/partial/failed`。保存范围、请求者、开始/结束时间、检查总数、发现数、未能执行数、严重程度计数、Lynis 加固指数/版本、证据路径与错误。详细检查列表与系统信息保存在 `report.json`，数据库只存有界摘要。

检查结果状态：`pass`、`finding`、`error`、`skipped`。只有 `finding` 进入事件中心；`error` 计入未能执行；`skipped` 表示当前环境无法评估（如容器内无 systemd），三者不会被混为一谈。

### ComponentStatus

`installed`、`service_status`、`health_status`、`capabilities`、`error_code`、`error_message`、`details`、`last_check_at`。

健康状态区分：`ok`、`degraded`、`unavailable`、`unknown`、`incompatible`、`check_failed`、`permission_denied`。仅“已安装”不会产生“防护正常”。

### ContainerSnapshot

内存快照（不落库）：`state`（`disabled/initializing/monitored/degraded/unavailable/permission_denied`）、`note`、`engine` 信息、容器数组、汇总、`checked_at`、`last_success_at`、`stale`、`truncated`、`inspect_errors`、范围与限制说明、事件接入计数。

单个容器包含：ID、名称、镜像、状态、时间、PID、重启数、OOM、运行用户、`privileged`、网络/PID/IPC/userns 模式、CapAdd/CapDrop、SecurityOpt、只读根文件系统、设备、挂载、端口、`findings`、`risk_level`、`risk_count`、`evaluated`、`evaluation_error`。**不保留环境变量**。

风险级别：`critical/high/medium/low/none/unknown`。缺少 `Config/HostConfig/State` 等必要字段时 `evaluated=false` 且级别为 `unknown`，绝不能当作 `none`。

### Falco 能力与事件

能力状态：`compatible`、`unsupported`、`requires_privileges`、`requires_setup`、`unknown`。`compatible` 只表示内核、BTF 与 capability 前提具备；`running_verified` 固定为 false，因为 lsec 无法确认宿主侧 Falco 进程与规则加载状态。

Falco 事件归一化为 `source=falco`、`category=runtime`，只保留有界的规则、优先级、输出、容器 ID/名称/镜像、进程字段。优先级映射：Emergency/Alert/Critical→critical，Error→high，Warning→medium，Notice→low，Informational/Debug→info；未知优先级→medium 并保留原始值。

### QuarantineItem

保存原路径、存储文件名、SHA-256、大小、检测名、引擎、关联事件、隔离者、状态（`quarantined/restored/deleted/missing`）与时间。文件本身存放在数据卷的 `quarantine/`（0700）。

### AuditRecord

记录请求 ID、操作者、客户端、动作、目标、前后状态（16 KB 截断）、是否确认、结果、错误与时间。

## 4. 扫描链路

1. API 校验角色、CSRF、任务类型、目标路径。
2. `ScanManager` 解析目标（快速扫描目录 / `/` / 自定义白名单根），探测 ClamAV 是否安装且 clamd 运行。
3. 任务写入 SQLite，工作线程取出并置为 `running`。
4. ClamAV Adapter 先遍历文件计数（用于真实进度），再逐文件通过 clamd `zSCAN path\0`（NUL 分帧）扫描。
5. 检测到 `FOUND` 时计算 SHA-256、生成 Detection，事件服务归一化/去重入库。
6. 任务结束写入统计、错误样例和证据 JSON；状态为 `succeeded/partial/failed/cancelled`。
7. 进度通过 SQLite 持久化，Web/CLI 轮询读取，不依赖内存虚构状态。

文件遍历规则：不跟随符号链接；跳过配置的目录、数据卷的隔离区与证据目录；超过大小上限的文件计入“跳过”，不计入扫描。

## 5. 主机体检链路

1. `POST /audits` 由管理员创建 `audit_runs` 记录（`queued`），服务只允许一个体检处于排队/运行状态。
2. 后台单工作线程将其置为 `running`，先执行内置只读检查，再按配置执行 Lynis。
3. 内置检查覆盖：额外 UID 0、空密码、重复 UID、敏感文件权限、SSH 显式指令、危险监听端口、传统 systemd 服务、ASLR、AppArmor/SELinux。所有文件读取基于可注入的根目录，便于单元测试。
4. 检查结果为 `pass/finding/error/skipped`。只有 `finding` 通过 `EventService.ingest_finding` 生成统一事件；`error` 计入“未能执行”，不生成风险事件。Lynis 的 `warning[]` 映射为发现，`suggestion[]` 只保存在报告中。
5. Lynis 以固定 argv 执行 `audit system --quick --no-colors --quiet`，原始报告和日志写入证据目录并收紧到 0600；解析使用稳定键 `hardening_index`、`lynis_tests_done`、`lynis_version`。
6. 汇总系统信息、检查明细、限制说明写入 `report.json`；数据库保存计数、严重程度、加固指数、证据路径与状态。
7. 状态汇总读取最近一次已完成体检，计算 `current/stale/failed/not_run`；体检发现经事件中心影响总体风险状态。
8. 守护进程重启时，残留的 `queued/running` 体检标记为 `failed` 并说明中断，不伪装为完成。

## 6. 容器监控与 Falco 链路

### 6.1 只读代理

- lsec 进程**不**挂载 `/var/run/docker.sock`。
- 可选的 `lsec-docker-proxy` 容器挂载 Socket（只读），仅转发：
  `GET /version`、`GET /info`、`GET /containers/json?all=0|1`、
  `GET /containers/<12-64 位十六进制 ID>/json`。
- 其他路径返回 403，所有非 GET 方法返回 405；响应上限 8 MB，上游超时 8 秒。
- 代理运行在 `internal: true` 网络，`cap_drop: ALL`、`no-new-privileges`、只读根文件系统，不发布宿主机端口。
- 代理仍属于高权限组件（Socket 等价 host root），因此容器检查会如实把它标记为严重风险。

### 6.2 采集与评估

1. `ContainerService` 后台线程按 `containers.refresh_seconds` 调用 Docker API；也可由管理员手动刷新（审计 `container.refresh`）。
2. 依次读取 `/version`、`/info`、容器列表，再对每个容器执行 inspect；列表数量受 `max_containers` 限制并标记截断。
3. `evaluate_container()` 是纯函数，检查特权模式、host 网络/PID/IPC/userns、Docker Socket 挂载、敏感目录挂载、过宽 capabilities、seccomp/AppArmor/SELinux、设备直通与 root 用户等。
4. 敏感路径按最长前缀匹配（如 `/etc/ssh` 命中 `/etc`），读写挂载比只读更严重；即使 Docker Socket 以只读挂载也按严重处理。
5. 单个容器详情读取失败会显示“未能评估”，不会让整次刷新失败；整体状态降级为 `degraded`。
6. 刷新失败时保留上次成功快照并标记 `stale=true`；若从未成功，则清空清单，绝不展示旧数据冒充当前状态。

### 6.3 事件关联

- 只有“运行中”且 `evaluated=true` 的容器 findings 写入统一事件中心：`source=docker`、`category=configuration`。
- 去重提示为 `<container_id>:<finding_key>`；同一进程内已上报的风险不会每轮重复创建。
- 事件目标包含容器 ID 与名称，证据包含引擎、规则、镜像、状态和有界检查详情。
- 配置风险消失后再次出现可重新合并/生成，反映真实状态变化。

### 6.4 Falco

- Adapter 读取内核版本、BTF、`/sys/fs/bpf`、tracefs、`CapEff` 与 `unprivileged_bpf_disabled`，区分不支持、权限不足、需要配置和兼容。
- Falco 缺失时组件为 `unavailable`；内核不兼容为 `incompatible`；权限不足为 `permission_denied`；前提具备仍为 `unknown` 且 `running_verified=false`。
- 安装计划只读，`installable_from_ui=false`；lsec 不安装、不启动、不加载驱动。
- 启用 `falco.ingest_enabled` 后生成独立令牌 `/data/secrets/falco.token`（0600）。该令牌只能 POST `/api/v1/integrations/falco`，不能读取任何其他 API；管理员/只读令牌也不能写入该端点。
- 事件写入前校验大小、JSON 对象、规则/输出与输出字段类型；无效容器 ID 不作为目标容器 ID 使用。

### 6.5 YARA 规则包与扫描

- 规则包格式：zip 或目录，包含 `manifest.json`（`schema_version`、`pack_id`、`version`、规则文件及 SHA-256）和可选的 `manifest.sig`（OpenSSL 分离签名）。
- 源路径必须位于 `yara.inbox_dir` 内；拒绝符号链接、zip 条目穿越、未声明文件、重复版本和超出数量/大小限制的包。
- 每个声明规则文件逐一复核 SHA-256；`require_signature=true` 时用配置的公钥验证 manifest 签名，缺公钥/签名无效直接拒绝。
- 使用 `yarac` 编译校验通过后才写入版本目录 `<rules_dir>/packs/<pack_id>/<version>/`；同版本永不覆盖。
- `state.json` 原子更新并记录激活版本；激活/删除均需管理员确认并写审计。
- 扫描时只枚举允许根目录内的普通文件，不跟随符号链接，跳过异常文件名；按文件数（`scan_batch_files`）和 128 KiB argv 预算分批调用 `yara -w -g`。
- 输出解析只接受 `规则 [标签] 目标` 形式，目标必须位于本次扫描范围内；严重程度由规则标签决定（`severity_critical/high/medium/low/info`，默认 medium）。
- 命中事件为 `source=yara`、`category=malware`，证据保留规则、标签、目标、包 ID/版本与编译规则哈希；不会自动隔离。

### 6.6 Wazuh 本地接入

- Adapter 只读探测 `wazuh-agentd`/`wazuh-control`、安装目录、`ossec.conf` 的 Manager 地址/端口、`client.keys` 是否存在与权限位；**不读取密钥内容**。
- 健康判定区分：配置禁用、未安装、配置缺失、Manager 未配置、Agent 停止、Manager 连接未验证。即使 Agent 正常运行，健康状态也是 `unknown` 且 `error_code=manager_connection_unverified`，能力状态最多为 `degraded`。
- 可选 `alerts.json` 接入由 `WazuhAlertIngester` 单线程轮询：持久化 inode 与字节偏移；首次启用从文件末尾开始，不导入历史积压；inode 变化或文件截断时重置；只处理完整行，限制单次读取与单条事件大小。
- 超大单行会持续丢弃到下一个换行，绝不把截断片段当作完整告警解析。
- 事件映射：level 12+→critical、8–11→high、4–7→medium、1–3→low、0→info；组标签映射 malware/intrusion/integrity/vulnerability/configuration，其余为 runtime。
- 事件 `source=wazuh`，`source_ref.manager_connection_verified` 固定为 false；建议动作只提示人工核对，不触发自动处置。

## 7. 隔离链路

- 要求 `confirm=true`；恢复/删除同样要求确认。
- 原路径必须是普通文件（拒绝符号链接/目录/设备/FIFO）。
- 真实路径必须位于 `response.quarantine_roots` 内；隔离区容量受 `quarantine_max_mb` 限制。
- 以 `O_NOFOLLOW` 打开源文件，哈希后复制到新文件（0600、`O_EXCL`），复核哈希。
- 删除源文件前用 `(st_dev, st_ino)` 确认路径仍指向同一文件，防止替换攻击。
- 恢复时复核存储文件哈希，原路径已存在则拒绝覆盖；写入后再次校验哈希。
- 每一步成功/失败都写审计。

## 8. 线程与并发

- `ThreadingHTTPServer` 处理并发请求，每个请求独立 SQLite 连接。
- `ScanManager` 启动 `scan.max_parallel_tasks` 个工作线程（1–4）和一个调度线程。
- 任务队列上限 50 个 `queued` 任务，超出返回冲突。
- `UpdateManager` 单飞锁，避免并发 freshclam；更新完成后用 `sigtool --info` 复核 CVD 数字签名。
- `WazuhAlertIngester` 单后台线程轮询，状态与偏移写入 0600 的 `state.json`；单次 tick 也在测试中直接调用。
- `AuditService` 单工作线程串行执行体检；创建时用锁 + 数据库状态防止并发体检。
- `ContainerService` 单后台线程定时刷新，`_refresh_lock` 防止手动刷新与定时刷新并发；快照读写使用独立锁。
- `MaintenanceService` 定期清理过期会话、终态事件、证据配额。
- 单实例由 `/data/daemon.lock` 的 `flock` 保证。

## 9. 真实性原则

- 状态汇总 `overall` 只有三种：`healthy`、`at_risk`、`protection_incomplete`。
- 容器内实时防护固定为 `unsupported`，因此总体状态不会显示“防护正常”。
- 未实现能力通过 `/capabilities` 返回 `not_implemented`，Web 页面显示说明而不是空白的“安全”页面。
- 组件探测失败显示 `check_failed`，权限不足显示 `permission_denied`，不会降级为“正常”。
- 扫描结果只来自 clamd 的真实响应；测试中的假 clamd 仅存在于 `tests/`，不进入产品镜像。
- 体检范围说明来自真实的容器探测结果；Lynis 缺失时明确标注“仅内置检查”，不会伪造加固指数或建议。
- 容器清单只来自 Docker Engine API 的真实响应；未启用、权限不足、不可用时清空或标记过期，不展示虚构容器。
- 容器检查无法读取详情时显示 `unknown`/“未能评估”，不会归为“无风险”。
- Falco 的 `compatible` 不等于运行中；`running_verified` 始终为 false，未安装/不兼容/权限不足分别显示，不伪装为已防护。
- Containerd 只报告探测结果，不把 Docker 清单冒充为 Containerd 清单。
- YARA 扫描只在规则包编译成功且存在激活版本时可用；签名未验证/公钥缺失的包不会被加载，也不会显示为“规则防护已就绪”。
- Wazuh 能力状态最多为 `degraded`，`connection_verified` 恒为 false；从未把“本地 Agent 已安装”表述为“Wazuh 完整能力”。
- `sigtool` 未安装或数据库为 `.cld` 时，签名校验结果显示“未验证/不适用”，不会显示为已通过。

## 10. 扩展点

- 新引擎实现 `Adapter` 并注册到 `ComponentManager`，事件通过统一 `EventService` 入库。
- Containerd：若后续采集清单，应复用只读代理思路，单独实现 containerd API/Socket 客户端与明确的能力状态，不得把 Docker 数据冒充为 containerd。
- 新事件来源必须提供确定性 `dedup_key`、有界证据和明确的 `source_ref`，并说明哪些能力未验证。
- 新规则/签名格式应复用 YARA 规则包的“先验证、后编译、再原子激活”流程，禁止原地覆盖已激活版本。
- 任何新增的容器操作（停止/重启/删除）都必须独立授权、说明影响、二次确认并审计；当前版本明确不提供。
- 发布流程见 `docs/RELEASE.md`：deb、源码包、SHA256SUMS 与 GPG 分离签名必须一起发布。
