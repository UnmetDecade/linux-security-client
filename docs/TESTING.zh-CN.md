# 测试说明

[English](TESTING.md) | **简体中文**

## 1. 运行

无需安装第三方 Python 包（仅标准库）：

```bash
./scripts/test.sh
# 等价于
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

要求 Python 3.11+（使用 `tomllib`、`X | None` 类型语法）。

Web 资源、翻译表与文档链接有一项独立的零依赖检查：

```bash
node scripts/check-web.js
```

## 2. 覆盖范围

CI 会统计 Python 覆盖率，并强制 64% 全局门槛；HTTP API、认证、事件映射、主机体检、
YARA 校验、隔离区、Docker API 客户端与存储还有更严格的单文件门槛：

```bash
PYTHONPATH=src python3 -m coverage run -m unittest discover -s tests -t .
python3 -m coverage report --fail-under=64
python3 -m coverage json -o coverage.json
python3 scripts/check-coverage.py coverage.json
```

门槛定义在 `scripts/check-coverage.py`，取值略低于当前实测值：真实回退会让构建失败，
但不会因为无关改动而变得脆弱。补测试时优先覆盖网络客户端、数据映射、操作载荷与
共享 UI 基础组件，最后才是页面级行为。

### 单元测试

| 文件 | 内容 |
| --- | --- |
| `tests/unit/test_config.py` | 默认安全配置、未知键/段拒绝、类型校验、TLS 成对、绝对路径、环境变量覆盖、并发上限 |
| `tests/unit/test_paths.py` | 相对路径/换行/NUL/超长路径拒绝、允许根包含判断、符号链接与目录拒绝 |
| `tests/unit/test_events.py` | 严重程度映射（EICAR=中危、木马=严重、PUP=低危）、去重合并、计数、状态流转、保留策略 |
| `tests/unit/test_scans.py` | 队列取消、运行中取消、非法转换、未支持类型、重启后中断任务标记失败 |
| `tests/unit/test_hostchecks.py` | 固定根文件系统：额外 UID 0、空密码、重复 UID、敏感文件权限、SSH 指令与 Match 排除、危险端口、ASLR、缺失文件为 error/skipped 而非 finding、shadow 哈希不落盘 |
| `tests/unit/test_db_migration.py` | schema v1 → v2 升级、`audit_runs` 创建、已有数据保留、迁移前备份存在 |
| `tests/unit/test_lynis.py` | 真实 3.0.8 报告格式解析、缺失键不猜测、warning 严重程度、只读 argv、报告/日志 0600、禁用/缺失二进制行为 |
| `tests/unit/test_containers.py` | 特权/host 命名空间、Docker Socket 只读仍严重、敏感路径最长匹配、root 只读、capabilities/seccomp/AppArmor、正常容器不误报、缺字段为 unknown、环境变量不保留、Docker API 只读与 403 区分、URL/ID 拒绝、失败不保留虚构清单 |
| `tests/unit/test_falco.py` | 现代/旧内核、BTF、CAP_BPF+CAP_PERFMON、权限不足、需配置、缺失二进制、安装计划不可从 UI 安装、令牌 0600/稳定/禁用不创建、事件优先级映射、未知优先级、非法载荷、非法容器 ID、去重键稳定 |
| `tests/unit/test_docker_proxy.py` | 真实 HTTP 代理对假 Unix Socket：GET 白名单、POST/PUT/PATCH/DELETE 405、未知路径/额外查询 403、短 ID/路径穿越/非十六进制拒绝、健康检查上游 `/version` |
| `tests/unit/test_yara.py` | 规则包 manifest/SHA-256/签名（真实 OpenSSL）、zip 穿越/符号链接/未声明文件/哈希不符/编译失败拒绝、同版本不可覆盖、激活/删除与状态损坏、输出解析与严重程度、argv 预算分批、只读扫描与符号链接跳过 |
| `tests/unit/test_wazuh.py` | Wazuh 级别/类别映射、事件字段与证据、去重、超大载荷拒绝、首次从 EOF 开始、偏移续读、轮转/截断重置、解析错误、超大行不产生片段事件、状态损坏暂停、符号链接告警文件拒绝、Agent 探测各降级路径、密钥文件不读取、安装计划只读 |
| `tests/unit/test_clamav_update.py` | `sigtool --info` CVD 签名验证成功/失败、sigtool 缺失与 `.cld` 明确“未验证/不适用”、更新响应包含验证结果 |

### 集成测试

`tests/integration/test_api_workflow.py` 启动真实守护进程、真实 `ThreadingHTTPServer`、临时 SQLite，并使用 **测试专用的假 clamd UNIX Socket**（按 NUL 分帧实现 `PING/VERSION/SCAN/SHUTDOWN`）驱动完整链路：

- 健康检查、静态页面、安全响应头、静态资源路径穿越拒绝
- 未认证访问拒绝；错误令牌 401
- viewer 只读：读取成功，创建扫描/读取日志 403
- 缺少 CSRF、跨站 Origin 拒绝
- 状态真实性：按需扫描 `ready`、实时防护 `unsupported`、总体不为 `healthy`
- EICAR 扫描：任务成功、文件数 2、检测 1、证据报告写入、事件字段正确
- 重复扫描：事件去重、`occurrences` 累加
- 隔离：缺少确认拒绝；隔离后文件消失；哈希长度；原路径被占用时拒绝覆盖；恢复内容一致；再次隔离并永久删除；审计包含 create/restore/delete
- 隔离安全：符号链接拒绝、根目录外路径拒绝
- 事件状态流转与非法流转；CSV/JSON 导出
- 设置：`auto` 返回 501、定时扫描合并、viewer 修改 403
- doctor 自检包含数据库与病毒库检查
- 非法扫描请求：`paths` 非数组、未支持类型、越界自定义路径
- 主机体检：viewer 发起 403；admin 创建 202；后台完成；检查状态合法；`errors_count` 与 error 检查一致；证据报告存在；历史与详情可读；状态页 `host_baseline` 关联最近体检；操作审计包含 `audit.run`
- 容器清单：使用假 Docker API 注入特权 + host 网络 + docker.sock 容器；viewer 可读清单与详情、无法刷新（403）；admin 刷新成功并写 `container.refresh`；Docker 请求全部为 GET；3 条配置风险事件正确关联容器；不存在 stop/restart 端点（404）
- Falco 接入：独立令牌写入成功（202），重复事件合并；管理员令牌调用接入端点 401；Falco 令牌不能读取 `/status`（401）；`/falco` 显示事件计数

`tests/integration/test_yara_api.py` 使用真实 API/存储/扫描队列与假 `yara`/`yarac`：

- viewer 可读规则状态/版本，安装/激活/删除返回 403
- 安装缺少 `confirm` 返回 400；合法安装返回 201 并写 `yara.pack.install` 审计
- 多版本共存、激活切换、删除指定版本
- 非法包（哈希不符/穿越/编译失败）被拒绝且不留下版本
- YARA 扫描生成 `source=yara` 事件；重复扫描去重；不写隔离区
- 没有激活规则包时扫描返回 `component_unavailable`

`tests/integration/test_wazuh_api.py` 使用假 `wazuh-control`、本地 `alerts.json` 与真实事件存储：

- viewer 可读 `/wazuh`，可见 `scope=local_agent_only`、`connection_verified=false`
- capabilities 中 Wazuh 状态最多 `degraded`，Manager 地址可见，注册密钥内容不出现在任何响应
- 安装计划为只读（`installable_from_ui=false`）
- 新增告警行生成统一事件；重复告警合并 `occurrences`；无自动隔离记录

### 真实性说明

测试中的假 clamd 只用于在不安装 ClamAV 的开发机上验证协议适配与业务链路。它位于 `tests/`，不进入镜像，也不会在生产环境返回结果。真实扫描结果必须来自 clamd。

## 3. 测试结果

| 环境 | 命令 | 结果 |
| --- | --- | --- |
| macOS（Darwin 27.0.0，Python 3.15.2） | `./scripts/test.sh` | `Ran 160 tests ... OK` |
| Ubuntu 24.04 测试环境（Python 3.12.3） | `PYTHONPATH=src python3 -m unittest discover -s tests -t .` | `Ran 160 tests ... OK` |

## 4. 真实 Linux + ClamAV E2E

在 Ubuntu 24.04 测试环境（2026-11-10）实际执行 `./scripts/e2e-eicar.sh`：

- ClamAV 1.4.6，病毒库 daily 28179 / main 63，`service_status=running`、`health_status=ok`
- 修复前发现真实协议问题：客户端发送 `zSCAN path\n` 被 clamd 以 `COMMAND READ TIMED OUT` 拒绝；改为文档规定的 `zSCAN path\0` NUL 分帧后通过
- 修复后快速扫描：任务 `已完成`，扫描文件 1、检测 1、错误 0
- 事件：`source=clamav`、`category=malware`、`severity=medium`、检测名 `Eicar-Signature`（ClamAV 1.4.6 实际返回值）
- 隔离 → 恢复（内容/哈希一致）→ 再次隔离 → 永久删除全部成功
- 审计记录包含 `quarantine.create`、`quarantine.restore`、`quarantine.delete`，操作者 `admin`
- `lsec components stop clamav` / `start clamav` 与 `lsec components update clamav` 均返回真实状态
- 真实 viewer 令牌：`GET /status` 200，创建扫描 403 `forbidden`

手工验证：

```bash
docker compose exec -T lsec lsec status
docker compose exec -T lsec lsec scan quick --wait
docker compose exec -T lsec lsec events list
docker compose exec -T lsec lsec quarantine list
```

### 主机体检 E2E

在 Ubuntu 24.04 测试环境的真实镜像（Lynis 3.0.8）上执行：

```bash
docker exec lsec lsec audit run --wait
docker exec lsec lsec audit report
docker exec lsec lsec audit history
```

结果：

- 体检 `succeeded`，范围 `container`，耗时约 7 秒
- 检查 10 项：通过 6、发现 1、未能执行 0、跳过 3
- SSH、systemd、AppArmor/SELinux 因容器内不可见而明确为 `skipped`，不是 `pass`
- 发现 `LOGG-2138`（klogd 未运行），级别 `medium`，生成 1 条统一事件；Lynis 39 条 suggestion 只保存在证据报告
- 加固指数 56，原始报告与日志 0600，输出目录 0700
- 再次体检时同一 `LOGG-2138` 发现按去重键合并，不重复刷屏
- `lsec audit list` 包含 `audit.run` 与 `audit.complete`，操作者 `admin`
- viewer 可读取历史/详情，发起体检 403

### 容器监控 E2E

在 Ubuntu 24.04 测试环境使用 `docker-compose.container.yml` 启动真实代理后执行（2026-11-10）：

```bash
cd /opt/lsec
docker compose -f docker-compose.yml -f docker-compose.container.yml up -d --build
docker exec lsec lsec containers list
docker exec lsec lsec containers inspect lsec-docker-proxy
docker exec lsec lsec falco status
docker exec lsec lsec doctor
```

结果：

- `lsec:0.4.0` 与 `lsec-docker-proxy:0.4.0` 均构建成功；代理 `healthy`
- 代理只挂载 `/var/run/docker.sock:ro`，`ReadonlyRootfs=true`、`CapDrop=[ALL]`、`Privileged=false`，仅位于 `lsec_lsec-internal`，无宿主机端口
- lsec 容器挂载仅 `/data`、`/var/lib/clamav`、`/scan`；容器内不存在 `/var/run/docker.sock`（`NO_DOCKER_SOCKET_IN_LSEC`）
- 真实清单：4 个测试容器（含 lsec、只读代理与监控组件）；运行中 3、停止 1、风险 3、无法评估 0
- 风险：扫描目录绑定挂载为高危；代理因 Docker Socket 为严重；特权监控容器因 host PID、Docker Socket 与 `/proc`/`/sys` 等挂载为严重并产生多项发现
- 统一事件：11 条运行中容器发现，来源 `docker`、类别 `configuration`；重启后重复风险按去重键合并（`occurrences=2`），没有重复事件洪泛
- 手动刷新 `POST /containers/refresh` 返回 200，审计出现 `container.refresh`（admin，success）
- 真实 Falco 事件接入：独立令牌返回 `202 created=true`；同一事件再次提交返回 `202 created=false`；目标为 `container_id` + 名称，优先级 Warning→中危
- 令牌隔离：管理员令牌调用接入端点 401；Falco 令牌读取 `/status`、`/containers` 均 401；viewer 读取容器 200、刷新 403
- 无容器变更能力：`POST /containers/<id>/stop|restart` 与 `DELETE /containers/<id>` 均 404；代理对 `POST /containers/<id>/stop` 返回 405
- Falco 真实状态：未安装；宿主内核 6.8.0-142、BTF 存在，但 lsec 进程 `CAP_SYS_ADMIN=false`、`CAP_BPF/PERFMON=false`，能力状态 `requires_privileges`，健康 `unavailable`；没有伪装为已启用
- Containerd：未安装，组件状态 `not_installed/unavailable`，并明确“不采集清单”
- `lsec doctor`：通过 7、警告 1（绑定 0.0.0.0 未 TLS）、失败 0、信息 2；容器监控与 Falco 状态被纳入自检
- schema 为 v2；本次未新增数据库迁移

### YARA 与统一事件中心 E2E

在 Ubuntu 24.04 测试环境的 `lsec:0.4.0`（YARA 4.2.3、OpenSSL 3.0.22）上执行：

- 使用临时密钥对生成签名规则包并安装：`e2e-test@1.0.0`，`signature_verified=true`，成功激活
- 非法包全部拒绝：未签名、签名错误、规则哈希不符、`yarac` 编译失败均返回 400，且不留下版本/staging 目录
- 单文件命中：任务 `succeeded`，1 文件、1 检测、0 错误；事件 `source=yara`、`category=malware`、`severity=high`
- 事件证据包含文件 SHA-256、`rule_id`、规则包 ID/版本、规则名、标签、文件大小和任务 ID
- 重复扫描 3 次后仍为 1 条事件，`occurrences=3`，`source_refs` 保留 3 个不同扫描任务
- 没有自动隔离；事件描述明确“规则命中不等同于已确认恶意软件”
- 1000 文件 YARA 扫描：`succeeded`，1000 文件、0 检测、0 错误，约 2.229 秒
- 1000 文件 ClamAV 扫描：`succeeded`，1000 文件、0 检测、0 错误，约 4.227 秒
- 规则包安装/激活/删除审计、viewer 只读均通过
- Web UI：规则包显示 `已验证`、`扫描就绪`；viewer 显示只读标识

测试发现并修复两个真实缺陷：

1. 对 `yarac` 编译产物调用 `yara` 时必须加 `-C`，否则被当作文本规则解析并报 non-ascii 语法错误。
2. `yara` 只接受一个目标参数；批量文件必须通过临时清单和 `--scan-list` 传入，否则 1000 文件扫描会变成 `partial` 并产生 5 个错误。

### Wazuh 可选接入与发布 E2E

主部署未安装 Wazuh Agent，真实状态为：

- `installed=false`、`health_status=unavailable`、`error_code=disabled`
- `scope=local_agent_only`、`connection_verified=false`
- Manager 未配置、地址为空
- 事件接入未启用，UI 显示 `未启用`、`未验证` 与“lsec 不是 Wazuh Manager”说明

使用 `/tmp/lsec-wazuh-test` 独立临时守护进程和真实本地 `alerts.json` 验证：

- 首次从 EOF 开始，不回灌历史告警
- level 10 告警生成 `source=wazuh`、`severity=high`、`category=auth` 事件，目标 IP 为 `203.0.113.7`
- 重复告警合并 `occurrences=2`；重启后接入计数归零但持久化偏移阻止重复采集
- 日志轮转 `max_bytes=8192/backups=3` 后活动文件 2756 字节，`.1/.2/.3` 各 8056 字节

deb 生命周期在一次性 Debian 12 容器中验证（无 systemd）：

- 缺少 `python3` 时安装失败并保持 unconfigured，未创建用户/数据目录；补装依赖后配置成功
- 0.4.0 → 0.4.1 升级保留 `/etc/lsec/lsec.toml` 本地修改和 `/var/lib/lsec` 数据标记
- `--force-downgrade` 回到 0.4.0 后配置与数据仍保留
- `dpkg -r` 保留数据与日志并打印保留路径；`dpkg -P` 清理数据、日志、配置和系统用户
- 本次无可用 GPG 私钥，发布产物未签名，`BUILD-MANIFEST.txt` 记录 `signed=no`

详见 `docs/TEST-REPORT.md`。

### Web UI 冒烟测试

使用 Playwright + 本机 Chrome，通过 SSH 隧道访问真实部署，覆盖：

- 管理员令牌登录、会话 Cookie 在刷新后仍有效、退出登录
- 10 个导航页面全部渲染，未支持能力显示明确说明
- 容器页：真实显示 4 个容器、3 个风险容器、11 项发现、Docker 29.0.2/API 1.52、监控 API、Falco 能力状态与事件接入；管理员可刷新，viewer 无刷新按钮
- 容器详情弹窗展示风险、挂载、端口与“不提供启停操作”说明；Falco 安装计划弹窗明确“不能从界面安装”
- 通过 UI 创建快速扫描，等待真实任务完成，任务列表出现新任务与检测数
- 从事件页隔离、在隔离区恢复、再次隔离并永久删除，均经过确认弹窗并出现成功提示
- 将两条 EICAR 测试事件标记“已解决”并填写备注，列表状态实时更新，审计出现 `event.status`
- 安全体检页展示真实加固指数、风险发现、系统信息、体检历史与 Lynis 建议；管理员运行体检后自动刷新为完成状态
- viewer 在安全体检页看不到运行按钮，并显示只读提示
- YARA 页：真实显示已安装规则包 `e2e-test`、`已验证`、`扫描就绪`；viewer 显示只读标识
- 主机页：Wazuh 卡片显示 `未启用`、`未验证` 与 `local_agent_only` 作用域说明，没有把本地告警接入描述成 Manager 能力
- 事件中心：筛选、详情与导出在真实数据上可用
- 页面无 console error、无 page error、无失败请求（补充 favicon 后 404 消失）
- 真实 viewer 登录只读，写接口返回 403

## 5. 协议与测试替身

集成测试中的假 clamd 严格按 NUL 分帧协议读取命令并返回 NUL 结尾响应。客户端如果回退为换行分帧，测试会阻塞/失败，避免再次出现“测试替身过于宽松、掩盖真实 clamd 不兼容”的问题。

Lynis 单元测试使用一个只写出固定 `lynis-report.dat` 的临时脚本，仅用于验证 argv、报告读取与解析；解析样例取自真实 Lynis 3.0.8 报告（`hardening_index=56`、`lynis_tests_done=230`、`warning[]=LOGG-2138|...|-|-|`）。生产镜像安装真实 Lynis，不使用该脚本。

## 6. 安全测试清单

| 项目 | 覆盖方式 |
| --- | --- |
| 普通用户调用特权接口 | 集成测试 viewer POST/DELETE/日志 403 |
| CSRF / 跨站 Origin | 集成测试缺少 CSRF、恶意 Origin 403 |
| 路径穿越 / 越界 | 单元 + 集成测试 |
| 符号链接 | 单元 + 集成测试 |
| 隔离目录权限 | 强制 0700；doctor 检查数据目录与令牌权限 |
| 令牌权限 | 0600；doctor 检查过宽权限 |
| 命令注入 | 全局 argv 执行，无 shell；clamd 命令拒绝控制字符 |
| 畸形请求 | 非 JSON、非对象、错误类型、超长请求体 |
| 队列/状态冲突 | 状态机单元测试；扫描队列上限 |
| 更新失败 | 保留旧病毒库，返回真实退出码与输出尾部 |
| Docker Socket 滥用 | 集成测试确认 Docker API 全部为 GET；代理测试确认写方法 405；产品无容器变更接口 |
| 容器敏感信息 | 单元测试确认环境变量不出现在检查结果；事件证据大小受限 |
| Falco 令牌越权 | 集成测试：管理员令牌不能写接入端点，Falco 令牌不能读其他 API |
| 容器 ID/路径注入 | 单元测试拒绝短 ID、非十六进制、路径穿越；代理再次校验 |
| 权限失败误报 | 容器监控 `permission_denied` 与 `unavailable` 分开；Docker 403 测试；失败时不返回虚构清单 |

## 7. 性能与长稳边界

已在测试主机执行一次性基准（详见 `docs/TEST-REPORT.md`）：

- 5000 条唯一事件写入 2.459 秒（2032.9 条/秒），列表 13.59 ms，导出 70.81 ms
- 200 个合成容器清单刷新 0.576 秒（约 2.9 ms/容器）
- 空闲容器 CPU 0.07%–0.11%，内存 981.1–981.3 MiB；约 5 分 41 秒内采样 12 次稳定

尚未自动化或未执行：

- 多天/多周长稳、内存泄漏和磁盘长期增长测试
- 高并发事件写入与持续 Falco 事件洪峰
- 真实 Docker daemon 在数百容器规模下的抖动
- 浏览器端 UI 的持续回归（已执行一次性 Playwright 冒烟，但脚本未纳入仓库/CI）
- TLS 双向配置与反向代理集成测试
- 真实 containerd API 集成（当前仅探测）
- 真实 Wazuh Manager/Agent 注册、Manager API 与 TLS 连接（产品不提供 Manager 能力）
- deb 包在真实 systemd 主机上的长期运行、自动重启与 apt 交互（已在 Debian 容器中验证安装/升级/降级/卸载脚本与 payload）
- GPG 签名发布（构建主机无可用私钥，本次产物未签名）

## 8. 测试数据与清理

- 单元/集成测试使用 `tempfile`，结束后自动删除
- E2E 脚本会在容器 `/scan` 写入 EICAR 文件用于验证；本次验收后已删除，`/scan` 与宿主机 `scan-data/` 均为空
- 测试产生的两条 EICAR 事件已通过 UI 标记“已解决”并保留审计记录，未删除历史
- 主机体检真实产生的 `LOGG-2138` 事件保持“新事件”状态，供用户自行确认；体检证据保留在 `/data/evidence/audits/`
- YARA 测试使用临时密钥和测试规则包；测试私钥位于临时目录，验收后删除；无效规则包不会进入已安装版本
- Wazuh 测试使用 `/tmp/lsec-wazuh-test` 独立守护进程与临时数据目录，验收后停止并删除，不影响主部署
- 测试不会扫描、修改或修复测试目录之外的路径
