# 安全与性能测试报告

[English](TEST-REPORT.md) | **简体中文**

版本：0.4.0  
测试日期：2026-11-10  
测试主机：Ubuntu 24.04.3 LTS 测试环境

本报告记录 YARA 与统一事件中心、Wazuh 可选接入与发布加固的验收测试，并汇总此前各能力的真实环境结果。报告只陈述实际执行过的测试；未执行的测试在“范围与限制”中明确列出，不作为已通过项。

## 1. 结论摘要

- 单元/集成测试：本机与测试主机均为 `Ran 160 tests ... OK`。
- 真实 YARA：签名规则包安装、激活、编译校验、批量扫描、事件去重全部通过；未签名、签名错误、哈希不符、规则编译失败四类非法包全部被拒绝。
- 真实 ClamAV：1000 文件扫描 `succeeded`，1000 文件、0 检测、0 错误，耗时约 4.227 秒。
- 真实 YARA：1000 文件扫描 `succeeded`，1000 文件、0 检测、0 错误，耗时约 2.229 秒；单文件命中产生 1 条高危事件，重复扫描合并为 `occurrences=3` 并保留 3 个 `source_refs`。
- Wazuh：主部署未安装 Agent，状态真实显示 `disabled`、`connection_verified=false`，并明确“lsec 不是 Wazuh Manager”。使用临时本地 Agent 告警文件验证了接入、去重、重启偏移与日志轮转；未声明任何 Manager 能力。
- 性能：5000 条唯一事件写入 2.459 秒（约 2033 条/秒），列表查询 13.59 ms，5000 条导出 70.81 ms；200 个合成容器清单刷新 0.576 秒（约 2.9 ms/容器）。
- 稳定性：主容器连续采样 12 次（约 5 分 41 秒），CPU 0.07%–0.11%，内存稳定在 981.1–981.3 MiB。该结果不构成多天长时间稳定性证明。
- 发布包：deb 安装 → 0.4.1 升级 → 0.4.0 降级 → remove → purge 全流程通过；升级和降级均保留配置与数据，remove 保留数据，purge 清理数据、配置与系统用户。
- 发布签名：构建主机没有可用 GPG 私钥，因此产物为**未签名构建**，`BUILD-MANIFEST.txt` 记录 `signed=no`；未声称已签名发布。

## 2. 测试环境

### 2.1 宿主机

| 项目 | 值 |
| --- | --- |
| 操作系统 | Ubuntu 24.04.3 LTS |
| 内核 | 6.8.0-142-generic |
| CPU | AMD Ryzen 9 9950X3D 16-Core / 32 线程 |
| 内存 | 123 GiB |
| Docker | 29.0.2 |
| Compose | v2.40.3 |
| 宿主机 Python | 3.12.3 |
| dpkg | 1.22.6 |

### 2.2 部署环境

| 项目 | 值 |
| --- | --- |
| 镜像 | `lsec:0.4.0` |
| 容器系统 | Debian GNU/Linux 12 (bookworm)，Python 3.12.16 |
| ClamAV | 1.4.6，病毒库 daily 28179 / main 63 |
| Lynis | 3.0.8 |
| YARA / yarac | 4.2.3 |
| OpenSSL | 3.0.22 |
| 数据库 | SQLite，schema v2，WAL |
| 访问方式 | 宿主 `127.0.0.1:8080`，测试经 SSH 隧道 `127.0.0.1:18080` |

## 3. 自动化测试

```bash
./scripts/test.sh
# 等价于
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

| 环境 | 结果 |
| --- | --- |
| macOS（Darwin 27.0.0，Python 3.15.2） | `Ran 160 tests ... OK` |
| Ubuntu 24.04 测试环境干净副本（Python 3.12.3） | `Ran 160 tests ... OK` |

测试主机上的完整测试从临时干净副本执行，避免部署目录中历史遗留的 `lsec/` 目录遮蔽 `src/lsec`。未删除该遗留目录，因为它不属于本项目测试清理范围。

覆盖重点：

- 配置校验、路径穿越、符号链接、allowlist 根目录。
- 事件严重程度映射、去重、状态流转、保留策略。
- 扫描队列、取消、重启后中断任务标记失败。
- 主机体检对“无法执行”与“真实发现”的区分。
- 容器只读 API、敏感路径、特权/host 命名空间、无启停能力。
- Falco 令牌隔离、事件映射与去重。
- YARA manifest、SHA-256、OpenSSL 签名、zip 穿越、编译校验、版本管理、扫描分批与输出解析。
- Wazuh 级别/类别映射、偏移续读、轮转/截断、超大行、符号链接告警文件、Agent 探测降级。
- ClamAV CVD 签名验证及验证失败的明确状态。

## 4. YARA 与统一事件中心

### 4.1 规则包与签名

使用临时 OpenSSL 密钥对构造签名规则包，并逐个提交：

| 用例 | 预期 | 实际 |
| --- | --- | --- |
| 合法 zip（manifest + manifest.sig + 规则哈希匹配 + `yarac` 编译通过） | 安装并激活 | 201，`signature_verified=true`，`pack_id=e2e-test`、`version=1.0.0` |
| 未签名包（缺少 `manifest.sig`） | 拒绝 | 400，未出现在版本列表 |
| 签名错误（内容被篡改或非对应私钥） | 拒绝 | 400，`openssl` 报 bad signature |
| 规则文件 SHA-256 与 manifest 不符 | 拒绝 | 400，未留下 staging 版本 |
| 规则语法错误导致 `yarac` 编译失败 | 拒绝 | 400，未留下 staging 版本 |

安装、激活、删除均写入审计（`yara.pack.install`、`yara.pack.activate`、`yara.pack.delete`）。viewer 读取规则状态成功，写操作返回 403。

### 4.2 单文件扫描与事件

使用已激活的 `e2e-test@1.0.0` 扫描包含标记内容的文件：

- 任务状态 `succeeded`，扫描 1 文件、1 检测、0 错误。
- 事件：`source=yara`、`category=malware`、`severity=high`。
- 证据包含文件 SHA-256、`rule_id=e2e-test:LsecE2EMarker`、规则包版本、规则名、标签、文件大小与任务 ID。
- 描述明确“规则命中不等同于已确认恶意软件”，并说明未自动隔离或删除。
- 连续扫描 3 次后仍只有 1 条事件，`occurrences=3`，`source_refs` 保留 3 个不同 `task_id` 的原始证据。
- 隔离区为空，确认没有自动隔离。

### 4.3 批量扫描

在真实容器内扫描 1000 个文件：

| 引擎 | 状态 | 文件数 | 检测 | 错误 | 耗时 |
| --- | --- | --- | --- | --- | --- |
| YARA 4.2.3 | `succeeded` | 1000 | 0 | 0 | 约 2.229 秒 |
| ClamAV 1.4.6 | `succeeded` | 1000 | 0 | 0 | 约 4.227 秒 |

测试过程中发现并修复两个真实缺陷：

1. `yara` 默认把 `yarac` 编译产物当作源码解析，报 `syntax error / non-ascii character`；修复为对编译规则使用 `-C`。
2. 一次向 `yara` 传入多个文件参数时，它把除最后一个之外的文件都当作规则文件，1000 文件扫描返回 `partial` 和 5 个错误；修复为把批次写入临时清单并使用 `--scan-list`，且清单文件在 `finally` 中删除。

修复后重新构建 `lsec:0.4.0` 并复测，上述 1000 文件扫描均无错误。

### 4.4 事件中心

- 事件列表、严重程度/来源/状态筛选、关键词搜索、详情与 CSV/JSON 导出通过真实 API 验证；事件页列表、状态流转与详情另经 Playwright 验证。
- 去重键稳定；重复事件累加 `occurrences` 并保留不同来源任务证据。
- 状态流转只允许合法路径；每次处置写入审计。
- viewer 可读，写操作 403。
- YARA 页通过 Playwright 验证：显示 `e2e-test`、`已验证`、`扫描就绪`，viewer 显示只读标识。

## 5. Wazuh 可选接入

### 5.1 主部署的真实状态

主部署未安装 Wazuh Agent。`GET /api/v1/wazuh` 返回：

- 组件 `installed=false`、`health_status=unavailable`、`error_code=disabled`。
- `scope=local_agent_only`，`connection_verified=false`。
- `manager.manager_configured=false`、`manager.address=null`。
- `ingest.enabled=false`、`running=false`。
- 说明文本明确：仅读取本地 Agent 状态与本地告警文件；lsec 不是 Wazuh Manager，不验证也不声称 Manager 连接能力。

Web UI 主机页显示 Wazuh 卡片、`未启用`、`未验证` 和作用域说明。没有把“未安装”显示为“运行中”，也没有把本地告警文件接入描述成 Manager 能力。

### 5.2 临时本地 Agent 测试

为验证可选接入路径，在 `/tmp/lsec-wazuh-test` 启动独立临时守护进程和临时数据目录，使用真实本地 `alerts.json`：

- 首次启动从文件 EOF 开始，不回灌历史告警。
- 写入一条 level 10 告警后，生成统一事件：`source=wazuh`、`severity=high`、`category=auth`，目标 IP 为 `203.0.113.7`。
- 重复写入同一告警后，`occurrences=2`，未产生第二条事件。
- 重启守护进程后接入计数器归零，但持久化偏移阻止重复采集，事件仍为 `occurrences=2`。
- 日志轮转（`max_bytes=8192`、`backups=3`）后，活动文件 2756 字节，`.1/.2/.3` 各 8056 字节；轮转被识别，未产生解析洪水。
- 超大行、非法 JSON、文件截断、符号链接告警文件等负向用例由单元测试覆盖；无法读取或解析失败不会生成虚构事件。

限制：临时测试只验证本地 Agent 告警文件接入，不包含真实 Wazuh Manager、真实 Agent 注册、TLS 连接或 Manager API 调用。产品也不声称提供这些能力。

## 6. 发布与升级测试

### 6.1 构建

从当前源码在测试主机构建两个测试版本：

- `lsec_0.4.0_all.deb`
- `lsec_0.4.1_all.deb`（仅用于升级/降级路径测试）

使用 `dpkg-deb` 检查：

- `Architecture: all`
- `Depends: python3 (>= 3.10), adduser`
- `Recommends: clamav, clamav-daemon, clamav-freshclam, yara, lynis`
- `Suggests: wazuh-agent`
- 包含 `conffiles`、`postinst`、`prerm`、`postrm`

### 6.2 安装/升级/降级/卸载

在一次性 Debian 12 容器中执行，容器内无 systemd，因此 postinst 的 systemd 分支按设计跳过：

| 步骤 | 结果 |
| --- | --- |
| 缺少 `python3` 时 `dpkg -i 0.4.0` | 依赖失败，包保持 unconfigured，未创建系统用户和数据目录；安装依赖后重新配置成功 |
| 安装 0.4.0 | 创建 `lsec` 系统用户/组，创建 `/var/lib/lsec` 及 `clamav/evidence/logs/quarantine/secrets/wazuh/yara` 子目录，权限符合预期 |
| 修改配置并写入数据标记后升级到 0.4.1 | 升级成功，配置中的本地标记保留，`/var/lib/lsec/upgrade-marker` 保留，用户/组不变 |
| `dpkg --force-downgrade` 到 0.4.0 | 降级成功，配置与数据仍保留 |
| `dpkg -r lsec` | 移除程序，明确打印保留 `/var/lib/lsec`、`/var/log/lsec`，数据仍在 |
| `dpkg -P lsec` | 删除数据、日志、配置与 `lsec` 系统用户/组，`dpkg-query` 不再找到包 |

测试环境说明：测试容器来自 `lsec:0.4.0` 镜像，镜像内 `/usr/local/bin/lsec` 是开发用启动脚本，会遮蔽包安装的 `/usr/bin/lsec`；测试时使用 `/usr/bin/lsec` 并在无 `PYTHONPATH` 的环境下验证。普通 deb 主机不存在该开发启动脚本。未在真实 systemd 主机上验证开机自启、服务重启与升级失败后的自动回滚；相关恢复步骤写入 `docs/RELEASE.md` 和 `docs/DEPLOYMENT.md`。

### 6.3 产物校验

发布脚本生成：

- `.deb`
- source tar
- `SHA256SUMS`
- `BUILD-MANIFEST.txt`

`scripts/verify-release.sh` 对发布物 `SHA256SUMS` 和 deb 元数据执行校验。构建主机没有 GPG 私钥，因此本次没有 `.asc` 签名文件，`BUILD-MANIFEST.txt` 明确记录 `signed=no`。签名流程本身由脚本支持，但本次未执行，不能把本次产物描述为“已签名”。

## 7. 性能测试

### 7.1 事件写入与查询

在部署容器内使用临时 SQLite 数据库写入 5000 条唯一 Falco 事件（不污染生产库）：

| 指标 | 结果 |
| --- | --- |
| 写入总耗时 | 2.459 秒 |
| 写入吞吐 | 2032.9 条/秒 |
| 写入延迟 p50 / p95 / max | 0.403 ms / 0.432 ms / 11.562 ms |
| 最近事件列表 | 13.59 ms |
| 严重事件筛选 | 3.97 ms |
| 关键词搜索 | 2.87 ms |
| 导出 5000 条 | 70.81 ms |
| 计数聚合 | 0.9 ms |
| 数据库大小 | 7,872,512 字节 |
| 进程最大 RSS | 63,300 KB |

说明：这是单机、单进程、顺序写入的合成负载；不代表高并发或长期运行上限。

### 7.2 容器清单规模

使用测试专用假 Docker API 生成 10/50/100/200 个容器并刷新只读清单：

| 容器数 | 刷新耗时 | 每容器 |
| --- | --- | --- |
| 10 | 0.007 秒 | 0.7 ms |
| 50 | 0.123 秒 | 2.46 ms |
| 100 | 0.242 秒 | 2.42 ms |
| 200 | 0.576 秒 | 2.88 ms |

200 容器时共发起 203 次 HTTP 请求，状态为 `monitored`，无 inspect 错误，所有容器均被监控。该测试使用本地合成 API，不包含真实 Docker daemon 在大量容器下的抖动。

### 7.3 空闲资源与短时稳定性

主部署空闲时：

| 指标 | 值 |
| --- | --- |
| 容器 CPU | 0.07%–0.11% |
| 容器内存 | 981.1–981.3 MiB / 123.4 GiB |
| 容器进程数 | 10 |
| clamd RSS | 约 965 MiB |
| lsec Python 进程 RSS | 约 34 MiB |

约 5 分 41 秒内采样 12 次（30 秒间隔），CPU 与内存均稳定，无重启、无 OOM、无健康检查失败。未执行数小时或数天的长稳测试，因此不声称已满足长时间稳定性验收。

## 8. 安全测试结果

| 控制目标 | 验证结果 |
| --- | --- |
| 认证与角色 | 未认证 401；viewer 写操作 403；Falco 令牌只能写接入端点 |
| CSRF / Origin | 缺少 CSRF 或跨站 Origin 被拒绝 |
| 路径穿越 / 符号链接 | 扫描、隔离、规则包、告警文件路径均有负向测试 |
| 命令执行 | 全部外部命令使用 argv 数组；无 shell 字符串拼接 |
| 隔离操作 | 必须显式确认；写入审计；无自动隔离/删除 |
| 容器安全 | 只读 Docker API；代理写方法 405；产品无 stop/restart/delete 路由 |
| 秘密保护 | 令牌文件 0600；响应与日志不返回令牌；Wazuh 注册密钥内容不读取/不返回 |
| 真实性 | 组件状态、扫描结果、容器清单、Wazuh 能力均来自真实探测；失败区分为 `unavailable`/`permission_denied`/`error`，不返回虚构数据 |
| 更新失败 | 保留旧病毒库并返回真实退出码与输出尾部 |
| 告警输入 | 超大载荷、非法 JSON、超大行、文件轮转/截断均有边界处理 |

## 9. 缺陷与修复记录

| 缺陷 | 影响 | 修复 |
| --- | --- | --- |
| clamd 使用换行分帧导致 `COMMAND READ TIMED OUT` | 真实 ClamAV 扫描失败 | 改为 NUL 分帧 `zSCAN path\0` |
| YARA 将 `yarac` 编译产物当源码解析 | 所有真实 YARA 扫描失败 | 增加 `-C` |
| 多文件参数被 YARA 当作多个规则文件 | 批量扫描 `partial`，产生错误 | 使用临时清单 + `--scan-list` |
| 构建时 Debian 官方源在大文件下载上停滞 | 镜像无法构建 | 构建期使用可达镜像（本次 SJTU），运行期网络不变 |
| Playwright 等待隐藏元素方式错误 | UI 冒烟误报超时 | 改为 `state: 'hidden'`，并断言真实页面文本 |

## 10. 范围与限制

未执行或不能由本次测试证明的事项：

- 未执行多天/多周长稳、内存泄漏和磁盘长期增长测试。
- 未在真实 systemd 主机上验证服务开机自启、崩溃自动重启和真实 apt 升级交互；deb 生命周期在无 systemd 的一次性容器中验证。
- 未验证真实 Wazuh Manager/Agent 注册、Manager API、TLS 和集群能力；产品明确不提供 Manager 能力。
- 未验证真实 containerd API 集成（当前仅探测状态）。
- 未验证 TLS 双向认证、反向代理和外部身份提供商集成。
- 未执行 GPG 签名发布；本次产物未签名。
- 容器性能测试使用合成 Docker API；真实 daemon 在数百容器下的表现可能不同。
- 浏览器 UI 仅执行一次性 Playwright 冒烟，未纳入 CI 持续回归。
- 主机体检在容器内运行，SSH/systemd/AppArmor 等宿主能力不可见时明确标记为 skipped，不代表宿主已通过检查。

## 11. 验收映射

### YARA 与统一事件中心

| 验收项 | 证据 |
| --- | --- |
| YARA Adapter | 真实 4.2.3 扫描；`-C` + `--scan-list` 修复后 1000 文件成功 |
| 规则包校验/版本管理 | 签名、哈希、编译校验；多版本安装/激活/删除；非法包拒绝 |
| 事件列表/去重/筛选/详情/审计/导出 | API 与 Playwright 验证；`occurrences=3` 且保留 3 个来源任务 |
| 非法规则包拒绝 | 四类非法包均 400，未留下版本 |
| 统一字段 | `source/category/severity/target/evidence/dedup_key/source_refs` 实测 |
| 去重保留来源证据 | 同一事件 3 个 `task_id` 均在 `source_refs` |

### Wazuh 与发布加固

| 验收项 | 证据 |
| --- | --- |
| Wazuh Agent 状态/事件接入基于实际架构 | 测试部署未安装时真实显示 disabled；临时本地 Agent 验证告警文件接入 |
| 不声称完整 Wazuh 能力 | `scope=local_agent_only`、`connection_verified=false`、UI 作用域说明 |
| 更新签名验证 | ClamAV CVD `sigtool` 验证成功/失败/不适用路径由测试覆盖 |
| 完整 deb 包 | 安装/升级/降级/remove/purge 全部通过 |
| 安装/升级/卸载文档 | `docs/RELEASE.md`、`docs/DEPLOYMENT.md` |
| 安全/性能测试报告 | 本文件 |
| 升级失败恢复路径 | 依赖失败保持 unconfigured；文档记录数据库备份与回滚包步骤 |
| 来源/签名/依赖可追溯 | `BUILD-MANIFEST.txt`、`SHA256SUMS`、`dpkg-deb -I`；本次明确未签名 |
