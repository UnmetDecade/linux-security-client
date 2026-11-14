# 安全模型

[English](SECURITY.md) | **简体中文**

## 1. 资产与信任边界

需要保护的资产：

- 访问令牌、Web 会话与 CSRF 令牌
- 隔离文件及其哈希证据
- SQLite 数据库（事件、任务、审计、隔离元数据）
- 扫描证据、运行日志
- 宿主机的被扫描文件

信任边界：

```
浏览器 / CLI  ──HTTP──▶  守护进程（容器）  ──UNIX Socket/子进程──▶  clamd / freshclam
                                      │
                                      ├──文件系统──▶ /data、/scan
                                      │
                                      └──HTTP（可选，internal 网络）──▶ docker-proxy ──UNIX Socket──▶ Docker Engine
```

浏览器、CLI 输入、被扫描文件内容、ClamAV/Falco 返回值、容器 inspect 数据都视为不可信输入。守护进程不执行 shell 字符串，不做自动删除，不自动操作容器。

## 2. 认证与授权

- 管理员和只读令牌由守护进程生成（`secrets.token_urlsafe(32)`），写入 `secrets/*.token`，权限 0600；令牌目录 0700。
- 支持 `LSEC_ADMIN_TOKEN` / `LSEC_VIEWER_TOKEN` 环境变量覆盖；若与磁盘文件不一致，会以 0600 原子替换令牌文件，保证 CLI 读取到同一凭据。
- Bearer Token 使用常量时间比较；Web 登录后生成随机会话 ID 与 CSRF Token。
- 会话 Cookie：`HttpOnly; SameSite=Strict; Path=/`；启用 TLS 时附加 `Secure`。
- 角色：`admin` / `viewer`。所有写接口在服务端检查 `admin`，不依赖前端隐藏按钮。
- Falco 接入令牌是独立角色 `integration`：只在 `/api/v1/integrations/falco` 有效，不能读取状态/事件/日志；管理员与只读令牌也不能写入该端点。接入限速 240 次/分钟。
- 登录按来源 IP 限速（默认 10 次/分钟），超限返回 429。
- 令牌和会话值不写入日志；登录审计只记录角色、来源、结果。Falco 令牌路径可展示，令牌内容不展示、不记录。

## 3. CSRF 与浏览器安全

- Cookie 会话的所有写请求必须带 `X-LSEC-CSRF`，值来自登录响应，使用常量时间比较。
- 如果请求带 `Origin`，其 host 必须与 `Host` 相同。
- 响应头：
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; ...`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Permissions-Policy` 关闭定位/摄像头/麦克风
- 前端不加载第三方脚本、字体或 CDN；CSP 的 `style-src` 允许内联样式属性，仅用于第一方生成的进度条宽度/间距。
- Web UI 所有动态文本经 HTML 转义后插入；不使用 `innerHTML` 拼接未转义数据。

## 4. 命令执行

- 全部外部命令通过 argv 列表执行，禁止 `shell=True`。
- 子进程使用 `start_new_session=True`；超时杀死整个进程组。
- 输出有大小上限；日志/API 不返回无限输出。
- ClamAV 使用文档化的 clamd UNIX Socket 协议，命令与响应采用 NUL 分帧（`zPING`、`zVERSION`、`zSCAN path`、`zSHUTDOWN`），不解析面向人的 CLI 输出。
- clamd 命令拒绝包含换行/NUL 的路径；路径校验发生在附加协议终止符之前。
- Lynis 只调用 `audit system --quick --no-colors --quiet` 及报告/日志输出路径，不执行 suggestion 文本，不接受用户提供的任意参数。
- `yarac` 只接收本次安装的规则文件与编译输出路径；`yara` 只接收已编译规则与白名单内的目标文件；参数按 128 KiB argv 预算分批。
- `sigtool` 只调用 `--info=<CVD 路径>` 读取签名元数据，不执行数据库内容。
- 主机体检全部为只读：不写系统文件、不改 sysctl、不启停服务、不修改账户或防火墙。

## 5. 文件与路径安全

- 所有用户提供的路径必须是绝对路径，长度 ≤ 4096，不含 NUL/换行/回车。
- 扫描自定义路径必须在 `scan.allowed_roots` 内。
- 隔离/恢复路径必须位于 `response.quarantine_roots` 内。
- 隔离源必须是普通文件；符号链接、目录、设备、FIFO 一律拒绝。
- 隔离使用 `O_NOFOLLOW` 打开，复制 + 校验哈希后才删除原文件；删除前比较 `(st_dev, st_ino)`。
- 恢复拒绝覆盖已存在的原路径；写入后复核哈希。
- 文件遍历不跟随符号链接；跳过 `/proc`、`/sys`、`/dev`、`/run`、容器数据目录、ClamAV 数据库和数据卷。
- 隔离目录 0700，文件 0600。
- YARA 规则包只接受 `yara.inbox_dir` 内的普通文件/目录；拒绝符号链接源与 zip 内符号链接、`..` 穿越、绝对路径条目。
- 每个规则文件按 manifest 的 SHA-256 逐一复核；同版本已存在时拒绝覆盖；激活指针使用临时文件 + `os.replace` 原子更新。
- Wazuh 告警文件与状态文件使用 `O_NOFOLLOW`；不读取 `client.keys` 内容；状态目录 0700、状态文件 0600。

## 6. 数据与日志

- SQLite 启用 WAL、外键、busy timeout；迁移在显式事务内执行，失败回滚并恢复迁移前备份。
- 数据目录默认 0750；令牌/证据/隔离目录 0700。
- 日志为 JSON 行，轮转（默认 10 MB × 5）；不记录令牌、Cookie、CSRF、文件内容。
- 审计记录包含请求 ID、前后状态（16 KB 截断）、确认标记，不能被普通用户修改或删除。
- 事件证据中的 `details` 限制为 32 KB，超出截断。
- 体检证据目录 0700，`report.json`、Lynis 报告与日志 0600；报告读取上限 1 MB。
- 体检不会读取或保存 `/etc/shadow` 的密码哈希，只判断密码字段是否为空。

## 6.1 容器与 Falco 数据处理

- Docker API 客户端只实现 GET；代码中不存在 start/stop/restart/exec 方法，代理也会拒绝写方法。
- 容器 ID 必须匹配 12–64 位十六进制；代理只接受该格式的 inspect 路径，防止路径注入。
- inspect 响应上限 8 MB；容器数量受 `max_containers` 限制；输出字段均截断。
- **不保存容器环境变量**（`Config.Env` 常含凭据）；测试明确验证环境变量不会出现在结果中。
- 容器风险事件只保存规则、镜像、状态和有界检查详情，不保存完整 inspect 文档。
- Falco 事件限制 `max_event_bytes`（默认 32 KB），只提取白名单字段；非法容器 ID 不作为目标 ID。
- Falco 事件中的命令输出会进入事件证据，可能包含敏感信息；事件中心访问受角色控制，导出需登录。
- lsec 不安装、不启动、不加载 Falco 驱动，也不修改内核参数；安装计划仅为文本建议。

## 6.2 YARA 规则包

- **信任来源**：规则包只从管理员可控的 inbox 读取，lsec 不下载规则。
- **完整性**：manifest 必须列出每个规则文件及其 SHA-256；任何未声明文件、哈希不符或缺失文件都会导致整包拒绝。
- **真实性**：`require_signature=true` 时使用 OpenSSL 验证 `manifest.sig` 对 manifest 字节的分离签名；公钥缺失或签名无效时拒绝安装，不会“先装了再说”。
- **可编译性**：只有 `yarac` 编译成功才落盘为可激活版本；编译错误包含在 API 错误与审计中。
- **版本不可变**：`<pack_id>/<version>` 目录一次写入，永不原地覆盖；删除/激活均需确认并审计。
- **扫描边界**：只枚举 `scan.allowed_roots` 内普通文件，不跟随符号链接；输出中的目标路径必须位于本次范围，否则丢弃该命中。
- **误报与边界**：规则命中是规则匹配结果，不等同于恶意软件结论；严重程度来自规则标签，默认 medium。

## 6.3 Wazuh 本地接入

- lsec 不联系 Manager、不注册 Agent、不读取/转发注册密钥内容。
- 仅本地 `alerts.json` 新增行进入事件中心；首次启用从 EOF 开始，避免导入历史积压。
- 单次读取与单条事件大小有上限；超大行持续丢弃到下一个换行，不解析截断片段。
- level 与组标签映射为统一严重程度/类别；证据保留告警 id、规则、Agent、Manager 名称与有界原文。
- `manager_connection_verified` 恒为 false；能力状态最多 `degraded`，不会显示为“Wazuh 已全面接管”。
- 告警不会触发自动隔离、删除或容器操作。

## 7. 容器加固

`docker-compose.yml` 默认：

- 不挂载 `/var/run/docker.sock`
- 不使用 `network_mode: host`、`pid: host`、`privileged`
- `no-new-privileges:true`
- 只挂载数据卷、病毒库卷和显式配置的扫描目录
- 端口默认发布到宿主机 `127.0.0.1`
- 日志轮转限制

### 7.1 容器监控代理（可选）

`docker-compose.container.yml` 增加独立的 `docker-proxy`：

- lsec 容器仍然不挂载 Docker Socket；只有代理挂载 `/var/run/docker.sock:ro`
- 代理只允许 4 个 GET 端点，其他路径 403，非 GET 方法 405；响应上限 8 MB
- 代理加入 `internal: true` 网络，不发布宿主机端口；lsec 通过内部 DNS `http://docker-proxy:2375` 访问
- `cap_drop: ALL`、`no-new-privileges:true`、`read_only: true`，仅 `/tmp` 为小容量 tmpfs
- 代理以 root 运行以读取 Socket；它仍是高权限组件，**不是**无风险组件

> Docker Socket 等价于宿主机 root。代理通过 allowlist 降低了误用和写操作风险，但无法消除“能控制代理镜像/容器即可控制宿主机”的残余风险。代理镜像与 Compose 文件必须视为受信基础设施。

**残余风险**：容器内进程以 root 运行，才能读取并隔离挂载目录中的任意文件。因此：

- 任意能控制容器或镜像的人，等同于拥有这些挂载目录的 root 权限
- 扫描目录应尽量只挂载需要检查的路径，不要挂载 `/`、`/etc`、用户主目录或凭据目录
- 镜像和 Compose 文件应视为受信基础设施；不要把 Docker Socket 交给 lsec 容器

## 8. 传输安全

- 默认只把 8080 发布到宿主机回环地址；远程访问推荐 SSH 隧道。
- 局域网直连必须显式设置 `LSEC_LISTEN_ADDR=0.0.0.0`；此时未启用 TLS 的令牌传输不安全。
- 生产环境应在反向代理终止 TLS，或配置 `server.tls_cert` / `server.tls_key`（TLS 1.2+，启用 HSTS）。
- 守护进程拒绝在非回环地址上无 TLS 启动，除非配置允许或显式设置 `LSEC_ALLOW_INSECURE_REMOTE=1`。容器内通过该显式开关启动，实际暴露范围由端口映射控制。

## 9. 更新与供应链

- ClamAV 病毒库通过发行版提供的 `freshclam` 从官方镜像更新；freshclam 负责下载时的 CVD 签名校验。每次更新完成后，lsec 再用 `sigtool --info` 复核磁盘上的 `.cvd` 文件并解析 `Verification OK`；未验证（sigtool 缺失或只有 `.cld`）会明确显示为“未验证/不适用”，不会当作通过。
- YARA 规则包必须由管理员放置并签名，lsec 不做在线规则订阅。
- 镜像构建依赖 Debian 软件源与 Docker Hub 的 `python:3.12-slim-bookworm`；生产环境应固定镜像 digest、使用内部镜像仓库并执行漏洞扫描。
- deb 包发布物包括 `lsec_<version>_all.deb`、源码包、`SHA256SUMS`；使用 `scripts/build-release.sh --sign-key <KEYID>` 可生成 GPG 分离签名，`scripts/verify-release.sh` 复核校验和与签名。
- 自动更新不覆盖自身程序；容器升级通过重建镜像，宿主机升级通过 `apt install`/`dpkg -i` 新 deb，旧版本可回滚（见部署文档）。
- systemd 单元默认启用 `NoNewPrivileges`、`ProtectSystem=strict`、`RestrictAddressFamilies`、空 capability 集，只允许写 `/var/lib/lsec`、`/var/log/lsec`、`/run/lsec`。

## 10. 已知残余风险

| 风险 | 说明 | 缓解 |
| --- | --- | --- |
| 容器内 root | 读取/移动挂载文件所需 | 最小化挂载范围；不挂载 Docker Socket；视为受信基础设施 |
| 无实时防护 | 容器内未启用 fanotify | UI 明确显示 `unsupported`，总状态为“防护不完整” |
| 无自动处置 | 设计选择 | 所有隔离/恢复/删除需人工确认 |
| HTTP 明文 | 默认回环；LAN 直连需显式开启 | SSH 隧道 / TLS 反向代理 / 配置证书 |
| 单节点 | 无中心管理端 | 备份 `/data`；后续阶段可扩展 |
| ClamAV 检测能力有限 | 签名引擎本身限制 | 不宣称 100% 防护；结果仅代表引擎实际返回 |
| 体检范围受限 | 容器只看到自身挂载、网络命名空间与内核参数 | UI/证据明确标注 `scope_note`；不把容器结果当作完整宿主机审计 |
| Lynis 警告非漏洞结论 | warning 是配置/运行状态提示，严重程度由固定规则映射 | 报告保留原始证据；不宣称主机被入侵 |
| Docker 代理高权限 | Socket 等价 host root；代理无法消除被控制后的风险 | 独立容器、GET 白名单、只读根文件系统、cap_drop ALL、internal 网络；不对外发布端口 |
| 容器检查为启发式 | 只检查配置，不检查镜像漏洞或运行时行为 | UI 明确说明；风险级别不是漏洞评分；不自动处置 |
| 容器清单仅 Docker | Containerd 仅探测，不采集清单 | 清单与范围说明明确标注来源；不把 Docker 数据冒充 containerd |
| Falco 运行状态未验证 | lsec 无法确认宿主侧进程与规则加载 | `running_verified=false`；能力状态与运行状态分开显示；不显示为已防护 |
| YARA 规则质量 | 规则命中取决于管理员投放的规则与签名信任 | 强制 SHA-256 + 可选签名；包不可变；事件保留规则与包版本；不宣称完整恶意软件检测 |
| Wazuh Manager 未验证 | lsec 只能看到本地 Agent 与本地告警文件 | 能力状态最多 `degraded`；界面固定显示“Manager 连接未验证”；不提供 Manager API |
| 规则扫描资源消耗 | 大目录 + 复杂规则可能占用 CPU/IO | 分批、超时、管理员主动触发；不提供常驻实时规则监控 |
| CVD 签名复核依赖 sigtool | 部分发行版/精简镜像可能未安装 | 明确显示“未验证”；freshclam 下载阶段仍执行其内建校验 |
