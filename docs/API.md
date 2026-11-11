# HTTP API

基础路径：`/api/v1`。所有响应为 JSON（导出接口除外）。成功响应包含 `"ok": true`；失败响应为：

```json
{
  "ok": false,
  "error": {
    "code": "invalid_argument",
    "message": "人类可读的说明",
    "details": {"...": "可选"},
    "request_id": "..."
  }
}
```

## 认证

### Bearer Token（CLI）

```http
Authorization: Bearer <token>
```

### Web 会话

`POST /api/v1/auth/login` 成功后设置 HttpOnly、SameSite=Strict 的 `lsec_session` Cookie，并在响应体返回一次性 `csrf_token`。后续写操作（POST/PATCH/DELETE）必须同时携带：

```http
X-LSEC-CSRF: <csrf_token>
```

Cookie 会话的写请求如果带 `Origin`，其 host 必须与 `Host` 一致。

### 角色

| 角色 | 权限 |
| --- | --- |
| `admin` | 读取 + 扫描/取消、组件启停/更新、事件状态、隔离/恢复/删除、容器刷新、策略修改、日志 |
| `viewer` | 读取状态、组件、任务、事件、隔离区、审计、自检、设置、容器清单 |
| `integration` | 仅 Falco 事件接入；不能读取任何其他 API |

令牌文件：`/data/secrets/admin.token`、`/data/secrets/viewer.token`，权限 0600。也可用 `LSEC_ADMIN_TOKEN` / `LSEC_VIEWER_TOKEN` 覆盖（至少 16 字符）。

Falco 使用独立令牌 `/data/secrets/falco.token`（启用 `falco.ingest_enabled` 时自动创建，0600）。它不在管理员/只读令牌表中，反向也不允许管理员/只读令牌调用 Falco 接入端点。

## 通用

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/health` | 公开 | 存活检查 |
| POST | `/auth/login` | 公开 | 登录，返回角色与 CSRF |
| POST | `/auth/logout` | 登录 | 注销当前会话 |
| GET | `/version` | 登录 | 守护进程/API 版本 |
| GET | `/system/info` | 登录 | 主机与守护进程信息 |
| GET | `/status` | 登录 | 汇总防护状态 |
| GET | `/capabilities` | 登录 | 能力矩阵 |

`/status` 示例（节选）：

```json
{
  "ok": true,
  "status": {
    "overall": "protection_incomplete",
    "overall_label": "防护不完整",
    "protection": {
      "on_demand": {"state": "ready", "reason": "ClamAV 按需扫描可用"},
      "real_time": {"state": "unsupported", "supported": false, "reason": "..."},
      "virus_database": {"state": "current", "updated_at": "...", "age_hours": 1.2}
    },
    "events": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "total_open": 1},
    "last_scan": {"task_type": "quick", "status": "succeeded", "...": "..."}
  }
}
```

## 组件

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/components` | 登录 | 组件真实状态 |
| POST | `/components/probe` | admin | 重新探测全部组件 |
| GET | `/components/{id}/install-plan` | 登录 | 安装来源与权限说明 |
| POST | `/components/clamav/start` | admin | 启动 clamd |
| POST | `/components/clamav/stop` | admin | 停止 clamd |
| POST | `/components/clamav/update` | admin | freshclam 更新病毒库 |

更新返回 `{"ok": true, "update": {"ok": true, "exit_code": 0, "duration_seconds": 12.3, "output_tail": "...", "database": {...}}}`。

## 扫描任务

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/scans?status=&limit=&offset=` | 登录 | 任务列表 |
| POST | `/scans` | admin | 创建任务 |
| GET | `/scans/{task_id}` | 登录 | 任务详情 |
| POST | `/scans/{task_id}/cancel` | admin | 请求取消 |

创建请求：

```json
{"type": "quick", "engines": ["clamav"]}
{"type": "full", "engines": ["clamav", "yara"]}
{"type": "custom", "paths": ["/scan/downloads"], "engines": ["clamav", "yara"]}
{"type": "yara", "paths": ["/scan/downloads"], "engines": ["yara"]}
```

`type` 支持 `quick/full/custom/yara`；`engines` 支持 `clamav`、`yara`，缺省为 `["clamav"]`。`type=yara` 只允许 YARA 引擎且必须提供 `paths`。自定义路径必须存在且位于 `scan.allowed_roots` 内。多引擎扫描时单个引擎失败记为部分完成并保留各引擎错误；全部引擎失败才是 `failed`。任务状态：

`queued`、`running`、`cancel_requested`、`cancelled`、`succeeded`、`failed`、`partial`。

`progress` 在文件总数未知时为 `null`。`result_summary.detections_sample` 最多 500 条；证据报告路径为 `result_summary.evidence_path`。

## 安全事件

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/events?severity=&source=&category=&status=&q=&since=&until=&limit=&offset=` | 登录 | 列表 |
| GET | `/events/{event_id}` | 登录 | 详情 |
| PATCH | `/events/{event_id}` | admin | 状态流转与备注 |
| GET | `/events/export?format=json|csv&...` | 登录 | 导出（最多 5000 条） |

状态流转：

```
new -> acknowledged | investigating | resolved | ignored
acknowledged -> investigating | resolved | ignored
investigating -> resolved | ignored
resolved -> new
ignored -> new
```

PATCH 请求：`{"status": "acknowledged", "note": "已人工核实"}`。

CSV 导出对以 `= + - @` 开头的单元格加 `'` 前缀，避免电子表格公式注入。

## 隔离区

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/quarantine?status=&limit=&offset=` | 登录 | 列表 |
| POST | `/quarantine` | admin | 隔离文件 |
| GET | `/quarantine/{item_id}` | 登录 | 详情（含 `file_exists`、`stored_path`） |
| POST | `/quarantine/{item_id}/restore` | admin | 恢复 |
| POST | `/quarantine/{item_id}/delete` | admin | 永久删除 |

隔离请求必须包含 `"confirm": true`：

```json
{
  "path": "/scan/eicar.txt",
  "detection_name": "Eicar-Signature",
  "engine": "clamav",
  "event_id": "<可选>",
  "confirm": true
}
```

恢复/删除请求体：`{"confirm": true}`。

## 主机体检

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/audits?limit=20&offset=0` | 登录 | 体检历史（不含大字段），并返回当前排队/运行的体检 |
| POST | `/audits` | admin | 创建只读主机体检，返回 202；已有体检运行时返回 409 |
| GET | `/audits/{audit_id}` | 登录 | 体检详情，含 `result_summary.checks`、Lynis 结果与证据路径 |

体检状态：`queued`、`running`、`succeeded`、`partial`、`failed`。检查状态：`pass`、`finding`、`error`、`skipped`；只有 `finding` 会生成统一事件，`error` 表示检查未能执行，不代表存在风险。

`POST /audits` 不需要请求体，返回：

```json
{"ok": true, "audit": {"audit_id": "...", "status": "queued", "scope": "container"}}
```

体检在后台串行执行；客户端应轮询 `GET /audits/{audit_id}` 直到状态进入 `succeeded/partial/failed`。详情中的关键字段：

- `findings_count`、`errors_count`、`severity_counts`
- `hardening_index`、`lynis_available`、`lynis_version`
- `evidence_path`：`report.json` 与原始 `lynis-report.dat` / `lynis.log` 所在目录
- `result_summary.scope_note`、`limitations`、`system_info`、`counts`

体检不会修改系统配置，也不会自动修复或处置。

## 容器安全

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/containers` | 登录 | 容器监控快照：状态、引擎信息、清单、汇总、限制说明 |
| GET | `/containers/{ref}` | 登录 | 单个容器详情；`ref` 可为完整 ID、唯一 ID 前缀或容器名称 |
| POST | `/containers/refresh` | admin | 立即执行一次只读采集并写入审计 `container.refresh` |
| GET | `/falco` | 登录 | Falco 组件、能力、事件接入统计 |
| POST | `/integrations/falco` | integration | 接收 Falco JSON 告警，返回 202 |

容器监控状态：`disabled`、`initializing`、`monitored`、`degraded`、`unavailable`、`permission_denied`。失败时保留的上次快照会带 `stale: true`；从未成功时清单为空，不会返回虚构数据。

单个容器风险级别：`critical`、`high`、`medium`、`low`、`none`、`unknown`。`evaluated: false` 表示详情字段不足或读取失败，`risk_level` 为 `unknown`，**不能**解读为安全。

`GET /containers` 响应节选：

```json
{
  "ok": true,
  "containers": {
    "state": "monitored",
    "note": "已读取 3 个容器，运行中 2 个；3 个存在配置风险",
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
    "scope_note": "容器清单来自 Docker Engine API…",
    "limitations": ["…"]
  }
}
```

`GET /falco` 返回组件探测结果（`component.details.capability` 含内核、BTF、capability 状态）以及 `event_ingest.enabled/endpoint/token_path/events_total/last_event_at`。只显示令牌路径，不显示令牌内容。

### Falco 事件接入

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

成功返回 `202`：

```json
{"ok": true, "event_id": "...", "created": true}
```

同一规则、容器和进程在去重窗口内重复上报时 `created` 为 `false`，事件 `occurrences` 累加。请求体上限由 `falco.max_event_bytes` 控制（默认 32 KB）；非法 JSON、非对象、缺少规则/输出或 `output_fields` 非对象会返回 400。接入限速 240 次/分钟。

本版本**不存在**容器停止、重启、删除、执行命令的 API；任何此类请求都会 404。

## YARA 规则包

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/yara` | 登录 | 组件、活跃规则包、签名配置与扫描就绪状态 |
| GET | `/yara/packs` | 登录 | 所有规则包及版本（含激活标记与签名校验结果） |
| POST | `/yara/packs` | admin | 从 inbox 安装规则包 |
| POST | `/yara/packs/{pack_id}/{version}/activate` | admin | 激活指定版本 |
| DELETE | `/yara/packs/{pack_id}/{version}` | admin | 删除指定版本 |

安装请求：

```json
{"path": "/data/yara/inbox/pack.zip", "activate": true, "confirm": true}
```

- `confirm` 必须为 `true`，否则返回 400；安装/激活/删除均写入审计。
- 源文件必须位于 `yara.inbox_dir` 内；拒绝符号链接、路径穿越、未声明文件、SHA-256 不符、`yarac` 编译失败和同版本覆盖。
- `yara.require_signature=true` 时必须存在有效 `manifest.sig` 与已配置公钥；签名验证失败返回 400。
- 成功安装返回 201：`{"ok":true,"pack":{...},"component":{...}}`。
- 规则包格式与签名步骤见 [部署与运维](DEPLOYMENT.md)。

## Wazuh（可选，仅本地）

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/wazuh` | 登录 | 本地 Agent 探测、Manager 配置摘要、告警接入状态 |
| GET | `/wazuh/install-plan` | 登录 | 只读安装/注册计划（不会自动执行） |

`/wazuh` 返回的 `state` 只会是 `disabled/unavailable/degraded/unknown/available`，且 `connection_verified` 恒为 `false`。`ingest` 只描述本地 `alerts.json` 的新增行接入：

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
  "note": "仅接入本地 Wazuh Agent alerts.json 的新增行；不是 Wazuh Manager，也不验证 Manager 连接"
}
```

- 本客户端不联系 Wazuh Manager、不提供 Manager API、不管理其他 Agent。
- 接入事件为 `source=wazuh`；`source_ref.manager_connection_verified=false`。
- 首次启用从文件末尾开始，不导入历史告警；Agent 未运行、Manager 未配置或连接未验证均显示为降级。
- 安装计划 `installable_from_ui=false`，仅列出管理员需在宿主机执行的步骤。

## 审计、设置、自检、日志

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/audit?limit=&offset=&action=` | 登录 | 操作审计 |
| GET | `/doctor` | 登录 | 运行环境自检（会触发组件探测） |
| GET | `/settings` | 登录 | 运行时设置与可编辑范围 |
| PATCH | `/settings` | admin | 修改策略 |
| GET | `/logs?lines=200` | admin | 守护进程日志尾部 |

设置项只有：`response_mode`（`alert/suggest`；`auto` 返回 501）、`auto_quarantine_enabled`（true 返回 501）、`scheduled_scan`（`enabled`、`type`、`interval_hours` 1–720、`last_run_at`）。

## 错误码

| code | HTTP | 含义 |
| --- | --- | --- |
| `invalid_argument` | 400 | 参数/路径/状态转换无效 |
| `unauthorized` | 401 | 未认证或令牌无效 |
| `forbidden` | 403 | 角色不足、CSRF/Origin 校验失败 |
| `not_found` | 404 | 资源不存在 |
| `conflict` | 409 | 状态冲突、队列满、路径被占用、哈希不符 |
| `rate_limited` | 429 | 登录过于频繁 |
| `component_unavailable` | 503 | ClamAV 未安装/未运行/病毒库缺失 |
| `not_implemented` | 501 | 后续阶段能力或未实现的自动处置 |
| `internal_error` | 500 | 内部错误，响应内含请求 ID |

## curl 示例

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

# Falco 接入必须使用独立令牌（不要把管理员令牌用于接入）
FALCO_TOKEN=$(docker compose exec -T lsec cat /data/secrets/falco.token)
curl -s -X POST -H "Authorization: Bearer $FALCO_TOKEN" -H 'Content-Type: application/json' \
     -d @falco-event.json http://127.0.0.1:8080/api/v1/integrations/falco
```
