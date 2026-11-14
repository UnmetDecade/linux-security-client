# 更新日志

[English](CHANGELOG.md) | **简体中文**

本文件记录项目中所有值得注意的变更。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [0.4.0] - 2026-11-14

### 新增

- 单实例守护进程，使用 SQLite + WAL 存储，事务化 schema 迁移并在迁移前自动备份。
- HTTP JSON API、原生 Web UI 与 `lsec` CLI，覆盖状态、组件、扫描、任务、事件、
  隔离区、审计、doctor 与导出。
- 管理员与只读角色；会话使用 HttpOnly、SameSite=Strict Cookie，写操作要求 CSRF 头。
- 组件探测覆盖 ClamAV、YARA、Lynis、Falco、Wazuh、Docker、Containerd 与 systemd，
  如实区分已安装、运行中与健康状态。
- ClamAV 按需扫描、病毒库状态、freshclam 更新，以及更新后的 CVD 签名复核。
- YARA 规则包：manifest 哈希、OpenSSL 签名校验、`yarac` 编译校验、版本激活与规则命中事件。
- 只读主机安全体检：账号、SSH 基线、敏感文件权限、监听端口、ASLR 与 AppArmor/SELinux。
- Lynis 集成：解析加固指数，并把警告归一化到统一事件中心。
- 通过独立只读 Docker API 代理读取容器清单并检查风险配置。
- 可选的本地 Wazuh Agent 探测与 `alerts.json` 摄取；明确不是 Wazuh Manager。
- 统一事件中心：确定性严重度映射、去重、筛选、状态流转与 JSON/CSV 导出。
- 隔离区：哈希校验、符号链接与路径越界拒绝，恢复与删除均需二次确认。
- Docker Compose 部署，以及带源码归档、`SHA256SUMS` 和可选 GPG 分离签名的
  Debian 安装包。
- 中英文 Web UI 与语言切换；默认英文。

### 安全

- 默认只监听本机回环地址；远程访问应使用 SSH 隧道或显式配置 TLS 反向代理。
- Web 进程不挂载 Docker Socket；容器监控走独立的只读代理。
- 不自动隔离、删除文件、终止进程或停止/重启容器。

[Unreleased]: https://github.com/UnmetDecade/linux-security-client/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/UnmetDecade/linux-security-client/releases/tag/v0.4.0
