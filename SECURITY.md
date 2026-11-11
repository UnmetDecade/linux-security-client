# Security Policy

## 报告安全问题

请不要通过公开 Issue 披露未修复的漏洞细节、可利用载荷或真实环境数据。

优先使用仓库的 **Security → Report a vulnerability**（GitHub Security Advisories）私下报告，并尽量包含：

- 受影响版本或提交
- 复现步骤与影响范围
- 是否涉及令牌、路径越界、命令执行、权限提升或数据泄露

维护者确认后会协调修复与披露时间。

## 安全边界

lsec 的安全模型、信任边界与已知限制见 [docs/SECURITY.md](docs/SECURITY.md)。以下行为属于设计选择，不是漏洞：

- 不自动隔离、删除、杀进程或停止/重启容器
- 不提供 Wazuh Manager 能力
- Containerd 仅探测，不提供容器清单
- 未验证的组件或更新签名不会显示为“已通过”
- 默认仅监听回环地址；局域网明文访问需要显式开启

## 支持范围

安全修复优先覆盖当前发布版本及 `main` 分支。第三方组件（ClamAV、YARA、Lynis、Falco、Wazuh、Docker）本身的漏洞应同时报告给对应上游项目。
