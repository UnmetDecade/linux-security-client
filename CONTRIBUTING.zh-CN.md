# 为 lsec 贡献代码

[English](CONTRIBUTING.md) | **简体中文**

感谢你抽出时间参与贡献。lsec 是安全工具，因此变更会同时审查行为和“如实性”：
当某项能力未安装、未启用或无法验证时，UI 绝不能声称它正在保护主机。

## 开始之前

- 如果发现疑似漏洞，请按 [SECURITY.zh-CN.md](SECURITY.zh-CN.md) 私密上报，
  不要开公开 issue。
- 新能力请先提交 feature request。README 列出了有意不支持的能力
  （自动修复、自动安装 Falco、Wazuh Manager 等）。
- 保持 PR 聚焦，重构和行为变更分开提交。

## 开发环境

要求：

- Python 3.11 或更高版本（代码使用 `tomllib` 与 `X | None` 语法）
- Node.js 22，用于 Web 与文档检查
- Docker + Compose，用于端到端验证（可选）

```bash
git clone https://github.com/UnmetDecade/linux-security-client.git
cd linux-security-client

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt

./scripts/test.sh
node scripts/check-web.js
```

运行时没有第三方 Python 依赖；`requirements-dev.txt` 只包含测试工具。

## 测试与覆盖率

完整测试套件使用标准库测试运行器：

```bash
./scripts/test.sh
# 等价于
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

CI 会强制覆盖率门槛：

```bash
PYTHONPATH=src python3 -m coverage run -m unittest discover -s tests -t .
python3 -m coverage report --fail-under=64
python3 -m coverage json -o coverage.json
python3 scripts/check-coverage.py coverage.json
```

- 全局门槛为 64%。
- 关键路径模块（HTTP API、认证、事件映射、主机体检、YARA 校验、隔离区、
  Docker API 客户端、存储）在 [scripts/check-coverage.py](scripts/check-coverage.py)
  中有更严格的单文件门槛。
- 补测试时，优先覆盖网络客户端、数据映射、操作载荷与共享 UI 基础组件，
  最后再覆盖页面级行为。

集成测试会启动真实守护进程和 HTTP 服务。clamd、Docker、YARA、Wazuh 使用仅测试
用的假实现，不会进入镜像。

## Web UI 与文档检查

```bash
node --check src/lsec/web/app.js
node --check src/lsec/web/i18n.js
node scripts/check-web.js
```

`check-web.js` 会检查语法、中英文 key 对齐、未知 `t()` key、落地页中的嵌套
`<a>`，以及失效的相对链接。

## 代码风格

- Python：4 空格缩进；在能说明接口时使用类型标注；不引入第三方运行时依赖。
- JavaScript、CSS、HTML、YAML、JSON：2 空格。
- Shell：除非脚本明确要求 bash，否则使用 POSIX `sh`。
- 文件使用 LF 并以换行结尾，详见 [.editorconfig](.editorconfig)。
- 注释与用户可见文案先写英文。
- 未经显式确认和审计记录，不要添加自动修改主机的功能（删除、隔离、终止进程、
  停止/重启）。

## 文档双语

每份长期文档都有英文正本和 `.zh-CN.md` 中文版，并在首个标题下带语言切换。
修改一侧时，请在同一个 PR 中同步另一侧。机器标识（API 字段名、枚举值、CLI 参数、
环境变量）在两种语言中保持不变。

## 提交信息

遵循 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)：

```text
feat(yara): verify pack signature before activation
fix(api): reject CSRF-less writes from cross-site origins
docs(deployment): document the read-only Docker proxy
test(hostchecks): cover missing shadow entries
```

提交信息使用英文；原因不明显时在正文中说明。

## Pull Request

1. 本地运行测试、覆盖率检查与 Web 检查。
2. 用户可见变更同步更新 [CHANGELOG.md](CHANGELOG.md) 与
   [CHANGELOG.zh-CN.md](CHANGELOG.zh-CN.md)。
3. 更新文档及其中文对照版。
4. 填写 PR 模板，说明你实际执行过的验证。
5. 确认变更中不含令牌、私钥、主机数据或扫描证据。

CI 全部通过后才能合并；由维护者做最终审查并以 squash 方式合并。

## 许可证

提交贡献即表示你同意以 [LICENSE](LICENSE) 中的 MIT 许可证授权你的贡献。
