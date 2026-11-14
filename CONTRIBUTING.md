# Contributing to lsec

**English** | [简体中文](CONTRIBUTING.zh-CN.md)

Thanks for taking the time to contribute. lsec is a security tool, so changes
are reviewed for both behavior and truthfulness: the UI must never claim a
capability is protecting the host when it is not installed, not enabled, or
could not be verified.

## Before you start

- For a suspected vulnerability, follow [SECURITY.md](SECURITY.md) instead of
  opening a public issue.
- For a new capability, open a feature request first. The README lists
  capabilities that are intentionally unsupported (automatic remediation, Falco
  auto-install, Wazuh Manager features, and so on).
- Keep pull requests focused. Separate refactors from behavior changes.

## Development setup

Requirements:

- Python 3.11 or newer (the code uses `tomllib` and `X | None` syntax)
- Node.js 22 for the web and documentation checks
- Docker with Compose for end-to-end runs (optional)

```bash
git clone https://github.com/UnmetDecade/linux-security-client.git
cd linux-security-client

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt

./scripts/test.sh
node scripts/check-web.js
```

The runtime has no third-party Python dependencies; `requirements-dev.txt` only
contains test tooling.

## Tests and coverage

The full suite uses the standard library test runner:

```bash
./scripts/test.sh
# equivalent to
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
```

Coverage is enforced in CI:

```bash
PYTHONPATH=src python3 -m coverage run -m unittest discover -s tests -t .
python3 -m coverage report --fail-under=64
python3 -m coverage json -o coverage.json
python3 scripts/check-coverage.py coverage.json
```

- The global floor is 64%.
- Modules on the critical path (HTTP API, auth, event mapping, host checks,
  YARA verification, quarantine, Docker API client, storage) have stricter
  per-file floors in [scripts/check-coverage.py](scripts/check-coverage.py).
- When you add tests, prioritize network clients, data mapping, operation
  payloads, and shared UI building blocks before page-level behavior.

The integration tests start a real daemon and HTTP server. They use test-only
fakes for clamd, Docker, YARA, and Wazuh; those fakes never ship in the image.

## Web UI and documentation checks

```bash
node --check src/lsec/web/app.js
node --check src/lsec/web/i18n.js
node scripts/check-web.js
```

`check-web.js` verifies syntax, English/Chinese key parity, unknown `t()` keys,
nested anchors in the docs landing pages, and broken relative links.

## Style

- Python: 4-space indentation, type hints where they clarify interfaces, no
  third-party runtime imports.
- JavaScript, CSS, HTML, YAML, JSON: 2 spaces.
- Shell: POSIX `sh` unless a script explicitly requires bash.
- Files use LF and end with a newline; see [.editorconfig](.editorconfig).
- Comments and user-facing strings are written in English first.
- Do not add features that mutate the host automatically (delete, quarantine,
  kill, stop/restart) without an explicit confirmation step and an audit entry.

## Keeping documentation bilingual

Every long-lived document has an English canonical file and a `.zh-CN.md`
counterpart, with a language switcher under the first heading. When you change
one side, update the other in the same pull request. Machine tokens (API field
names, enum values, CLI flags, environment variables) stay unchanged in both
versions.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(yara): verify pack signature before activation
fix(api): reject CSRF-less writes from cross-site origins
docs(deployment): document the read-only Docker proxy
test(hostchecks): cover missing shadow entries
```

Write commit messages in English. Add a body when the reason is not obvious
from the subject.

## Pull requests

1. Run the tests, coverage checks, and web checks locally.
2. Update [CHANGELOG.md](CHANGELOG.md) and
   [CHANGELOG.zh-CN.md](CHANGELOG.zh-CN.md) for user-visible changes.
3. Update documentation and its Chinese counterpart.
4. Fill in the pull request template, including the testing you performed.
5. Confirm the change contains no tokens, private keys, host data, or scan
   evidence.

CI must pass before a pull request can merge. A maintainer performs the final
review and squash merge.

## License

By contributing, you agree that your contributions are licensed under the MIT
License in [LICENSE](LICENSE).
