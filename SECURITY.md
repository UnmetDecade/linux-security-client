# Security Policy

**English** | [简体中文](SECURITY.zh-CN.md)

## Reporting security issues

Please do not disclose unpatched vulnerability details, exploit payloads, or real-environment data through public Issues.

Prefer reporting privately through the repository's **Security → Report a vulnerability** (GitHub Security Advisories), and include as much of the following as possible:

- Affected version or commit
- Reproduction steps and impact scope
- Whether tokens, path out-of-bounds, command execution, privilege escalation, or data leakage are involved

After the maintainers confirm, they will coordinate the fix and disclosure timeline.

## Security boundaries

See [docs/SECURITY.md](docs/SECURITY.md) for lsec's security model, trust boundaries, and known limitations. The following behaviors are design choices, not vulnerabilities:

- No automatic quarantine, deletion, process killing, or container stop/restart
- Does not provide Wazuh Manager capability
- Containerd is probe-only and provides no container inventory
- Unverified components or update signatures are never shown as "passed"
- Listens only on the loopback address by default; plaintext LAN access requires explicit enablement

## Support scope

Security fixes prioritize the current release version and the `main` branch. Vulnerabilities in third-party components (ClamAV, YARA, Lynis, Falco, Wazuh, Docker) themselves should also be reported to the corresponding upstream projects.
