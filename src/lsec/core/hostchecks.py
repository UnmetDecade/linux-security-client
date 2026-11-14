"""Read-only host baseline checks.

Every check is observational. Nothing in this module writes system files,
changes sysctl values, reloads services or executes a shell. A check that
cannot run is reported as ``error`` and is never converted into a risk finding.
"""

from __future__ import annotations

import glob
import os
import stat
from dataclasses import dataclass, field
from typing import Any, Callable

from ..common.executor import run, which
from ..common.hostinfo import host_info

PASS = "pass"
FINDING = "finding"
ERROR = "error"
SKIPPED = "skipped"
CHECK_STATUSES = (PASS, FINDING, ERROR, SKIPPED)

_MAX_FILE = 128 * 1024
_MAX_DETAIL = 2000


@dataclass
class CheckResult:
    check_id: str
    category: str
    title: str
    status: str
    severity: str | None = None
    detail: str = ""
    remediation: str | None = None
    source: str = "system"
    target: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    dedup_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "detail": (self.detail or "")[:_MAX_DETAIL],
            "remediation": self.remediation,
            "source": self.source,
            "target": self.target,
            "evidence": self.evidence,
            "dedup_hint": self.dedup_hint,
        }


def _rooted(root: str, path: str) -> str:
    root = root.rstrip("/")
    if not root:
        return path
    return f"{root}{path}"


def _read(path: str, *, limit: int = _MAX_FILE) -> tuple[str | None, str | None]:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"
    if not stat.S_ISREG(st.st_mode):
        return None, f"{path} is not a regular file"
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"


def _result(
    check_id: str,
    category: str,
    title: str,
    status: str,
    *,
    severity: str | None = None,
    detail: str = "",
    remediation: str | None = None,
    target: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    dedup_hint: str | None = None,
    source: str = "system",
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category=category,
        title=title,
        status=status,
        severity=severity,
        detail=detail[:_MAX_DETAIL],
        remediation=remediation,
        source=source,
        target=target or {"type": "host"},
        evidence=evidence or {},
        dedup_hint=dedup_hint,
    )


def parse_passwd(text: str) -> tuple[list[dict[str, str]], int]:
    entries: list[dict[str, str]] = []
    malformed = 0
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            malformed += 1
            continue
        entries.append(
            {
                "name": parts[0],
                "uid": parts[2],
                "gid": parts[3],
                "home": parts[5],
                "shell": parts[6],
            }
        )
    return entries, malformed


def parse_shadow(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        # Never retain or report the password hash itself.
        entries.append({"name": parts[0], "password": parts[1]})
    return entries


def parse_proc_net_tcp(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[1]
        if ":" not in local:
            continue
        raw_addr, raw_port = local.rsplit(":", 1)
        try:
            port = int(raw_port, 16)
        except ValueError:
            continue
        if fields[3] != "0A":  # TCP_LISTEN
            continue
        rows.append({"address": raw_addr, "port": port, "state": fields[3]})
    return rows


def _address_kind(raw: str) -> str:
    if not raw:
        return "unknown"
    if raw in {
        "00000000",
        "00000000000000000000000000000000",
        "0000000000000000FFFF000000000000",
    }:
        return "wildcard"
    # 127.0.0.0/8 is stored little-endian, so the first octet is the last byte.
    if len(raw) == 8 and raw.endswith("7F"):
        return "loopback"
    if raw == "00000000000000000000000001000000":
        return "loopback"
    # IPv4-mapped IPv6 loopback addresses (::ffff:127.0.0.0/8).
    if len(raw) == 32 and raw.startswith("0000000000000000FFFF0000") and raw.endswith("7F"):
        return "loopback"
    return "external"


def _ssh_config_texts(root: str) -> tuple[list[tuple[str, str]], list[str]]:
    files: list[tuple[str, str]] = []
    notes: list[str] = []
    main = _rooted(root, "/etc/ssh/sshd_config")
    text, error = _read(main)
    if text is None:
        if error and error != "missing":
            notes.append(error)
        return files, notes
    files.append((main, text))
    pattern = _rooted(root, "/etc/ssh/sshd_config.d/*.conf")
    for path in sorted(glob.glob(pattern)):
        value, read_error = _read(path)
        if value is not None:
            files.append((path, value))
        elif read_error and read_error != "missing":
            notes.append(read_error)
    return files, notes


def parse_ssh_config(
    files: list[tuple[str, str]]
) -> tuple[dict[str, str], list[str]]:
    """Return explicit global directives and parser limitations.

    Match blocks are conditional and are deliberately excluded from the
    conclusion. Include expansion is approximated with sshd_config.d/*.conf;
    the note makes that limitation visible.
    """
    values: dict[str, str] = {}
    notes: list[str] = []
    saw_match = False
    for _path, text in files:
        in_match = False
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            stripped = stripped.split("#", 1)[0].strip()
            parts = stripped.split(None, 1)
            if not parts:
                continue
            key = parts[0].lower()
            if key == "match":
                in_match = True
                saw_match = True
                continue
            if in_match:
                continue
            if len(parts) == 1:
                continue
            values[key] = parts[1].strip().strip('"')
    if saw_match:
        notes.append("Match blocks were not included in the global conclusion")
    if len(files) > 1:
        notes.append("sshd_config.d/*.conf files were merged; Include positional semantics were not fully expanded")
    return values, notes


def _check_uid0(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/etc/passwd"))
    if text is None:
        return [
            _result(
                "AUTH-UID0",
                "users",
                "UID 0 account check",
                ERROR,
                detail=f"cannot read /etc/passwd: {error}",
            )
        ]
    entries, malformed = parse_passwd(text)
    if not entries:
        return [
            _result(
                "AUTH-UID0",
                "users",
                "UID 0 account check",
                ERROR,
                detail=f"/etc/passwd has no valid account records ({malformed} malformed lines)",
            )
        ]
    roots = [entry["name"] for entry in entries if entry["uid"] == "0"]
    extras = [name for name in roots if name != "root"]
    if extras:
        return [
            _result(
                "AUTH-UID0",
                "users",
                "Additional UID 0 account found",
                FINDING,
                severity="high",
                detail=f"UID 0 account exists besides root: {', '.join(extras)}",
                remediation="Verify the origin of these accounts, remove unneeded privileged accounts, and audit their login records.",
                target={"type": "user", "name": name},
                evidence={"accounts": extras},
                dedup_hint=f"uid0:{name}",
            )
            for name in extras
        ]
    return [
        _result(
            "AUTH-UID0",
            "users",
            "UID 0 account check",
            PASS,
            detail="only root has UID 0",
        )
    ]


def _check_empty_passwords(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/etc/shadow"))
    if text is None:
        if error == "missing":
            return [
                _result(
                    "AUTH-EMPTY-PASSWORD",
                    "users",
                    "Empty password account check",
                    SKIPPED,
                    detail="/etc/shadow does not exist; empty password accounts were not evaluated",
                )
            ]
        return [
            _result(
                "AUTH-EMPTY-PASSWORD",
                "users",
                "Empty password account check",
                ERROR,
                detail=f"cannot read /etc/shadow: {error}",
            )
        ]
    empty = [entry["name"] for entry in parse_shadow(text) if entry["password"] == ""]
    if empty:
        return [
            _result(
                "AUTH-EMPTY-PASSWORD",
                "users",
                "Empty password account found",
                FINDING,
                severity="critical",
                detail=f"the following accounts have an empty password field: {', '.join(empty)}",
                remediation="Set a strong password or lock these accounts immediately, and check the authentication logs.",
                target={"type": "user", "name": name},
                evidence={"accounts": empty},
                dedup_hint=f"empty-password:{name}",
            )
            for name in empty
        ]
    return [
        _result(
            "AUTH-EMPTY-PASSWORD",
            "users",
            "Empty password account check",
            PASS,
            detail="no empty password accounts found (only the password field is checked; hash contents are not read)",
        )
    ]


def _check_duplicate_uid(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/etc/passwd"))
    if text is None:
        return [
            _result(
                "AUTH-DUPLICATE-UID",
                "users",
                "Duplicate UID check",
                ERROR,
                detail=f"cannot read /etc/passwd: {error}",
            )
        ]
    entries, _malformed = parse_passwd(text)
    by_uid: dict[str, list[str]] = {}
    for entry in entries:
        if entry["uid"] == "0":
            continue
        by_uid.setdefault(entry["uid"], []).append(entry["name"])
    duplicates = {uid: names for uid, names in by_uid.items() if len(names) > 1}
    if duplicates:
        return [
            _result(
                "AUTH-DUPLICATE-UID",
                "users",
                "Duplicate non-root UIDs found",
                FINDING,
                severity="medium",
                detail="; ".join(
                    f"UID {uid}: {', '.join(names)}"
                    for uid, names in sorted(duplicates.items())
                ),
                remediation="Confirm whether shared UIDs are an intended configuration; if not, assign distinct UIDs and check file ownership.",
                evidence={
                    "duplicates": [
                        {"uid": uid, "accounts": names}
                        for uid, names in sorted(duplicates.items())
                    ]
                },
                dedup_hint="duplicate-uid:" + ",".join(sorted(duplicates)),
            )
        ]
    return [
        _result(
            "AUTH-DUPLICATE-UID",
            "users",
            "Duplicate UID check",
            PASS,
            detail="no duplicate non-root UIDs found",
        )
    ]


def _file_mode_finding(
    root: str, path: str, *, forbidden_mask: int, severity: str, title: str
) -> CheckResult | None | str:
    target = _rooted(root, path)
    try:
        st = os.stat(target)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"{path}: {exc}"
    if not stat.S_ISREG(st.st_mode):
        return f"{path}: not a regular file"
    mode = stat.S_IMODE(st.st_mode)
    if mode & forbidden_mask:
        return _result(
            "PERM-SENSITIVE-FILE",
            "permissions",
            title,
            FINDING,
            severity=severity,
            detail=f"{path} permissions are {mode:04o} and include unsafe group/other access bits",
            remediation=f"Tighten {path} permissions to the distribution-recommended value and check ownership.",
            target={"type": "file", "path": path},
            evidence={"path": path, "mode": f"{mode:04o}", "forbidden_mask": f"{forbidden_mask:04o}"},
            dedup_hint=f"perm:{path}",
        )
    return None


def _check_sensitive_permissions(root: str) -> list[CheckResult]:
    specs = (
        ("/etc/passwd", 0o022, "high", "sensitive account file is writable by group or other users"),
        ("/etc/group", 0o022, "high", "sensitive group file is writable by group or other users"),
        ("/etc/shadow", 0o026, "high", "password hash file permissions are too broad"),
        ("/etc/gshadow", 0o026, "high", "group password file permissions are too broad"),
    )
    findings: list[CheckResult] = []
    errors: list[str] = []
    checked = 0
    for path, mask, severity, title in specs:
        try:
            os.stat(_rooted(root, path))
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            continue
        checked += 1
        item = _file_mode_finding(
            root, path, forbidden_mask=mask, severity=severity, title=title
        )
        if isinstance(item, CheckResult):
            findings.append(item)
        elif isinstance(item, str):
            errors.append(item)
    results: list[CheckResult] = list(findings)
    if errors:
        results.append(
            _result(
                "PERM-SENSITIVE-FILE",
                "permissions",
                "Sensitive file permission check",
                ERROR,
                detail="; ".join(errors),
            )
        )
    if not findings and not errors:
        if checked:
            results.append(
                _result(
                    "PERM-SENSITIVE-FILE",
                    "permissions",
                    "Sensitive file permission check",
                    PASS,
                    detail=f"checked {checked} files; no group/other writable or password-file readable issues found",
                )
            )
        else:
            results.append(
                _result(
                    "PERM-SENSITIVE-FILE",
                    "permissions",
                    "Sensitive file permission check",
                    SKIPPED,
                    detail="/etc/passwd, /etc/shadow and similar files do not exist",
                )
            )
    return results


def _check_ssh(root: str) -> list[CheckResult]:
    files, notes = _ssh_config_texts(root)
    if not files:
        detail = "no /etc/ssh/sshd_config found; the OpenSSH server is not installed or the container has not mounted the configuration, so the SSH baseline was not evaluated"
        if notes:
            detail += f" ({'; '.join(notes)})"
        return [
            _result(
                "SSH-BASELINE",
                "ssh",
                "SSH baseline check",
                SKIPPED,
                detail=detail,
            )
        ]
    values, parse_notes = parse_ssh_config(files)
    notes.extend(parse_notes)
    results: list[CheckResult] = []
    suffix = f" (limitations: {'; '.join(notes)})" if notes else ""

    root_login = values.get("permitrootlogin")
    if root_login is None:
        results.append(
            _result(
                "SSH-ROOT-LOGIN",
                "ssh",
                "SSH root login check",
                SKIPPED,
                detail="PermitRootLogin is not explicitly configured; Include/Match semantics were not fully expanded, so no conclusion is drawn" + suffix,
            )
        )
    elif root_login.lower() == "yes":
        results.append(
            _result(
                "SSH-ROOT-LOGIN",
                "ssh",
                "SSH allows direct root login",
                FINDING,
                severity="high",
                detail="PermitRootLogin yes" + suffix,
                remediation="Set PermitRootLogin to no or prohibit-password, and reload sshd.",
                target={"type": "config", "path": "/etc/ssh/sshd_config"},
                evidence={"directive": "PermitRootLogin", "value": root_login},
                dedup_hint="ssh:permitrootlogin",
            )
        )
    else:
        results.append(
            _result(
                "SSH-ROOT-LOGIN",
                "ssh",
                "SSH root login check",
                PASS,
                detail=f"PermitRootLogin {root_login}" + suffix,
            )
        )

    password_auth = values.get("passwordauthentication")
    if password_auth is None:
        results.append(
            _result(
                "SSH-PASSWORD-AUTH",
                "ssh",
                "SSH password authentication check",
                SKIPPED,
                detail="PasswordAuthentication is not explicitly configured; no conclusion is drawn" + suffix,
            )
        )
    elif password_auth.lower() == "yes":
        results.append(
            _result(
                "SSH-PASSWORD-AUTH",
                "ssh",
                "SSH password authentication enabled",
                FINDING,
                severity="medium",
                detail="PasswordAuthentication yes; prefer key-based authentication if not required" + suffix,
                remediation="Keep this only if the business requires it; otherwise set PasswordAuthentication no and configure key-based login.",
                target={"type": "config", "path": "/etc/ssh/sshd_config"},
                evidence={"directive": "PasswordAuthentication", "value": password_auth},
                dedup_hint="ssh:passwordauthentication",
            )
        )
    else:
        results.append(
            _result(
                "SSH-PASSWORD-AUTH",
                "ssh",
                "SSH password authentication check",
                PASS,
                detail=f"PasswordAuthentication {password_auth}" + suffix,
            )
        )

    empty = values.get("permitemptypasswords")
    if empty is None:
        results.append(
            _result(
                "SSH-EMPTY-PASSWORDS",
                "ssh",
                "SSH empty password login check",
                SKIPPED,
                detail="PermitEmptyPasswords is not explicitly configured; no conclusion is drawn" + suffix,
            )
        )
    elif empty.lower() == "yes":
        results.append(
            _result(
                "SSH-EMPTY-PASSWORDS",
                "ssh",
                "SSH allows empty password login",
                FINDING,
                severity="critical",
                detail="PermitEmptyPasswords yes" + suffix,
                remediation="Set PermitEmptyPasswords no immediately and lock accounts with empty passwords.",
                target={"type": "config", "path": "/etc/ssh/sshd_config"},
                evidence={"directive": "PermitEmptyPasswords", "value": empty},
                dedup_hint="ssh:permitemptypasswords",
            )
        )
    else:
        results.append(
            _result(
                "SSH-EMPTY-PASSWORDS",
                "ssh",
                "SSH empty password login check",
                PASS,
                detail=f"PermitEmptyPasswords {empty}" + suffix,
            )
        )

    main_path = _rooted(root, "/etc/ssh/sshd_config")
    try:
        st = os.stat(main_path)
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o022:
            results.append(
                _result(
                    "SSH-CONFIG-PERMS",
                    "ssh",
                    "SSH configuration file permissions are too broad",
                    FINDING,
                    severity="medium",
                    detail=f"/etc/ssh/sshd_config permissions are {mode:04o}; group or other users can write to it",
                    remediation="Run chmod 600 /etc/ssh/sshd_config (owned by root) and check whether it has been tampered with.",
                    target={"type": "file", "path": "/etc/ssh/sshd_config"},
                    evidence={"mode": f"{mode:04o}"},
                    dedup_hint="ssh:config-perms",
                )
            )
        else:
            results.append(
                _result(
                    "SSH-CONFIG-PERMS",
                    "ssh",
                    "SSH configuration file permission check",
                    PASS,
                    detail=f"/etc/ssh/sshd_config permissions {mode:04o}",
                )
            )
    except OSError as exc:
        results.append(
            _result(
                "SSH-CONFIG-PERMS",
                "ssh",
                "SSH configuration file permission check",
                ERROR,
                detail=f"cannot read /etc/ssh/sshd_config attributes: {exc}",
            )
        )
    return results


_DANGEROUS_PORTS: dict[int, tuple[str, str | None, str]] = {
    21: ("FTP", "medium", "plaintext file transfer service"),
    23: ("Telnet", "high", "plaintext remote login service"),
    69: ("TFTP", "high", "unauthenticated file transfer service"),
    111: ("rpcbind", "low", "RPC port mapping service"),
    512: ("rexec", "high", "legacy plaintext remote execution service"),
    513: ("rlogin", "high", "legacy plaintext remote login service"),
    514: ("rsh", "high", "legacy plaintext remote shell service"),
    2375: ("Docker API", "critical", "unencrypted and typically unauthenticated container runtime API"),
}


def _check_ports(root: str) -> list[CheckResult]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    read_any = False
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        text, error = _read(_rooted(root, name))
        if text is None:
            if error and error != "missing":
                errors.append(f"{name}: {error}")
            continue
        read_any = True
        rows.extend(parse_proc_net_tcp(text))
    if not read_any:
        return [
            _result(
                "PORT-DANGEROUS",
                "ports",
                "Dangerous listening port check",
                ERROR,
                detail="cannot read /proc/net/tcp and /proc/net/tcp6; listening ports were not evaluated"
                + (f" ({'; '.join(errors)})" if errors else ""),
            )
        ]
    findings: list[CheckResult] = []
    seen: set[tuple[int, str]] = set()
    known_ports = {row["port"] for row in rows}
    for row in rows:
        port = row["port"]
        spec = _DANGEROUS_PORTS.get(port)
        if not spec:
            continue
        service, severity, note = spec
        kind = _address_kind(row["address"])
        if kind == "loopback":
            if port == 2375:
                severity = "high"
            else:
                continue
        elif kind == "wildcard":
            if port == 2375:
                severity = "critical"
        if severity is None:
            continue
        key = (port, kind)
        if key in seen:
            continue
        seen.add(key)
        bind = "all interfaces" if kind == "wildcard" else ("the loopback address" if kind == "loopback" else "an external interface")
        findings.append(
            _result(
                "PORT-DANGEROUS",
                "ports",
                f"Dangerous listening port found: {service}",
                FINDING,
                severity=severity,
                detail=f"{service} is listening on TCP {port} on {bind} ({note})",
                remediation=f"Confirm whether the business needs {service}; if not, stop the service or restrict it to the loopback address or a firewall allowlist.",
                target={"type": "port", "name": str(port)},
                evidence={"port": port, "service": service, "bind": kind},
                dedup_hint=f"port:{port}:{kind}",
            )
        )
    if findings:
        return findings
    return [
        _result(
            "PORT-DANGEROUS",
            "ports",
            "Dangerous listening port check",
            PASS,
            detail=f"checked {len(known_ports)} listening ports; no unexpected legacy plaintext/unauthenticated management services found",
        )
    ]


_LEGACY_UNITS: dict[str, tuple[str, str, str]] = {
    "telnet.socket": ("Telnet", "high", "plaintext remote login service"),
    "rsh.socket": ("rsh", "high", "legacy plaintext remote shell service"),
    "rlogin.socket": ("rlogin", "high", "legacy plaintext remote login service"),
    "rexec.socket": ("rexec", "high", "legacy plaintext remote execution service"),
    "tftp.socket": ("TFTP", "high", "unauthenticated file transfer service"),
    "vsftpd.service": ("vsftpd", "medium", "FTP service; disable it if not required"),
}


def _check_services(root: str) -> list[CheckResult]:
    if not os.path.isdir(_rooted(root, "/run/systemd/system")):
        return [
            _result(
                "SVC-LEGACY",
                "services",
                "Legacy dangerous service check",
                SKIPPED,
                detail="systemd was not detected (usually unavailable inside containers); service enablement was not evaluated",
            )
        ]
    binary = which("systemctl")
    if not binary:
        return [
            _result(
                "SVC-LEGACY",
                "services",
                "Legacy dangerous service check",
                SKIPPED,
                detail="systemd is running but systemctl was not found; service enablement was not evaluated",
            )
        ]
    findings: list[CheckResult] = []
    errors: list[str] = []
    for unit, (name, severity, note) in _LEGACY_UNITS.items():
        result = run([binary, "is-enabled", unit], timeout=5)
        output = (result.stdout or "").strip().splitlines()
        state = output[0].strip().lower() if output else ""
        if result.timed_out:
            errors.append(f"{unit}: query timed out")
        elif state == "enabled":
            findings.append(
                _result(
                    "SVC-LEGACY",
                    "services",
                    f"Enabled legacy dangerous service found: {name}",
                    FINDING,
                    severity=severity,
                    detail=f"{unit} is enabled ({note})",
                    remediation=f"Confirm whether {name} is required; if not, run systemctl disable --now {unit}.",
                    target={"type": "service", "name": unit},
                    evidence={"unit": unit, "state": state},
                    dedup_hint=f"service:{unit}",
                )
            )
        elif result.returncode not in (0, 1) and state == "":
            errors.append(f"{unit}: {result.tail(120)}")
    if findings:
        return findings
    if errors:
        return [
            _result(
                "SVC-LEGACY",
                "services",
                "Legacy dangerous service check",
                ERROR,
                detail="; ".join(errors),
            )
        ]
    return [
        _result(
            "SVC-LEGACY",
            "services",
            "Legacy dangerous service check",
            PASS,
            detail="no enabled Telnet/rsh/rlogin/rexec/TFTP/vsftpd services found",
        )
    ]


def _check_aslr(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/proc/sys/kernel/randomize_va_space"))
    if text is None:
        return [
            _result(
                "SYS-ASLR",
                "kernel",
                "Address space randomization check",
                ERROR,
                detail=f"cannot read the ASLR setting: {error}",
            )
        ]
    value = text.strip()
    if value == "2":
        return [
            _result(
                "SYS-ASLR",
                "kernel",
                "Address space randomization check",
                PASS,
                detail="randomize_va_space=2 (full randomization)",
            )
        ]
    severity = "medium" if value == "0" else "low"
    return [
        _result(
            "SYS-ASLR",
            "kernel",
            "Insufficient address space randomization",
            FINDING,
            severity=severity,
            detail=f"randomize_va_space={value}; keep it at 2",
            remediation="After evaluating compatibility, set kernel.randomize_va_space=2 (via sysctl); this program will not change it automatically.",
            target={"type": "sysctl", "name": "kernel.randomize_va_space"},
            evidence={"value": value},
            dedup_hint="sysctl:randomize_va_space",
        )
    ]


def _check_mac(root: str) -> list[CheckResult]:
    apparmor = os.path.exists(_rooted(root, "/sys/kernel/security/apparmor"))
    selinux = os.path.exists(_rooted(root, "/sys/fs/selinux"))
    if apparmor or selinux:
        frameworks = []
        if apparmor:
            frameworks.append("AppArmor")
        if selinux:
            frameworks.append("SELinux")
        return [
            _result(
                "SYS-MAC",
                "kernel",
                "Mandatory access control check",
                PASS,
                detail=f"detected {' / '.join(frameworks)} security framework interfaces",
            )
        ]
    return [
        _result(
            "SYS-MAC",
            "kernel",
            "Mandatory access control check",
            SKIPPED,
            detail="no AppArmor/SELinux interfaces detected (the container may hide the host security filesystems); no conclusion is drawn",
        )
    ]


_BUILTIN_CHECKS: tuple[Callable[[str], list[CheckResult]], ...] = (
    _check_uid0,
    _check_empty_passwords,
    _check_duplicate_uid,
    _check_sensitive_permissions,
    _check_ssh,
    _check_ports,
    _check_services,
    _check_aslr,
    _check_mac,
)


def run_builtin_checks(root: str = "/") -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in _BUILTIN_CHECKS:
        try:
            results.extend(check(root))
        except Exception as exc:  # a broken check must not abort the audit
            results.append(
                _result(
                    check.__name__.upper(),
                    "system",
                    "Check execution failed",
                    ERROR,
                    detail=f"internal check error: {exc}",
                )
            )
    return results


def collect_system_info(root: str = "/") -> dict[str, Any]:
    info = host_info()
    uptime = _read(_rooted(root, "/proc/uptime"))
    load = _read(_rooted(root, "/proc/loadavg"))
    meminfo, _ = _read(_rooted(root, "/proc/meminfo"))
    memory: dict[str, int] = {}
    if meminfo:
        for line in meminfo.splitlines():
            key, _, value = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                pieces = value.split()
                if pieces and pieces[0].isdigit():
                    memory[key] = int(pieces[0]) * 1024
    info.update(
        {
            "cpu_count": os.cpu_count(),
            "uptime_seconds": _first_number(uptime[0]) if uptime[0] else None,
            "load_average": load[0].split()[:3] if load[0] else None,
            "memory_total_bytes": memory.get("MemTotal"),
            "memory_available_bytes": memory.get("MemAvailable"),
        }
    )
    return info


def _first_number(text: str) -> float | None:
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None
