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
        return None, f"无法读取 {path}: {exc}"
    if not stat.S_ISREG(st.st_mode):
        return None, f"{path} 不是普通文件"
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"无法读取 {path}: {exc}"


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
        notes.append("Match 条件块未纳入全局结论")
    if len(files) > 1:
        notes.append("已合并 sshd_config.d/*.conf；未完整展开 Include 位置语义")
    return values, notes


def _check_uid0(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/etc/passwd"))
    if text is None:
        return [
            _result(
                "AUTH-UID0",
                "users",
                "UID 0 账户检查",
                ERROR,
                detail=f"无法读取 /etc/passwd: {error}",
            )
        ]
    entries, malformed = parse_passwd(text)
    if not entries:
        return [
            _result(
                "AUTH-UID0",
                "users",
                "UID 0 账户检查",
                ERROR,
                detail=f"/etc/passwd 无有效账户记录（格式异常 {malformed} 行）",
            )
        ]
    roots = [entry["name"] for entry in entries if entry["uid"] == "0"]
    extras = [name for name in roots if name != "root"]
    if extras:
        return [
            _result(
                "AUTH-UID0",
                "users",
                "发现额外的 UID 0 账户",
                FINDING,
                severity="high",
                detail=f"除 root 外存在 UID 0 账户: {', '.join(extras)}",
                remediation="核实这些账户的来源，移除不需要的特权账户，并审计其登录记录。",
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
            "UID 0 账户检查",
            PASS,
            detail="仅 root 拥有 UID 0",
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
                    "空密码账户检查",
                    SKIPPED,
                    detail="/etc/shadow 不存在，未评估空密码账户",
                )
            ]
        return [
            _result(
                "AUTH-EMPTY-PASSWORD",
                "users",
                "空密码账户检查",
                ERROR,
                detail=f"无法读取 /etc/shadow: {error}",
            )
        ]
    empty = [entry["name"] for entry in parse_shadow(text) if entry["password"] == ""]
    if empty:
        return [
            _result(
                "AUTH-EMPTY-PASSWORD",
                "users",
                "发现空密码账户",
                FINDING,
                severity="critical",
                detail=f"以下账户的密码字段为空: {', '.join(empty)}",
                remediation="立即为账户设置强密码或锁定账户，并检查认证日志。",
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
            "空密码账户检查",
            PASS,
            detail="未发现空密码账户（仅检查密码字段是否为空，不读取哈希内容）",
        )
    ]


def _check_duplicate_uid(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/etc/passwd"))
    if text is None:
        return [
            _result(
                "AUTH-DUPLICATE-UID",
                "users",
                "重复 UID 检查",
                ERROR,
                detail=f"无法读取 /etc/passwd: {error}",
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
                "发现重复的非 root UID",
                FINDING,
                severity="medium",
                detail="；".join(
                    f"UID {uid}: {', '.join(names)}"
                    for uid, names in sorted(duplicates.items())
                ),
                remediation="确认共享 UID 是否为预期配置；非预期时改为独立 UID 并检查文件属主。",
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
            "重复 UID 检查",
            PASS,
            detail="未发现重复的非 root UID",
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
        return f"{path}: 不是普通文件"
    mode = stat.S_IMODE(st.st_mode)
    if mode & forbidden_mask:
        return _result(
            "PERM-SENSITIVE-FILE",
            "permissions",
            title,
            FINDING,
            severity=severity,
            detail=f"{path} 权限为 {mode:04o}，包含不安全的组/其他用户访问位",
            remediation=f"将 {path} 权限收紧到发行版推荐值，并检查属主。",
            target={"type": "file", "path": path},
            evidence={"path": path, "mode": f"{mode:04o}", "forbidden_mask": f"{forbidden_mask:04o}"},
            dedup_hint=f"perm:{path}",
        )
    return None


def _check_sensitive_permissions(root: str) -> list[CheckResult]:
    specs = (
        ("/etc/passwd", 0o022, "high", "敏感账户文件可被组或其他用户写入"),
        ("/etc/group", 0o022, "high", "敏感组文件可被组或其他用户写入"),
        ("/etc/shadow", 0o026, "high", "密码哈希文件权限过宽"),
        ("/etc/gshadow", 0o026, "high", "组密码文件权限过宽"),
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
                "敏感文件权限检查",
                ERROR,
                detail="；".join(errors),
            )
        )
    if not findings and not errors:
        if checked:
            results.append(
                _result(
                    "PERM-SENSITIVE-FILE",
                    "permissions",
                    "敏感文件权限检查",
                    PASS,
                    detail=f"已检查 {checked} 个文件，未发现组/其他用户可写或密码文件可读",
                )
            )
        else:
            results.append(
                _result(
                    "PERM-SENSITIVE-FILE",
                    "permissions",
                    "敏感文件权限检查",
                    SKIPPED,
                    detail="/etc/passwd、/etc/shadow 等文件均不存在",
                )
            )
    return results


def _check_ssh(root: str) -> list[CheckResult]:
    files, notes = _ssh_config_texts(root)
    if not files:
        detail = "未找到 /etc/ssh/sshd_config；未安装 OpenSSH 服务端或容器未挂载配置，未评估 SSH 基线"
        if notes:
            detail += f"（{'; '.join(notes)}）"
        return [
            _result(
                "SSH-BASELINE",
                "ssh",
                "SSH 基线检查",
                SKIPPED,
                detail=detail,
            )
        ]
    values, parse_notes = parse_ssh_config(files)
    notes.extend(parse_notes)
    results: list[CheckResult] = []
    suffix = f"（限制: {'; '.join(notes)}）" if notes else ""

    root_login = values.get("permitrootlogin")
    if root_login is None:
        results.append(
            _result(
                "SSH-ROOT-LOGIN",
                "ssh",
                "SSH root 登录检查",
                SKIPPED,
                detail="未显式配置 PermitRootLogin，未展开全部 Include/Match 语义，不下结论" + suffix,
            )
        )
    elif root_login.lower() == "yes":
        results.append(
            _result(
                "SSH-ROOT-LOGIN",
                "ssh",
                "SSH 允许 root 直接登录",
                FINDING,
                severity="high",
                detail="PermitRootLogin yes" + suffix,
                remediation="将 PermitRootLogin 设为 no 或 prohibit-password，并重载 sshd。",
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
                "SSH root 登录检查",
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
                "SSH 密码认证检查",
                SKIPPED,
                detail="未显式配置 PasswordAuthentication，不下结论" + suffix,
            )
        )
    elif password_auth.lower() == "yes":
        results.append(
            _result(
                "SSH-PASSWORD-AUTH",
                "ssh",
                "SSH 启用密码认证",
                FINDING,
                severity="medium",
                detail="PasswordAuthentication yes；如无必要，建议改用密钥认证" + suffix,
                remediation="确认业务需要后保留；否则设置 PasswordAuthentication no 并配置密钥登录。",
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
                "SSH 密码认证检查",
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
                "SSH 空密码登录检查",
                SKIPPED,
                detail="未显式配置 PermitEmptyPasswords，不下结论" + suffix,
            )
        )
    elif empty.lower() == "yes":
        results.append(
            _result(
                "SSH-EMPTY-PASSWORDS",
                "ssh",
                "SSH 允许空密码登录",
                FINDING,
                severity="critical",
                detail="PermitEmptyPasswords yes" + suffix,
                remediation="立即设置 PermitEmptyPasswords no，并锁定空密码账户。",
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
                "SSH 空密码登录检查",
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
                    "SSH 配置文件权限过宽",
                    FINDING,
                    severity="medium",
                    detail=f"/etc/ssh/sshd_config 权限为 {mode:04o}，组或其他用户可写",
                    remediation="执行 chmod 600 /etc/ssh/sshd_config（属主 root）并检查是否被篡改。",
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
                    "SSH 配置文件权限检查",
                    PASS,
                    detail=f"/etc/ssh/sshd_config 权限 {mode:04o}",
                )
            )
    except OSError as exc:
        results.append(
            _result(
                "SSH-CONFIG-PERMS",
                "ssh",
                "SSH 配置文件权限检查",
                ERROR,
                detail=f"无法读取 /etc/ssh/sshd_config 属性: {exc}",
            )
        )
    return results


_DANGEROUS_PORTS: dict[int, tuple[str, str | None, str]] = {
    21: ("FTP", "medium", "明文文件传输服务"),
    23: ("Telnet", "high", "明文远程登录服务"),
    69: ("TFTP", "high", "无认证文件传输服务"),
    111: ("rpcbind", "low", "RPC 端口映射服务"),
    512: ("rexec", "high", "传统明文远程执行服务"),
    513: ("rlogin", "high", "传统明文远程登录服务"),
    514: ("rsh", "high", "传统明文远程 shell 服务"),
    2375: ("Docker API", "critical", "未加密且通常无认证的容器运行时 API"),
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
                "危险监听端口检查",
                ERROR,
                detail="无法读取 /proc/net/tcp 与 /proc/net/tcp6，未评估监听端口"
                + (f"（{'; '.join(errors)}）" if errors else ""),
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
        bind = "所有接口" if kind == "wildcard" else ("回环地址" if kind == "loopback" else "外部接口")
        findings.append(
            _result(
                "PORT-DANGEROUS",
                "ports",
                f"发现危险监听端口: {service}",
                FINDING,
                severity=severity,
                detail=f"{service} 正在{bind}监听 TCP {port}（{note}）",
                remediation=f"确认业务是否需要 {service}；不需要时停止服务或限制为回环/防火墙白名单。",
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
            "危险监听端口检查",
            PASS,
            detail=f"已检查 {len(known_ports)} 个监听端口，未发现非预期的传统明文/无认证管理服务",
        )
    ]


_LEGACY_UNITS: dict[str, tuple[str, str, str]] = {
    "telnet.socket": ("Telnet", "high", "明文远程登录服务"),
    "rsh.socket": ("rsh", "high", "传统明文远程 shell 服务"),
    "rlogin.socket": ("rlogin", "high", "传统明文远程登录服务"),
    "rexec.socket": ("rexec", "high", "传统明文远程执行服务"),
    "tftp.socket": ("TFTP", "high", "无认证文件传输服务"),
    "vsftpd.service": ("vsftpd", "medium", "FTP 服务；如非必要应停用"),
}


def _check_services(root: str) -> list[CheckResult]:
    if not os.path.isdir(_rooted(root, "/run/systemd/system")):
        return [
            _result(
                "SVC-LEGACY",
                "services",
                "传统危险服务检查",
                SKIPPED,
                detail="未检测到 systemd（容器内通常不可用），未评估服务启用状态",
            )
        ]
    binary = which("systemctl")
    if not binary:
        return [
            _result(
                "SVC-LEGACY",
                "services",
                "传统危险服务检查",
                SKIPPED,
                detail="systemd 正在运行但找不到 systemctl，未评估服务启用状态",
            )
        ]
    findings: list[CheckResult] = []
    errors: list[str] = []
    for unit, (name, severity, note) in _LEGACY_UNITS.items():
        result = run([binary, "is-enabled", unit], timeout=5)
        output = (result.stdout or "").strip().splitlines()
        state = output[0].strip().lower() if output else ""
        if result.timed_out:
            errors.append(f"{unit}: 查询超时")
        elif state == "enabled":
            findings.append(
                _result(
                    "SVC-LEGACY",
                    "services",
                    f"发现已启用的传统危险服务: {name}",
                    FINDING,
                    severity=severity,
                    detail=f"{unit} 已启用（{note}）",
                    remediation=f"确认 {name} 是否必需；不需要时 systemctl disable --now {unit}。",
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
                "传统危险服务检查",
                ERROR,
                detail="；".join(errors),
            )
        ]
    return [
        _result(
            "SVC-LEGACY",
            "services",
            "传统危险服务检查",
            PASS,
            detail="未发现已启用的 Telnet/rsh/rlogin/rexec/TFTP/vsftpd 服务",
        )
    ]


def _check_aslr(root: str) -> list[CheckResult]:
    text, error = _read(_rooted(root, "/proc/sys/kernel/randomize_va_space"))
    if text is None:
        return [
            _result(
                "SYS-ASLR",
                "kernel",
                "地址空间随机化检查",
                ERROR,
                detail=f"无法读取 ASLR 设置: {error}",
            )
        ]
    value = text.strip()
    if value == "2":
        return [
            _result(
                "SYS-ASLR",
                "kernel",
                "地址空间随机化检查",
                PASS,
                detail="randomize_va_space=2（完全随机化）",
            )
        ]
    severity = "medium" if value == "0" else "low"
    return [
        _result(
            "SYS-ASLR",
            "kernel",
            "地址空间随机化不足",
            FINDING,
            severity=severity,
            detail=f"randomize_va_space={value}；建议保持为 2",
            remediation="评估兼容性后设置 kernel.randomize_va_space=2（通过 sysctl）；本程序不会自动修改。",
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
                "强制访问控制检查",
                PASS,
                detail=f"检测到 {' / '.join(frameworks)} 安全框架接口",
            )
        ]
    return [
        _result(
            "SYS-MAC",
            "kernel",
            "强制访问控制检查",
            SKIPPED,
            detail="未检测到 AppArmor/SELinux 接口（容器可能隐藏宿主机的安全文件系统），不下结论",
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
                    "检查执行失败",
                    ERROR,
                    detail=f"内部检查异常: {exc}",
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
