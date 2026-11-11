"""Read-only host baseline check tests against a fixture root filesystem."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from lsec.core.hostchecks import (
    ERROR,
    FINDING,
    PASS,
    SKIPPED,
    _address_kind,
    parse_proc_net_tcp,
    parse_ssh_config,
    parse_shadow,
    run_builtin_checks,
)


def _write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)


class HostCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _populate(self) -> None:
        _write(
            self.root / "etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\n"
            "toor:x:0:0:toor:/root:/bin/sh\n"
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
            "bob:x:1000:1000::/home/bob:/bin/bash\n",
            0o664,
        )
        _write(
            self.root / "etc/shadow",
            "root:$6$secret$hash:19000:0:99999:7:::\n"
            "toor:!:19000:0:99999:7:::\n"
            "alice::19000:0:99999:7:::\n",
            0o644,
        )
        _write(self.root / "etc/group", "root:x:0:\nusers:x:1000:\n", 0o644)
        _write(
            self.root / "etc/ssh/sshd_config",
            "PermitRootLogin yes\n"
            "PasswordAuthentication yes\n"
            "PermitEmptyPasswords no\n"
            "Match User backup\n"
            "    PermitRootLogin no\n",
            0o644,
        )
        _write(
            self.root / "proc/net/tcp",
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt\n"
            "   0: 00000000:0017 00000000:0000 0A 00000000:00000000 00:00000000\n"
            "   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000\n",
            0o644,
        )
        _write(self.root / "proc/sys/kernel/randomize_va_space", "0\n", 0o644)

    def test_findings_are_distinct_and_errors_are_not_findings(self) -> None:
        self._populate()
        results = run_builtin_checks(str(self.root))
        by_id: dict[str, list] = {}
        for item in results:
            self.assertIn(item.status, {PASS, FINDING, ERROR, SKIPPED})
            by_id.setdefault(item.check_id, []).append(item)

        uid0 = by_id["AUTH-UID0"]
        self.assertEqual([item.status for item in uid0], [FINDING])
        self.assertEqual(uid0[0].severity, "high")
        self.assertEqual(uid0[0].target["name"], "toor")

        self.assertEqual(
            [item.severity for item in by_id["AUTH-EMPTY-PASSWORD"]], ["critical"]
        )
        self.assertEqual(
            [item.severity for item in by_id["AUTH-DUPLICATE-UID"]], ["medium"]
        )
        self.assertEqual(
            {item.target["path"] for item in by_id["PERM-SENSITIVE-FILE"]},
            {"/etc/passwd", "/etc/shadow"},
        )
        self.assertEqual(
            {item.check_id: item.status for item in by_id["SSH-ROOT-LOGIN"]},
            {"SSH-ROOT-LOGIN": FINDING},
        )
        self.assertEqual(by_id["SSH-ROOT-LOGIN"][0].severity, "high")
        self.assertEqual(
            by_id["SSH-PASSWORD-AUTH"][0].severity, "medium"
        )
        self.assertEqual(by_id["PORT-DANGEROUS"][0].severity, "high")
        self.assertEqual(by_id["SYS-ASLR"][0].severity, "medium")
        self.assertEqual(by_id["SVC-LEGACY"][0].status, SKIPPED)
        self.assertEqual(by_id["SYS-MAC"][0].status, SKIPPED)

        # Match blocks must not be folded into the global SSH conclusion.
        ssh = parse_ssh_config(
            [
                (
                    "/etc/ssh/sshd_config",
                    (self.root / "etc/ssh/sshd_config").read_text(encoding="utf-8"),
                )
            ]
        )
        self.assertEqual(ssh[0]["permitrootlogin"], "yes")
        self.assertIn("Match 条件块未纳入全局结论", ssh[1])

    def test_hashes_are_never_retained(self) -> None:
        self._populate()
        entries = parse_shadow((self.root / "etc/shadow").read_text(encoding="utf-8"))
        self.assertEqual(entries[0]["password"], "$6$secret$hash")
        results = run_builtin_checks(str(self.root))
        serialized = json.dumps([item.to_dict() for item in results], ensure_ascii=False)
        self.assertNotIn("$6$secret$hash", serialized)

    def test_missing_files_are_errors_or_skips_not_findings(self) -> None:
        results = run_builtin_checks(str(self.root))
        statuses = {item.check_id: item.status for item in results}
        self.assertEqual(statuses["AUTH-UID0"], ERROR)
        self.assertEqual(statuses["AUTH-EMPTY-PASSWORD"], SKIPPED)
        self.assertEqual(statuses["SSH-BASELINE"], SKIPPED)
        self.assertEqual(statuses["PORT-DANGEROUS"], ERROR)
        self.assertEqual(statuses["SYS-ASLR"], ERROR)
        self.assertNotIn(FINDING, statuses.values())

    def test_ssh_dropins_require_main_config(self) -> None:
        _write(self.root / "etc/ssh/sshd_config.d/50-cloud.conf", "PermitRootLogin no\n")
        results = run_builtin_checks(str(self.root))
        ssh = [item for item in results if item.check_id == "SSH-BASELINE"]
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0].status, SKIPPED)

    def test_proc_net_parser_and_address_kinds(self) -> None:
        rows = parse_proc_net_tcp(
            "header\n"
            " 0: 00000000:0017 00000000:0000 0A 0:0\n"
            " 1: 00000000:0050 00000000:0000 01 0:0\n"
            " 2: 0100007F:0016 00000000:0000 0A 0:0\n"
        )
        self.assertEqual([row["port"] for row in rows], [23, 22])
        self.assertEqual(_address_kind("00000000"), "wildcard")
        self.assertEqual(_address_kind("0100007F"), "loopback")
        self.assertEqual(_address_kind("0000000000000000FFFF00000100007F"), "loopback")
        self.assertEqual(_address_kind("0101A8C0"), "external")


if __name__ == "__main__":
    unittest.main()
