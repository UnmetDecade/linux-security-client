"""Test-only Docker Engine API double.

It implements the small set of GET endpoints lsec reads. It is not shipped in
the product and is only used to verify read-only behavior and risk mapping.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


def make_inspect(
    container_id: str,
    name: str,
    *,
    image: str = "nginx:latest",
    state: str = "running",
    privileged: bool = False,
    network_mode: str = "bridge",
    pid_mode: str = "",
    ipc_mode: str = "",
    cap_add: list[str] | None = None,
    cap_drop: list[str] | None = None,
    security_opt: list[str] | None = None,
    mounts: list[dict[str, Any]] | None = None,
    binds: list[str] | None = None,
    devices: list[dict[str, Any]] | None = None,
    user: str = "",
    read_only_rootfs: bool = False,
    started_at: str = "2026-11-10T08:00:00Z",
) -> dict[str, Any]:
    return {
        "Id": container_id,
        "Name": f"/{name}",
        "Image": "sha256:" + "a" * 64,
        "Created": "2026-11-10T07:59:00Z",
        "State": {
            "Status": state,
            "Running": state == "running",
            "Pid": 4242 if state == "running" else 0,
            "StartedAt": started_at if state == "running" else "0001-01-01T00:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z" if state == "running" else "2026-11-10T09:00:00Z",
            "RestartCount": 0,
            "OOMKilled": False,
        },
        "Config": {
            "Image": image,
            "User": user,
            "Env": ["SECRET_TOKEN=must-not-be-collected"],
        },
        "HostConfig": {
            "Privileged": privileged,
            "NetworkMode": network_mode,
            "PidMode": pid_mode,
            "IpcMode": ipc_mode,
            "UsernsMode": "",
            "CapAdd": cap_add or [],
            "CapDrop": cap_drop or [],
            "SecurityOpt": security_opt or [],
            "Devices": devices or [],
            "Binds": binds or [],
            "ReadonlyRootfs": read_only_rootfs,
            "RestartPolicy": {"Name": "no"},
        },
        "Mounts": mounts or [],
        "NetworkSettings": {
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8088"}]}
        },
    }


def list_item_from(inspect: dict[str, Any]) -> dict[str, Any]:
    return {
        "Id": inspect["Id"],
        "Names": [inspect["Name"]],
        "Image": inspect["Config"]["Image"],
        "ImageID": inspect["Image"],
        "State": inspect["State"]["Status"],
        "Status": "Up 2 hours",
    }


class FakeDockerApi:
    def __init__(self) -> None:
        self.inspections: dict[str, dict[str, Any]] = {}
        self.permission_denied = False
        self.requests: list[tuple[str, str]] = []
        self.stop_event = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "fake-docker/1.0"

            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def _send(self, status: int, payload: Any) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                outer.requests.append(("GET", self.path))
                if outer.permission_denied:
                    self._send(403, {"message": "permission denied"})
                    return
                path = urlsplit(self.path).path
                if path == "/version":
                    self._send(
                        200,
                        {
                            "Version": "24.0.9",
                            "ApiVersion": "1.43",
                            "MinAPIVersion": "1.12",
                        },
                    )
                    return
                if path == "/info":
                    self._send(
                        200,
                        {
                            "OperatingSystem": "Ubuntu 24.04",
                            "KernelVersion": "6.8.0",
                            "Architecture": "x86_64",
                            "ContainersRunning": 1,
                            "ContainersStopped": 0,
                        },
                    )
                    return
                if path == "/containers/json":
                    self._send(
                        200,
                        [
                            list_item_from(item)
                            for item in outer.inspections.values()
                        ],
                    )
                    return
                match = re.match(r"^/containers/([0-9a-fA-F]{12,64})/json$", path)
                if match and match.group(1) in outer.inspections:
                    self._send(200, outer.inspections[match.group(1)])
                    return
                self._send(404, {"message": "not found"})

            def _reject(self) -> None:
                outer.requests.append((self.command, self.path))
                self._send(405, {"message": "read-only test double"})

            do_POST = _reject  # noqa: N815
            do_DELETE = _reject  # noqa: N815
            do_PUT = _reject  # noqa: N815
            do_PATCH = _reject  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def set_containers(self, inspections: list[dict[str, Any]]) -> None:
        self.inspections = {item["Id"]: item for item in inspections}

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
