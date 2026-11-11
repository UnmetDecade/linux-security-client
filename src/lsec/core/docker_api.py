"""Minimal, read-only Docker Engine API client.

Only GET requests are implemented. Container monitoring never mutates the
runtime: there is no start/stop/restart/exec path in this module.

In production lsec connects to a dedicated GET-only proxy over an internal
network. A Unix socket URL is supported for local development, but mounting the
Docker socket into the Web process is strongly discouraged because the socket
is effectively host root.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
from typing import Any
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CONTAINER_ID_RE = re.compile(r"^[0-9a-fA-F]{12,64}$")


class DockerApiError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.unix_path)
        except Exception:
            sock.close()
            raise
        self.sock = sock


class DockerApiClient:
    def __init__(self, api_url: str, timeout: float = 8) -> None:
        self.api_url = api_url
        self.timeout = timeout
        self._mode, self._target = self._parse_url(api_url)

    @staticmethod
    def _parse_url(api_url: str) -> tuple[str, Any]:
        if api_url.startswith("unix://"):
            path = api_url[len("unix://"):]
            if not path.startswith("/"):
                raise DockerApiError("invalid_config", "Unix Socket 路径必须是绝对路径")
            return "unix", path
        if api_url.startswith("http://"):
            parsed = urlsplit(api_url)
            if (
                not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise DockerApiError("invalid_config", "Docker API 地址不合法")
            return "tcp", (parsed.hostname, parsed.port or 80)
        raise DockerApiError("invalid_config", "只支持 unix:// 或 http:// Docker API")

    def _connection(self) -> http.client.HTTPConnection:
        if self._mode == "unix":
            return _UnixHTTPConnection(self._target, self.timeout)
        host, port = self._target
        return http.client.HTTPConnection(host, port, timeout=self.timeout)

    def _get(self, path: str) -> Any:
        connection = self._connection()
        try:
            try:
                connection.request(
                    "GET",
                    path,
                    headers={"Accept": "application/json", "Host": "docker"},
                )
                response = connection.getresponse()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            except FileNotFoundError:
                raise DockerApiError("unavailable", "Docker API Socket 不存在") from None
            except PermissionError:
                raise DockerApiError("permission_denied", "无权访问 Docker API Socket") from None
            except (socket.timeout, TimeoutError):
                raise DockerApiError("timeout", "Docker API 请求超时") from None
            except ConnectionRefusedError:
                raise DockerApiError("unavailable", "Docker API 拒绝连接") from None
            except OSError as exc:
                message = str(exc)
                if "permission denied" in message.lower():
                    raise DockerApiError("permission_denied", "无权访问 Docker API") from None
                raise DockerApiError("unavailable", f"无法连接 Docker API: {message[:200]}") from None
        finally:
            connection.close()

        if len(raw) > MAX_RESPONSE_BYTES:
            raise DockerApiError("protocol_error", "Docker API 响应过大")
        if response.status in {401, 403}:
            raise DockerApiError("permission_denied", "Docker API 拒绝访问（权限不足）")
        if response.status == 404:
            raise DockerApiError("not_found", "Docker API 资源不存在")
        if response.status >= 400:
            detail = raw.decode("utf-8", errors="replace")[:300]
            raise DockerApiError(
                "protocol_error", f"Docker API 返回 HTTP {response.status}: {detail}"
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DockerApiError("protocol_error", "Docker API 返回了非 JSON 数据") from None

    def version(self) -> dict[str, Any]:
        data = self._get("/version")
        if not isinstance(data, dict):
            raise DockerApiError("protocol_error", "Docker /version 响应格式错误")
        return data

    def info(self) -> dict[str, Any]:
        data = self._get("/info")
        if not isinstance(data, dict):
            raise DockerApiError("protocol_error", "Docker /info 响应格式错误")
        return data

    def list_containers(self) -> list[dict[str, Any]]:
        data = self._get("/containers/json?all=1")
        if not isinstance(data, list):
            raise DockerApiError("protocol_error", "Docker 容器列表格式错误")
        return [item for item in data if isinstance(item, dict)]

    def inspect_container(self, container_id: str) -> dict[str, Any]:
        if not CONTAINER_ID_RE.match(container_id):
            raise DockerApiError("invalid_argument", "容器 ID 格式错误")
        data = self._get(f"/containers/{container_id}/json")
        if not isinstance(data, dict):
            raise DockerApiError("protocol_error", "Docker 容器详情格式错误")
        return data
