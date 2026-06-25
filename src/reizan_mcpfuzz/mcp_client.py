"""Minimal stdio MCP client for tools/list enumeration."""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from collections import deque
from typing import Any, TextIO

from reizan_mcpfuzz.manifest import ManifestError, tools_from_payload
from reizan_mcpfuzz.models import ToolRecord


PROTOCOL_VERSION = "2025-06-18"


class MCPClientError(RuntimeError):
    pass


def list_tools_stdio(command: list[str], timeout_seconds: float = 10.0) -> tuple[ToolRecord, ...]:
    if not command:
        raise MCPClientError("server command is empty")
    client = StdioMCPClient(command, timeout_seconds=timeout_seconds)
    with client:
        initialize_result = client.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "reizan-mcpfuzz",
                    "version": "0.1.0",
                },
            },
        )
        if not isinstance(initialize_result, dict):
            raise MCPClientError("initialize result was not an object")
        client.notify("notifications/initialized", {})
        tools: list[ToolRecord] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor
            result = client.request("tools/list", params)
            try:
                page = tools_from_payload({"result": result})
            except ManifestError as exc:
                raise MCPClientError(str(exc)) from exc
            tools.extend(page)
            if not isinstance(result, dict):
                break
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                break
            cursor = next_cursor
        return tuple(tools)


class StdioMCPClient:
    def __init__(self, command: list[str], *, timeout_seconds: float) -> None:
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.process: subprocess.Popen[str] | None = None
        self._stdout_queue: queue.Queue[str | None] = queue.Queue()
        self._stderr_tail: deque[str] = deque(maxlen=20)
        self._next_id = 1

    def __enter__(self) -> "StdioMCPClient":
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            raise MCPClientError(f"could not start MCP server: {exc}") from exc
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        threading.Thread(target=_read_stdout, args=(self.process.stdout, self._stdout_queue), daemon=True).start()
        threading.Thread(target=_read_stderr, args=(self.process.stderr, self._stderr_tail), daemon=True).start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def request(self, method: str, params: dict[str, Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        response = self._read_response(request_id)
        if "error" in response:
            raise MCPClientError(f"{method} returned error: {response['error']}")
        if "result" not in response:
            raise MCPClientError(f"{method} response missing result")
        return response["result"]

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def close(self) -> None:
        if self.process is None:
            return
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1.0)

    def _write(self, message: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise MCPClientError("MCP server process is not running")
        if self.process.poll() is not None:
            raise MCPClientError(f"MCP server exited early with code {self.process.returncode}: {self._stderr()}")
        try:
            self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
            self.process.stdin.flush()
        except OSError as exc:
            raise MCPClientError(f"could not write to MCP server stdin: {exc}") from exc

    def _read_response(self, request_id: int) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                line = self._stdout_queue.get(timeout=min(0.1, remaining))
            except queue.Empty:
                if self.process is not None and self.process.poll() is not None:
                    raise MCPClientError(
                        f"MCP server exited before response {request_id}: {self._stderr()}"
                    )
                continue
            if line is None:
                raise MCPClientError(f"MCP server closed stdout before response {request_id}: {self._stderr()}")
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise MCPClientError(f"MCP server wrote non-JSON stdout: {stripped[:300]}") from exc
            if not isinstance(message, dict):
                raise MCPClientError("MCP server wrote a non-object JSON-RPC message")
            if message.get("id") == request_id:
                return message
            if "id" in message and isinstance(message.get("method"), str):
                self._write(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "error": {"code": -32601, "message": "method not supported by reizan-mcpfuzz"},
                    }
                )
        raise MCPClientError(f"timed out waiting for MCP response {request_id}: {self._stderr()}")

    def _stderr(self) -> str:
        tail = "".join(self._stderr_tail).strip()
        return tail or "no stderr"


def _read_stdout(stream: TextIO, out: queue.Queue[str | None]) -> None:
    try:
        for line in stream:
            out.put(line)
    finally:
        out.put(None)


def _read_stderr(stream: TextIO, tail: deque[str]) -> None:
    for line in stream:
        tail.append(line)
