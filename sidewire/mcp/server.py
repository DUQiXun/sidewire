"""MCP stdio server.

Newline-delimited JSON-RPC 2.0 on stdin/stdout, exactly what Claude Desktop,
Codex, DeepSeek Harness and friends expect.  Nothing but protocol bytes may
ever touch stdout, so every diagnostic goes to stderr.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import traceback

from .. import __version__
from . import tools as toolmod

SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST = SUPPORTED_VERSIONS[0]


class StdioServer(object):
    def __init__(self, ctx, name="sidewire"):
        self.ctx = ctx
        self.name = name
        self._out = sys.stdout.buffer
        self._lock = threading.Lock()
        self._stopping = threading.Event()

    # ------------------------------------------------------------------ io
    def log(self, msg):
        try:
            sys.stderr.write("[sidewire] %s\n" % msg)
            sys.stderr.flush()
        except Exception:
            pass

    def write(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n"
        with self._lock:
            try:
                self._out.write(data)
                self._out.flush()
            except (BrokenPipeError, ValueError):
                self._stopping.set()

    def reply(self, rid, result):
        self.write({"jsonrpc": "2.0", "id": rid, "result": result})

    def error(self, rid, code, message, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self.write({"jsonrpc": "2.0", "id": rid, "error": err})

    # -------------------------------------------------------------- reading
    def _read_message(self):
        """Read one JSON-RPC message; supports both newline and LSP framing."""
        buf = sys.stdin.buffer
        while True:
            line = buf.readline()
            if not line:
                return None
            stripped = line.strip()
            if not stripped:
                continue
            low = stripped.lower()
            if low.startswith(b"content-length:"):
                try:
                    n = int(stripped.split(b":", 1)[1].strip())
                except (IndexError, ValueError):
                    continue
                body = buf.read(n)
                if not body:
                    return None
                return json.loads(body.decode("utf-8"))
            try:
                return json.loads(stripped.decode("utf-8"))
            except UnicodeDecodeError:
                self.log("ignoring non-utf8 input line")
                continue
            except json.JSONDecodeError as exc:
                self.log("ignoring malformed json line: %s" % exc)
                continue

    # ------------------------------------------------------------- handlers
    def handle(self, msg):
        if not isinstance(msg, dict):
            self.error(None, -32600, "invalid request")
            return
        method = msg.get("method")
        rid = msg.get("id")
        is_notification = "id" not in msg
        params = msg.get("params") or {}

        if method == "initialize":
            wanted = params.get("protocolVersion")
            version = wanted if wanted in SUPPORTED_VERSIONS else LATEST
            self.reply(rid, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": __version__},
                "instructions": (
                    "SideWire gives you shell, file, process and network control over remote "
                    "machines on the LAN. Call `hosts` to see targets, `host_info` to identify "
                    "the one you are about to touch, then `run` / `fs_*`. Paths are always paths "
                    "on the target, not on this machine."
                ),
            })
            return

        if is_notification:
            # notifications/initialized, notifications/cancelled, ...
            return

        if method == "ping":
            self.reply(rid, {})
            return

        if method == "tools/list":
            self.reply(rid, {"tools": toolmod.tool_list_payload()})
            return

        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if name not in toolmod.BY_NAME:
                self.error(rid, -32602, "unknown tool: %s" % name)
                return
            self.reply(rid, toolmod.dispatch(self.ctx, name, args))
            return

        if method in ("resources/list",):
            self.reply(rid, {"resources": []})
            return
        if method in ("resources/templates/list",):
            self.reply(rid, {"resourceTemplates": []})
            return
        if method in ("prompts/list",):
            self.reply(rid, {"prompts": []})
            return
        if method == "logging/setLevel":
            self.reply(rid, {})
            return
        if method == "shutdown":
            self.reply(rid, {})
            self._stopping.set()
            return

        self.error(rid, -32601, "method not found: %s" % method)

    # ----------------------------------------------------------------- loop
    def serve(self):
        self.log("ready (pid %d, python %s)" % (os.getpid(), sys.version.split()[0]))
        while not self._stopping.is_set():
            try:
                msg = self._read_message()
            except Exception as exc:  # noqa: BLE001
                self.log("read error: %s" % exc)
                break
            if msg is None:
                break
            if isinstance(msg, list):
                for item in msg:
                    self._safe_handle(item)
                continue
            self._safe_handle(msg)
        self.log("stdin closed, shutting down")
        try:
            self.ctx.close_all()
        except Exception:
            pass
        return 0

    def _safe_handle(self, msg):
        try:
            self.handle(msg)
        except Exception:  # noqa: BLE001
            self.log("handler crashed:\n%s" % traceback.format_exc())
            rid = msg.get("id") if isinstance(msg, dict) else None
            self.error(rid, -32603, "internal error")
