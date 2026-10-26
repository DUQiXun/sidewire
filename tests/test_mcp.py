#!/usr/bin/env python3
"""Talks to the MCP server exactly like a real host would: newline-delimited
JSON-RPC on stdin/stdout, with a live agentd behind it.

    python tests/test_mcp.py
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from sidewire import config as cfgmod  # noqa: E402
from sidewire import protocol as P     # noqa: E402

RESULTS = []


def check(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ""))
    except Exception as exc:  # noqa: BLE001
        RESULTS.append((name, False, "%s: %s" % (type(exc).__name__, exc)))


def eq(a, b, what=""):
    if a != b:
        raise AssertionError("%s expected %r got %r" % (what, b, a))


def truthy(v, what=""):
    if not v:
        raise AssertionError("expected truthy: %s" % what)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


class McpClient(object):
    def __init__(self, argv, env):
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env)
        self._id = 0

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj).encode() + b"\n")
        self.proc.stdin.flush()

    def call(self, method, params=None, timeout=30):
        self._id += 1
        rid = self._id
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        return self.read_until(rid, timeout)

    def notify(self, method, params=None):
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def read_until(self, rid, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            line = self.proc.stdout.readline()
            if not line:
                err = self.proc.stderr.read().decode("utf-8", "replace")
                raise AssertionError("server closed stdout. stderr:\n%s" % err[-1500:])
            try:
                msg = json.loads(line.decode("utf-8"))
            except ValueError:
                continue
            if msg.get("id") == rid:
                return msg
        raise AssertionError("timeout waiting for id=%s" % rid)

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            pass


def tool_text(resp):
    content = resp["result"]["content"]
    return content[0]["text"] if content else ""


def main():
    tmp = tempfile.mkdtemp(prefix="cw-mcp-")
    os.environ["SIDEWIRE_HOME"] = tmp
    port = free_port()
    key = P.format_key(P.gen_key(32))
    key_file = os.path.join(tmp, "agent.key")
    cfgmod.write_key_file(key_file, key)
    work = os.path.join(tmp, "work")
    os.makedirs(work, exist_ok=True)

    agent = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "agent", "sidewire_agentd.py"),
         "--bind", "127.0.0.1", "--port", str(port), "--key-file", key_file,
         "--workdir", work],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port):
            print("agentd failed to start")
            return 2
        cfgmod.add_host("sub", "127.0.0.1", port, key=key, set_default=True,
                        note="e2e target")

        env = dict(os.environ)
        env["SIDEWIRE_HOME"] = tmp
        cli = McpClient([sys.executable, os.path.join(ROOT, "sw.py"), "serve"], env)
        try:
            def t_initialize():
                resp = cli.call("initialize", {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                })
                res = resp["result"]
                eq(res["protocolVersion"], "2025-06-18", "version")
                truthy(res["serverInfo"]["name"] == "sidewire", "serverInfo")
                truthy("tools" in res["capabilities"], "capabilities")
                cli.notify("notifications/initialized")
            check("initialize", t_initialize)

            def t_ping():
                resp = cli.call("ping")
                eq(resp["result"], {}, "ping result")
            check("ping", t_ping)

            def t_list():
                resp = cli.call("tools/list")
                tools = resp["result"]["tools"]
                names = {t["name"] for t in tools}
                for want in ("hosts", "host_info", "run", "fs_read", "fs_write",
                             "fs_pull", "fs_push", "proc_list", "svc", "tty_open"):
                    truthy(want in names, "missing tool %s" % want)
                truthy(len(tools) >= 25, "tool count %d" % len(tools))
                for t in tools:
                    truthy(t["description"], "description for " + t["name"])
                    eq(t["inputSchema"]["type"], "object", "schema for " + t["name"])
            check("tools/list", t_list)

            def t_hosts():
                resp = cli.call("tools/call", {"name": "hosts", "arguments": {}})
                data = json.loads(tool_text(resp))
                eq(data["default"], "sub", "default host")
                eq(data["hosts"][0]["online"], True, "online")
            check("tools/call hosts", t_hosts)

            def t_info():
                resp = cli.call("tools/call", {"name": "host_info", "arguments": {}})
                data = json.loads(tool_text(resp))
                truthy(data["hostname"], "hostname")
                truthy(data["cpu_count"] >= 1, "cpu")
            check("tools/call host_info", t_info)

            def t_run():
                resp = cli.call("tools/call", {"name": "run",
                                               "arguments": {"command": "echo mcp-works"}})
                self_ok = resp["result"]["isError"] is False
                truthy(self_ok, "isError false")
                truthy("mcp-works" in tool_text(resp), "stdout")
            check("tools/call run", t_run)

            def t_run_script():
                script = "import platform\nprint('py', platform.python_version())"
                resp = cli.call("tools/call", {"name": "run_script",
                                               "arguments": {"script": script, "lang": "python"}})
                truthy("py 3" in tool_text(resp), "script output")
            check("tools/call run_script", t_run_script)

            def t_fs_roundtrip():
                path = os.path.join(work, "mcp.txt")
                cli.call("tools/call", {"name": "fs_write",
                                        "arguments": {"path": path, "data": "alpha\nbeta\n"}})
                resp = cli.call("tools/call", {"name": "fs_read", "arguments": {"path": path}})
                truthy("beta" in tool_text(resp), "read back")
                resp = cli.call("tools/call", {"name": "fs_grep",
                                               "arguments": {"root": work, "pattern": "beta"}})
                truthy("mcp.txt" in tool_text(resp), "grep")
            check("fs_write/read/grep", t_fs_roundtrip)

            def t_pull():
                path = os.path.join(work, "pull-me.txt")
                cli.call("tools/call", {"name": "fs_write",
                                        "arguments": {"path": path, "data": "pull payload"}})
                resp = cli.call("tools/call", {"name": "fs_pull",
                                               "arguments": {"path": path}})
                data = json.loads(tool_text(resp))
                truthy(os.path.exists(data["local_path"]), "local file exists")
                with open(data["local_path"], "r", encoding="utf-8") as fh:
                    eq(fh.read(), "pull payload", "content")
            check("fs_pull to local disk", t_pull)

            def t_unknown_tool():
                resp = cli.call("tools/call", {"name": "no_such_tool", "arguments": {}})
                truthy("error" in resp, "json-rpc error")
                eq(resp["error"]["code"], -32602, "code")
            check("unknown tool -> -32602", t_unknown_tool)

            def t_unknown_method():
                resp = cli.call("nonsense/method")
                eq(resp["error"]["code"], -32601, "code")
            check("unknown method -> -32601", t_unknown_method)

            def t_error_is_reported():
                resp = cli.call("tools/call", {"name": "fs_read",
                                               "arguments": {"path": "/definitely/not/here"}})
                truthy(resp["result"]["isError"], "isError true")
                truthy("error" in tool_text(resp), "error payload")
            check("remote error surfaces as isError", t_error_is_reported)

            def t_old_protocol_version():
                resp = cli.call("initialize", {"protocolVersion": "2024-11-05",
                                               "capabilities": {},
                                               "clientInfo": {"name": "old", "version": "0"}})
                eq(resp["result"]["protocolVersion"], "2024-11-05", "negotiated")
            check("protocol version negotiation", t_old_protocol_version)
        finally:
            cli.close()
    finally:
        agent.terminate()
        try:
            agent.wait(timeout=5)
        except Exception:
            agent.kill()

    print()
    width = max(len(r[0]) for r in RESULTS) + 2
    failed = 0
    for name, okflag, err in RESULTS:
        print("%-6s %-*s %s" % ("PASS" if okflag else "FAIL", width, name, err))
        if not okflag:
            failed += 1
    print("\n%d/%d passed" % (len(RESULTS) - failed, len(RESULTS)))
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
