#!/usr/bin/env python3
"""Exercise MCP tools against the live LAN host and report real pass/fail."""
import json
import subprocess
import sys
import os

PY = sys.executable
CW = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cw.py"))

CASES = [
    ("hosts", {}),
    ("host_info", {}),
    ("run", {"command": "echo mcp-roundtrip && nproc && uname -r"}),
    ("fs_ls", {"path": "/home/a"}),
    ("fs_stat", {"path": "/etc/hostname"}),
    ("fs_hash", {"path": "/etc/hostname"}),
    ("fs_grep", {"root": "/etc", "pattern": "a-desktop"}),
    ("fs_find", {"root": "/home/a", "pattern": "*.py"}),
    ("proc_list", {"limit": 3}),
    ("net", {}),
    ("svc", {"action": "list", "limit": 3}),
    ("job_list", {}),
]


def main():
    proc = subprocess.Popen([PY, CW, "serve"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding="utf-8", bufsize=1)

    def send(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()

    def recv():
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        return json.loads(line)

    def rpc(mid, method, params=None):
        send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        return recv()

    init = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "probe", "version": "0"}})
    print("server:", init.get("result", {}).get("serverInfo"))
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    print("tools :", len(rpc(2, "tools/list").get("result", {}).get("tools", [])))

    ok = fail = 0
    for i, (name, args) in enumerate(CASES, start=10):
        r = rpc(i, "tools/call", {"name": name, "arguments": args})
        if "error" in r:
            print("\n%-11s FAIL  rpc error: %s" % (name, r["error"].get("message")))
            fail += 1
            continue
        res = r.get("result", {})
        content = res.get("content") or []
        text = " ".join(c.get("text", "") for c in content if c.get("type") == "text")
        text = " ".join(text.split())
        if res.get("isError"):
            print("\n%-11s FAIL  %s" % (name, text[:160]))
            fail += 1
        else:
            print("\n%-11s ok    %s" % (name, text[:170] or "(empty)"))
            ok += 1

    print("\n%d ok, %d failed" % (ok, fail))
    proc.stdin.close()
    proc.terminate()
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
