#!/usr/bin/env python3
"""Prove the MCP server re-reads hosts.json between calls (no restart needed)."""
import json
import os
import shutil
import subprocess
import sys

PY = sys.executable
CW = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sw.py"))
HOSTS = os.path.expanduser(r"~\.sidewire\hosts.json")


def main():
    backup = HOSTS + ".reloadtest"
    shutil.copy2(HOSTS, backup)
    try:
        proc = subprocess.Popen([PY, CW, "serve"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", bufsize=1)

        def send(o):
            proc.stdin.write(json.dumps(o) + "\n")
            proc.stdin.flush()

        def recv():
            return json.loads(proc.stdout.readline())

        def rpc(mid, method, params=None):
            send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
            return recv()

        rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "t", "version": "0"}})
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        def probe(mid, label):
            r = rpc(mid, "tools/call", {"name": "host_probe", "arguments": {}})
            if "error" in r:
                print("%-22s rpc error: %s" % (label, r["error"].get("message")[:70]))
                return False
            res = r["result"]
            text = " ".join(c.get("text", "") for c in res.get("content", []))
            text = " ".join(text.split())
            bad = res.get("isError")
            print("%-22s %s  %s" % (label, "FAIL" if bad else "ok", text[:90]))
            return not bad

        a = probe(10, "1. baseline")

        # point the host at an address nothing answers on
        cfg = json.load(open(HOSTS, encoding="utf-8"))
        real = cfg["hosts"]["a-desktop"]["host"]
        cfg["hosts"]["a-desktop"]["host"] = "127.0.0.1"
        cfg["hosts"]["a-desktop"]["port"] = 7999
        json.dump(cfg, open(HOSTS, "w", encoding="utf-8"), indent=2)

        b = probe(11, "2. after bad address")

        cfg["hosts"]["a-desktop"]["host"] = real
        cfg["hosts"]["a-desktop"]["port"] = 7900
        json.dump(cfg, open(HOSTS, "w", encoding="utf-8"), indent=2)

        c = probe(12, "3. after restoring")

        proc.stdin.close()
        proc.terminate()

        print()
        print("reload works:", "YES" if (a and not b and c) else "NO")
        return 0 if (a and not b and c) else 1
    finally:
        shutil.move(backup, HOSTS)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
