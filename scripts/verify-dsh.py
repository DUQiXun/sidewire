#!/usr/bin/env python3
"""Verify that DeepSeek Harness can actually boot the registered MCP server.

It reads the real `cordis.patch.yml` files, extracts the `mcp-crosswire`
entry, launches it exactly the way dsh would (same command, args, cwd, env),
and runs an MCP handshake plus `tools/list` against it.

    python scripts/verify-dsh.py
    python scripts/verify-dsh.py --profile desktop
"""

import argparse
import json
import os
import subprocess
import sys

try:
    import yaml
except ImportError:
    print("this script needs pyyaml:  pip install pyyaml")
    sys.exit(2)


def dsh_home():
    return os.environ.get("DSH_HOME") or os.path.join(os.path.expanduser("~"), ".dsh")


def find_entries(profile=None):
    root = os.path.join(dsh_home(), "profiles")
    if not os.path.isdir(root):
        return []
    found = []
    for name in sorted(os.listdir(root)):
        if profile and name != profile:
            continue
        path = os.path.join(root, name, "cordis.patch.yml")
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or []
        except Exception as exc:  # noqa: BLE001
            print("%-8s  YAML ERROR: %s" % (name, str(exc).splitlines()[0]))
            continue
        for entry in doc:
            if not isinstance(entry, dict):
                continue
            for item in entry.get("insert") or []:
                if item.get("id") == "mcp-crosswire":
                    found.append((name, item.get("config") or {}))
    return found


def rpc(proc, obj):
    proc.stdin.write(json.dumps(obj).encode() + b"\n")
    proc.stdin.flush()


def read_id(proc, rid, timeout=25):
    end = timeout
    while end > 0:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout: " + proc.stderr.read().decode("utf-8", "replace")[-800:])
        try:
            msg = json.loads(line.decode("utf-8"))
        except ValueError:
            continue
        if msg.get("id") == rid:
            return msg
        end -= 1
    raise RuntimeError("no answer for id=%s" % rid)


def check(name, cfg):
    cmd = cfg.get("command")
    args = cfg.get("args") or []
    env = dict(os.environ)
    env.update(cfg.get("env") or {})
    cwd = cfg.get("cwd") or None
    print("  command : %s %s" % (cmd, " ".join(args)))
    print("  cwd     : %s" % cwd)
    try:
        proc = subprocess.Popen([cmd] + list(args), cwd=cwd, env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except Exception as exc:  # noqa: BLE001
        print("  FAIL    : cannot start (%s)" % exc)
        return False
    try:
        rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "verify-dsh", "version": "0"}}})
        res = read_id(proc, 1)["result"]
        print("  server  : %s %s (protocol %s)" % (
            res["serverInfo"]["name"], res["serverInfo"]["version"], res["protocolVersion"]))
        rpc(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = read_id(proc, 2)["result"]["tools"]
        print("  tools   : %d registered" % len(tools))
        rpc(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "hosts", "arguments": {}}})
        payload = json.loads(read_id(proc, 3)["result"]["content"][0]["text"])
        hosts = payload.get("hosts") or []
        print("  hosts   : %s" % (", ".join(
            "%s(%s)" % (h["alias"], "up" if h.get("online") else "down") for h in hosts)
            or "none configured yet"))
        return True
    except Exception as exc:  # noqa: BLE001
        print("  FAIL    : %s" % exc)
        return False
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=None)
    args = ap.parse_args()

    entries = find_entries(args.profile)
    if not entries:
        print("no mcp-crosswire entry found under %s" % os.path.join(dsh_home(), "profiles"))
        return 1
    bad = 0
    for name, cfg in entries:
        print("\nprofile: %s" % name)
        if not check(name, cfg):
            bad += 1
    print("\n%d/%d profiles boot the server cleanly" % (len(entries) - bad, len(entries)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
