"""Command line entry point: `crosswire <command>`."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time

from . import __version__
from . import config as cfgmod
from . import protocol as P
from .client import RemoteError, open_remote
from .mcp import tools as toolmod


def _c(text, code):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return "\033[%sm%s\033[0m" % (code, text)


def ok(t):
    return _c(t, "32")


def bad(t):
    return _c(t, "31")


def dim(t):
    return _c(t, "2")


def bold(t):
    return _c(t, "1")


def eprint(*a):
    print(*a, file=sys.stderr)


# ------------------------------------------------------------------- commands

def cmd_init(args):
    home = cfgmod.ensure_home()
    cfg = cfgmod.load()
    cfgmod.save(cfg)
    key_path = cfgmod.default_key_file()
    created = False
    if not os.path.exists(key_path) or args.force:
        raw = P.gen_key(32)
        cfgmod.write_key_file(key_path, P.format_key(raw))
        created = True
    key = cfgmod.read_key_file(key_path)
    print("config dir : %s" % home)
    print("hosts file : %s" % cfgmod.config_path())
    print("key file   : %s%s" % (key_path, "  (new)" if created else ""))
    print("key        : %s" % key)
    print()
    print(bold("Next:"))
    print("  1. copy agent/crosswire_agentd.py to the Linux box and run:")
    print("       sudo mkdir -p /etc/crosswire")
    print("       sudo python3 crosswire_agentd.py --keygen --out /etc/crosswire/agent.key")
    print("     then start it with that key (see docs/DEPLOY.md).")
    print("  2. register the machine here:")
    print("       crosswire add sub 192.168.1.50 --key %s" % key[:14] + "...")
    print("  3. wire it into your agent:")
    print("       crosswire dsh-install        # DeepSeek Harness")
    print("       crosswire mcp-config         # everything else")
    return 0


def cmd_add(args):
    cfg = cfgmod.add_host(args.alias, args.host, args.port, key=args.key,
                          user=args.user, note=args.note,
                          set_default=args.default, key_file=args.key_file)
    print("added %s -> %s:%s%s" % (args.alias, args.host, args.port,
                                   "  (default)" if cfg.get("default") == args.alias else ""))
    if not args.no_check:
        _try_ping(args.alias)
    return 0


def cmd_rm(args):
    cfgmod.remove_host(args.alias)
    print("removed %s" % args.alias)
    return 0


def cmd_default(args):
    cfgmod.set_default(args.alias)
    print("default host is now %s" % args.alias)
    return 0


def cmd_list(args):
    cfg = cfgmod.load()
    hosts = cfg.get("hosts") or {}
    if not hosts:
        print("no hosts yet — `crosswire add sub 192.168.1.50 --key <key>`")
        return 1
    print("%-10s %-22s %-6s %-8s %s" % ("ALIAS", "ADDRESS", "PORT", "STATUS", "NOTE"))
    for alias, entry in sorted(hosts.items()):
        mark = "*" if cfg.get("default") == alias else " "
        status = dim("?")
        if not args.no_check:
            t0 = time.time()
            try:
                remote = open_remote(cfg, alias)
                remote.ping(timeout=3)
                status = ok("%.0fms" % ((time.time() - t0) * 1000))
                remote.close()
            except Exception as exc:  # noqa: BLE001
                status = bad("offline")
                if args.verbose:
                    status += dim(" (%s)" % str(exc)[:40])
        print("%s%-9s %-22s %-6s %-8s %s" % (mark, alias,
                                              "%s" % entry.get("host"),
                                              entry.get("port", 7900),
                                              status, entry.get("note", "")))
    print(dim("\n* = default"))
    return 0


def cmd_ping(args):
    cfg = cfgmod.load()
    t0 = time.time()
    remote = open_remote(cfg, args.alias)
    info = remote.ping()
    print(ok("online") + "  %s  %.1fms" % (info.get("host"), info.get("ms")))
    print(dim("os=%s agent=%s total=%.1fms" %
              (info.get("os"), info.get("agent"), (time.time() - t0) * 1000)))
    remote.close()
    return 0


def cmd_info(args):
    cfg = cfgmod.load()
    remote = open_remote(cfg, args.alias)
    info = remote.request("sys.info", {}, timeout=15)
    for k in ("hostname", "os", "kernel", "arch", "user", "is_root", "cpu_count",
              "cpu_model", "mem_total_mb", "disk_free_gb", "uptime_s", "init",
              "pkg_manager", "allow_sudo", "allow_power", "allow_pkg", "ipv4"):
        print("%-14s %s" % (k, info.get(k)))
    remote.close()
    return 0


def cmd_sh(args):
    cfg = cfgmod.load()
    remote = open_remote(cfg, args.alias)
    cmd = args.command if isinstance(args.command, str) else " ".join(args.command)
    res = remote.request("exec.run", {"command": cmd, "timeout": args.timeout}, timeout=args.timeout + 10)
    sys.stdout.write(res.get("stdout") or "")
    sys.stderr.write(res.get("stderr") or "")
    remote.close()
    return int(res.get("exit") or 0)


def cmd_push(args):
    cfg = cfgmod.load()
    remote = open_remote(cfg, args.alias)
    info = remote.push(args.local, args.remote)
    print("uploaded %s -> %s (%d bytes, sha256 %s)" %
          (args.local, info["remote_path"], info["size"], info["sha256"][:16]))
    remote.close()
    return 0


def cmd_pull(args):
    cfg = cfgmod.load()
    remote = open_remote(cfg, args.alias)
    local = args.local or os.path.join(cfg["downloads"], os.path.basename(args.remote))
    info = remote.pull(args.remote, local)
    print("downloaded %s -> %s (%d bytes)" % (args.remote, info["local_path"], info["size"]))
    remote.close()
    return 0


def cmd_shell(args):
    cfg = cfgmod.load()
    remote = open_remote(cfg, args.alias)
    tty = remote.request("tty.open", {}, timeout=20)
    tid = tty["tty_id"]
    print(dim("connected to %s (%s). type 'exit' or Ctrl-D to leave." %
              (remote.alias, remote.info.get("host"))))
    offset = 0
    try:
        while True:
            try:
                line = input(_c("$ ", "36"))
            except EOFError:
                break
            if line.strip() in ("exit", "quit", ":q"):
                break
            remote.request("tty.write", {"tty_id": tid, "data": line + "\n"}, timeout=10)
            res = remote.request("tty.read", {"tty_id": tid, "offset": offset, "wait": 0.6},
                                 timeout=15)
            sys.stdout.write(res.get("data") or "")
            offset = res.get("offset", offset)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            remote.request("tty.close", {"tty_id": tid}, timeout=10)
        except Exception:
            pass
        remote.close()
    return 0


def cmd_keygen(args):
    raw = P.gen_key(32)
    text = P.format_key(raw)
    if args.out:
        cfgmod.write_key_file(args.out, text)
        print("wrote %s" % args.out)
    print(text)
    if not args.quiet:
        eprint(dim("\nOn the target:  crosswire_agentd.py --keygen --out /etc/crosswire/agent.key"))
    return 0


def cmd_serve(args):
    from .mcp.server import StdioServer
    cfg = cfgmod.load()
    ctx = toolmod.Ctx(cfg, logger=lambda m: eprint("[crosswire] %s" % m))
    if args.list_tools:
        for t in toolmod.tool_list_payload():
            print("%-12s %s" % (t["name"], t["description"].split(".")[0]))
        return 0
    return StdioServer(ctx, name=args.name).serve()


def cmd_tools(args):
    for t in toolmod.tool_list_payload():
        print(bold(t["name"]))
        print("  " + t["description"].replace("\n", "\n  "))
        props = (t["inputSchema"].get("properties") or {})
        if props:
            print(dim("  args: " + ", ".join(sorted(props))))
        print()
    return 0


def cmd_doctor(args):
    problems = 0
    print(bold("config"))
    print("  home        %s" % cfgmod.home())
    print("  hosts.json  %s %s" % (cfgmod.config_path(),
                                   ok("ok") if os.path.exists(cfgmod.config_path()) else bad("missing")))
    try:
        cfg = cfgmod.load()
    except Exception as exc:  # noqa: BLE001
        print(bad("  cannot load config: %s" % exc))
        return 2
    hosts = cfg.get("hosts") or {}
    print("  hosts       %d configured, default=%s" % (len(hosts), cfg.get("default")))
    print("  downloads   %s" % cfg.get("downloads"))
    print()
    print(bold("python"))
    print("  %s on %s" % (sys.version.split()[0], platform.platform()))
    print()
    print(bold("hosts"))
    for alias in sorted(hosts):
        try:
            entry = dict(hosts[alias])
            key = cfgmod.host_key(entry, cfg)
            P.parse_key(key)
        except Exception as exc:  # noqa: BLE001
            print("  %-8s %s" % (alias, bad("key problem: %s" % exc)))
            problems += 1
            continue
        t0 = time.time()
        try:
            remote = open_remote(cfg, alias)
            info = remote.request("sys.info", {}, timeout=10)
            print("  %-8s %s %s  %s  agent=%s  sudo=%s pkg=%s power=%s" % (
                alias, ok("online"), "%.0fms" % ((time.time() - t0) * 1000),
                info.get("os"), remote.info.get("agent"),
                info.get("allow_sudo"), info.get("allow_pkg"), info.get("allow_power")))
            remote.close()
        except RemoteError as exc:
            print("  %-8s %s  %s" % (alias, bad("offline"), exc.msg))
            if exc.detail:
                print("           %s" % dim(exc.detail))
            problems += 1
        except Exception as exc:  # noqa: BLE001
            print("  %-8s %s  %s" % (alias, bad("error"), exc))
            problems += 1
    print()
    if problems:
        print(bad("%d problem(s)" % problems))
        return 1
    print(ok("all good"))
    return 0


def _try_ping(alias):
    try:
        cfg = cfgmod.load()
        t0 = time.time()
        remote = open_remote(cfg, alias)
        info = remote.ping(timeout=4)
        print(ok("  reachable") + "  %s  %.0fms" % (info.get("host"), (time.time() - t0) * 1000))
        remote.close()
        return True
    except Exception as exc:  # noqa: BLE001
        print(bad("  not reachable: %s" % exc))
        print(dim("  check: is agentd running on the target? firewall open on the port? "
                  "same LAN? key correct?"))
        return False


def cmd_bootstrap(args):
    """Print exactly what to paste on the Linux box."""
    key = args.key
    if not key:
        key = cfgmod.read_key_file(cfgmod.default_key_file())
    key = key or "<your-key>"
    port = args.port or cfgmod.DEFAULT_PORT
    script = """
# --- on the target machine (Linux) -----------------------------------------
sudo mkdir -p /etc/crosswire /opt/crosswire
sudo cp crosswire_agentd.py /opt/crosswire/
echo '%s' | sudo tee /etc/crosswire/agent.key >/dev/null
sudo chmod 600 /etc/crosswire/agent.key

# run in the foreground first to see it work
sudo python3 /opt/crosswire/crosswire_agentd.py \\
     --key-file /etc/crosswire/agent.key --port %d --allow-sudo --allow-pkg

# then install it as a service
sudo python3 /opt/crosswire/crosswire_agentd.py --print-unit \\
     | sudo tee /etc/systemd/system/crosswire-agentd.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now crosswire-agentd
sudo ufw allow %d/tcp        # or firewall-cmd --add-port=%d/tcp
""" % (key, port, port, port)
    print(script.strip())
    return 0


def cmd_mcp_config(args):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    py = sys.executable
    entry = {
        "command": py,
        "args": [os.path.join(here, "cw.py"), "serve"],
        "env": {"CROSSWIRE_HOME": cfgmod.home()},
    }
    if args.client == "claude":
        payload = {"mcpServers": {"crosswire": entry}}
    elif args.client == "codex":
        payload = {"mcp_servers": {"crosswire": dict(entry, startup_timeout_sec=30)}}
    else:
        payload = {"mcpServers": {"crosswire": entry}}
    print(json.dumps(payload, indent=2))
    return 0


def cmd_dsh_install(args):
    """Register this MCP server into DeepSeek Harness profiles."""
    home = os.path.expanduser("~/.dsh")
    profiles_dir = os.path.join(home, "profiles")
    if not os.path.isdir(profiles_dir):
        eprint(bad("no DeepSeek Harness at %s" % home))
        return 2
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    launcher = os.path.join(here, "cw.py")
    py = args.python or sys.executable
    if os.name == "nt":
        # git-bash / msys happily rewrites C:\x into C://x when passing args
        py = py.replace("/", "\\")
        launcher = launcher.replace("/", "\\")
        here = here.replace("/", "\\")
    targets = args.profile or [d for d in sorted(os.listdir(profiles_dir))
                               if os.path.isdir(os.path.join(profiles_dir, d))]
    block = """
# ── CrossWire ────────────────────────────────────────────────────────────────
# LAN control of another machine (Linux box as the "sub" host). Adds the
# mcp__crosswire__* tool family. Server: crosswire/cw.py serve
- insert:
    - id: mcp-crosswire
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: crosswire
        transport: stdio
        command: '%s'
        args:
          - '%s'
          - 'serve'
        cwd: '%s'
        env:
          CROSSWIRE_HOME: '%s'
        toolCallTimeoutMs: 600000
        failOnStartupError: false
""" % (py, launcher, here, cfgmod.home())
    changed = []
    for name in targets:
        path = os.path.join(profiles_dir, name, "cordis.patch.yml")
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if "mcp-crosswire" in text:
            print(dim("  %-8s already registered" % name))
            continue
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(block)
        changed.append(name)
        print(ok("  %-8s registered" % name))
    if changed:
        print("\nrestart dsh to pick it up: %s" % ", ".join(changed))
    return 0


def cmd_serve_agent(args):
    """Convenience: run the bundled agent daemon (handy for a self-test)."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    agent = os.path.join(here, "agent", "crosswire_agentd.py")
    argv = [sys.executable, agent] + args.agent_args
    return subprocess.call(argv)


# ---------------------------------------------------------------------- parser

def build_parser():
    ap = argparse.ArgumentParser(
        prog="crosswire",
        description="CrossWire %s — control another machine on your LAN from an AI agent." % __version__)
    ap.add_argument("-V", "--version", action="version", version="crosswire " + __version__)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="create ~/.crosswire and a fresh key")
    p.add_argument("--force", action="store_true", help="replace an existing key")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add", help="register a target machine")
    p.add_argument("alias", help="short name, e.g. sub")
    p.add_argument("host", help="IP or hostname on the LAN")
    p.add_argument("--port", type=int, default=cfgmod.DEFAULT_PORT)
    p.add_argument("--key", default=None)
    p.add_argument("--key-file", default=None)
    p.add_argument("--user", default=None)
    p.add_argument("--note", default=None)
    p.add_argument("--default", action="store_true")
    p.add_argument("--no-check", action="store_true")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("rm", help="forget a target")
    p.add_argument("alias")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("default", help="set the default target")
    p.add_argument("alias")
    p.set_defaults(func=cmd_default)

    p = sub.add_parser("list", help="list targets and their reachability")
    p.add_argument("--no-check", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("ping", help="round-trip test")
    p.add_argument("alias", nargs="?")
    p.set_defaults(func=cmd_ping)

    p = sub.add_parser("info", help="show what the target is")
    p.add_argument("alias", nargs="?")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("sh", help="run one command on the target")
    p.add_argument("command", help="quote the whole command line: sh \"df -h && free -m\"")
    p.add_argument("--host", dest="alias", default=None)
    p.add_argument("--timeout", type=float, default=60)
    p.set_defaults(func=cmd_sh)

    p = sub.add_parser("push", help="upload a file")
    p.add_argument("local")
    p.add_argument("remote")
    p.add_argument("--host", dest="alias", default=None)
    p.set_defaults(func=cmd_push)

    p = sub.add_parser("pull", help="download a file")
    p.add_argument("remote")
    p.add_argument("local", nargs="?")
    p.add_argument("--host", dest="alias", default=None)
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("shell", help="interactive shell on the target")
    p.add_argument("alias", nargs="?")
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("keygen", help="generate a shared key")
    p.add_argument("--out", default=None)
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("serve", help="run the MCP server on stdio (what the agent launches)")
    p.add_argument("--name", default="crosswire")
    p.add_argument("--list-tools", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("tools", help="print the tool catalogue")
    p.set_defaults(func=cmd_tools)

    p = sub.add_parser("doctor", help="check config, key and connectivity")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("bootstrap", help="print the install snippet for the Linux box")
    p.add_argument("--key", default=None)
    p.add_argument("--port", type=int, default=None)
    p.set_defaults(func=cmd_bootstrap)

    p = sub.add_parser("mcp-config", help="print a client config block")
    p.add_argument("--client", choices=["claude", "codex", "generic"], default="generic")
    p.set_defaults(func=cmd_mcp_config)

    p = sub.add_parser("dsh-install", help="register into DeepSeek Harness profiles")
    p.add_argument("--profile", action="append", default=None)
    p.add_argument("--python", default=None)
    p.set_defaults(func=cmd_dsh_install)

    p = sub.add_parser("agent", help="run the bundled agent daemon")
    p.add_argument("agent_args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_serve_agent)

    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 1
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        return 130
    except RemoteError as exc:
        eprint(bad("error: %s" % exc.msg))
        if exc.detail:
            eprint(dim("  " + exc.detail))
        return 1
    except cfgmod.HostNotFound as exc:
        eprint(bad("error: %s" % exc))
        return 1
    except RuntimeError as exc:
        eprint(bad("error: %s" % exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
