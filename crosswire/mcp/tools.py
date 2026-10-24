"""MCP tool definitions and their handlers.

Every tool takes an optional ``host`` argument so one MCP server can drive
several machines ("main" / "sub" / "lab" …).  Tools that return file content
respect a byte cap and say so explicitly instead of silently cutting text.
"""

from __future__ import annotations

import json
import os
import time

from .. import config as cfgmod
from ..client import RemoteError, open_remote

HOST_PROP = {
    "type": "string",
    "description": "Target host alias from the host registry (e.g. 'sub'). "
                   "Omit to use the default host.",
}

MAX_OUT = 60000


class Ctx(object):
    """Shared state: one lazily opened connection per host alias."""

    def __init__(self, cfg, logger=None):
        self.cfg = cfg
        self.log = logger or (lambda *a, **k: None)
        self._conns = {}
        self.downloads = cfg.get("downloads")

    def conn(self, alias=None):
        cfg = self.cfg
        name, entry = cfgmod.resolve_host(cfg, alias)
        key_text = cfgmod.host_key(entry, cfg)
        existing = self._conns.get(name)
        if existing and existing.alive:
            return existing
        if existing:
            try:
                existing.close()
            except Exception:
                pass
        remote = open_remote(cfg, name, self.log)
        self._conns[name] = remote
        return remote

    def close_all(self):
        for remote in self._conns.values():
            try:
                remote.close()
            except Exception:
                pass
        self._conns.clear()


def _json(obj, limit=MAX_OUT):
    text = json.dumps(obj, ensure_ascii=False, indent=1, default=str)
    if len(text) > limit:
        text = text[:limit] + "\n… [output truncated at %d chars]" % limit
    return text


def _result(obj):
    text = _json(obj)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": obj if isinstance(obj, dict) else {"value": obj},
        "isError": bool(isinstance(obj, dict) and obj.get("error")),
    }


def _fail(exc):
    if isinstance(exc, RemoteError):
        payload = {"error": exc.msg, "code": exc.code}
        if exc.detail:
            payload["detail"] = exc.detail
    elif isinstance(exc, cfgmod.HostNotFound):
        payload = {"error": str(exc), "code": "unknown_host"}
    else:
        payload = {"error": "%s: %s" % (type(exc).__name__, exc), "code": "client_error"}
    return {
        "content": [{"type": "text", "text": _json(payload)}],
        "isError": True,
    }


# ---------------------------------------------------------------- definitions

def _schema(props, required=None):
    return {"type": "object", "properties": props,
            "required": required or [], "additionalProperties": True}


def _host(props):
    p = dict(props)
    p["host"] = HOST_PROP
    return p


TOOLS = [
    {
        "name": "hosts",
        "description":
            "List the configured target machines (alias, address, whether it answers right now) "
            "and which one is the default. Call this first when you are unsure which machine "
            "'the other computer' means.",
        "inputSchema": _schema({}),
        "handler": "t_hosts",
    },
    {
        "name": "host_info",
        "description":
            "Identify the target: hostname, distro/kernel, arch, current user, cpu/mem/disk, "
            "uptime, interfaces, init system, package manager, and which dangerous features "
            "(sudo, power, pkg) the agent policy allows. Always call this before your first "
            "real operation so you know what you are talking to.",
        "inputSchema": _schema(_host({})),
        "handler": "t_host_info",
    },
    {
        "name": "host_probe",
        "description": "Cheap round-trip latency check plus agent version. Use it to tell "
                       "'machine is off' apart from 'agent is broken'.",
        "inputSchema": _schema(_host({})),
        "handler": "t_host_probe",
    },
    {
        "name": "run",
        "description":
            "Run a command on the target and return exit code, stdout and stderr. "
            "Prefer the plain string form: run(command=\"ls -la /etc\"). Commands execute with "
            "the target's login shell (bash -lc) so PATH and aliases behave like an SSH session. "
            "Long commands: set timeout and you get a job_id back to poll with job_poll; or set "
            "background=true and poll. Output is capped at max_output bytes per stream.",
        "inputSchema": _schema(_host({
            "command": {"type": "string", "description": "Shell command line, e.g. \"df -h && free -m\""},
            "argv": {"type": "array", "items": {"type": "string"},
                     "description": "Exact argv instead of a shell line (no quoting, no globbing)"},
            "shell": {"type": "string", "description": "Shell to use, e.g. /bin/sh or /usr/bin/python3"},
            "cwd": {"type": "string", "description": "Working directory on the target"},
            "env": {"type": "object", "description": "Extra environment variables"},
            "stdin": {"type": "string", "description": "Text piped into the command's stdin"},
            "timeout": {"type": "number", "description": "Seconds to wait before returning a job_id (default 60)"},
            "sudo": {"type": "boolean", "description": "Run through sudo (needs allow_sudo or NOPASSWD)"},
            "background": {"type": "boolean", "description": "Do not wait at all; return a job_id immediately"},
            "max_output": {"type": "integer", "description": "Per-stream byte cap (default 60000)"},
            "label": {"type": "string", "description": "Human label shown in job listings"},
        }), []),
        "handler": "t_run",
    },
    {
        "name": "run_script",
        "description":
            "Write a script to a temp file on the target and execute it. Use this instead of "
            "run() whenever the command contains quotes, heredocs, $variables or several lines — "
            "it removes an entire class of quoting bugs. The temp file is deleted afterwards "
            "unless keep=true.",
        "inputSchema": _schema(_host({
            "script": {"type": "string", "description": "Full script body"},
            "lang": {"type": "string", "enum": ["bash", "sh", "python", "perl", "node", "pwsh"],
                     "description": "Interpreter (default bash)"},
            "cwd": {"type": "string"},
            "timeout": {"type": "number"},
            "sudo": {"type": "boolean"},
            "keep": {"type": "boolean", "description": "Leave the script on disk"},
            "max_output": {"type": "integer"},
        }), ["script"]),
        "handler": "t_run_script",
    },
    {
        "name": "job_list",
        "description": "List background jobs started on the target (running and recently finished).",
        "inputSchema": _schema(_host({"limit": {"type": "integer"}})),
        "handler": "t_job_list",
    },
    {
        "name": "job_poll",
        "description":
            "Read new output from a background job. Pass the stdout_offset/stderr_offset from the "
            "previous call to get only the delta. wait=N blocks up to N seconds for new output, "
            "which is usually better than polling in a tight loop.",
        "inputSchema": _schema(_host({
            "job_id": {"type": "string"},
            "stdout_offset": {"type": "integer"},
            "stderr_offset": {"type": "integer"},
            "wait": {"type": "number", "description": "Seconds to block waiting for output"},
            "max_output": {"type": "integer"},
        }), ["job_id"]),
        "handler": "t_job_poll",
    },
    {
        "name": "job_kill",
        "description": "Terminate a background job (kills the whole process group).",
        "inputSchema": _schema(_host({
            "job_id": {"type": "string"},
            "signal": {"type": "integer", "description": "Signal number, default 15"},
        }), ["job_id"]),
        "handler": "t_job_kill",
    },
    {
        "name": "tty_open",
        "description":
            "Open a persistent interactive shell (real PTY) on the target. Use it for things that "
            "need state across commands: ssh into another box, an interactive installer, a REPL, "
            "or a program that only works on a terminal. Returns a tty_id; then use tty_write / "
            "tty_read. Most one-shot work should use run() instead.",
        "inputSchema": _schema(_host({
            "shell": {"type": "string", "description": "e.g. /bin/bash or /usr/bin/python3"},
            "cwd": {"type": "string"},
            "cols": {"type": "integer"},
            "rows": {"type": "integer"},
        })),
        "handler": "t_tty_open",
    },
    {
        "name": "tty_write",
        "description": "Type into an interactive shell. Newlines are converted to carriage "
                       "returns automatically; set raw=true to send bytes verbatim.",
        "inputSchema": _schema(_host({
            "tty_id": {"type": "string"},
            "data": {"type": "string", "description": "Text to type; include \\n to press Enter"},
            "raw": {"type": "boolean"},
        }), ["tty_id", "data"]),
        "handler": "t_tty_write",
    },
    {
        "name": "tty_read",
        "description":
            "Read new terminal output since offset. wait=N blocks up to N seconds (use ~1-3s after "
            "typing something). until=\"$ \" waits for a pattern to appear in the buffer.",
        "inputSchema": _schema(_host({
            "tty_id": {"type": "string"},
            "offset": {"type": "integer", "description": "Byte offset returned by the previous read"},
            "wait": {"type": "number"},
            "until": {"type": "string"},
        }), ["tty_id"]),
        "handler": "t_tty_read",
    },
    {
        "name": "tty_close",
        "description": "Close an interactive shell and its process group.",
        "inputSchema": _schema(_host({"tty_id": {"type": "string"}}), ["tty_id"]),
        "handler": "t_tty_close",
    },
    {
        "name": "fs_ls",
        "description":
            "List a directory on the target. Returns name, type, size, mode, mtime for each entry. "
            "depth>1 recurses (capped at 8) and is handy for a quick tree of a project.",
        "inputSchema": _schema(_host({
            "path": {"type": "string"},
            "all": {"type": "boolean", "description": "Include dotfiles"},
            "depth": {"type": "integer", "description": "1 = this directory only"},
            "limit": {"type": "integer"},
        })),
        "handler": "t_fs_ls",
    },
    {
        "name": "fs_read",
        "description":
            "Read a file from the target as text. For big files use start_line/end_line or "
            "offset/max_bytes — do not pull a 200 MB log into the conversation. Binary files "
            "come back base64 only if you ask for binary=true.",
        "inputSchema": _schema(_host({
            "path": {"type": "string"},
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
            "offset": {"type": "integer", "description": "Byte offset"},
            "max_bytes": {"type": "integer"},
            "encoding": {"type": "string"},
            "binary": {"type": "boolean"},
        }), ["path"]),
        "handler": "t_fs_read",
    },
    {
        "name": "fs_write",
        "description":
            "Write text to a file on the target (creates parent directories by default). "
            "mode='w' overwrites, 'a' appends, 'x' fails if the file exists. For a large binary "
            "blob use fs_push instead.",
        "inputSchema": _schema(_host({
            "path": {"type": "string"},
            "data": {"type": "string"},
            "data_b64": {"type": "string"},
            "mode": {"type": "string", "enum": ["w", "a", "x"]},
            "create_parents": {"type": "boolean"},
            "chmod": {"type": "string", "description": "Octal string, e.g. '755'"},
        }), ["path"]),
        "handler": "t_fs_write",
    },
    {
        "name": "fs_edit",
        "description":
            "Replace an exact substring (or regex) inside a remote file. Returns how many "
            "occurrences changed. Safer than rewriting a whole file with fs_write because "
            "nothing else in the file moves. Use dry_run=true to count first.",
        "inputSchema": _schema(_host({
            "path": {"type": "string"},
            "old": {"type": "string"},
            "new": {"type": "string"},
            "regex": {"type": "boolean"},
            "count": {"type": "integer", "description": "Max replacements (default all)"},
            "ignore_case": {"type": "boolean"},
            "backup": {"type": "boolean", "description": "Keep a .cw-bak copy"},
            "dry_run": {"type": "boolean"},
            "allow_missing": {"type": "boolean", "description": "Do not error when old is absent"},
        }), ["path", "old", "new"]),
        "handler": "t_fs_edit",
    },
    {
        "name": "fs_stat",
        "description": "File/directory metadata: size, mode, owner, mtime, inode, link target.",
        "inputSchema": _schema(_host({"path": {"type": "string"}}), ["path"]),
        "handler": "t_fs_stat",
    },
    {
        "name": "fs_find",
        "description":
            "Find files or directories by name glob under a root (\"*.log\", \"**/config.*\"). "
            "Cheaper than ls -R when you only need matches. Filters: type, size, age, depth.",
        "inputSchema": _schema(_host({
            "root": {"type": "string"},
            "pattern": {"type": "string"},
            "type": {"type": "string", "enum": ["any", "file", "dir"]},
            "max_depth": {"type": "integer"},
            "min_size": {"type": "integer"},
            "max_size": {"type": "integer"},
            "newer_than": {"type": "number", "description": "Unix timestamp"},
            "limit": {"type": "integer"},
            "follow_links": {"type": "boolean"},
        }), ["root", "pattern"]),
        "handler": "t_fs_find",
    },
    {
        "name": "fs_grep",
        "description":
            "Search file contents with a regular expression on the target. Skips binary files and "
            ".git/node_modules. Returns path, line number and the matching line. This runs on the "
            "target, so it is the right way to search a big tree without moving it.",
        "inputSchema": _schema(_host({
            "root": {"type": "string"},
            "pattern": {"type": "string"},
            "glob": {"type": "string", "description": "Filename filter, default *"},
            "ignore_case": {"type": "boolean"},
            "fixed": {"type": "boolean", "description": "Treat pattern as a literal string"},
            "max_matches": {"type": "integer"},
            "max_file_size": {"type": "integer"},
        }), ["root", "pattern"]),
        "handler": "t_fs_grep",
    },
    {
        "name": "fs_manage",
        "description":
            "One tool for filesystem housekeeping: op=mkdir|touch|rm|mv|cp|chmod|chown|symlink|truncate. "
            "rm on a directory requires recursive=true.",
        "inputSchema": _schema(_host({
            "op": {"type": "string",
                   "enum": ["mkdir", "touch", "rm", "mv", "cp", "chmod", "chown", "symlink", "truncate"]},
            "path": {"type": "string", "description": "Source path (or the link path for symlink)"},
            "dest": {"type": "string", "description": "Destination (mv/cp) or target (symlink)"},
            "mode": {"type": "string", "description": "Octal mode for chmod"},
            "recursive": {"type": "boolean"},
            "parents": {"type": "boolean"},
            "uid": {"type": "integer"},
            "gid": {"type": "integer"},
            "size": {"type": "integer", "description": "New size for truncate"},
        }), ["op", "path"]),
        "handler": "t_fs_manage",
    },
    {
        "name": "fs_pull",
        "description":
            "Copy a file FROM the target TO this machine and return the local path. Then read it "
            "with your normal local file tools. This is the only sane way to look at binaries, "
            "images or multi-MB files. Default local path is the downloads folder.",
        "inputSchema": _schema(_host({
            "path": {"type": "string", "description": "Path on the target"},
            "local_path": {"type": "string", "description": "Where to save it locally (optional)"},
            "timeout": {"type": "number"},
        }), ["path"]),
        "handler": "t_fs_pull",
    },
    {
        "name": "fs_push",
        "description":
            "Copy a local file TO the target. Use it for build artifacts, scripts, configs. "
            "The transfer is chunked and sha256-verified on arrival.",
        "inputSchema": _schema(_host({
            "local_path": {"type": "string", "description": "Path on this machine"},
            "path": {"type": "string", "description": "Destination path on the target"},
            "timeout": {"type": "number"},
        }), ["local_path", "path"]),
        "handler": "t_fs_push",
    },
    {
        "name": "fs_tail",
        "description": "Last N lines of a file — the cheap way to read the end of a log.",
        "inputSchema": _schema(_host({
            "path": {"type": "string"},
            "lines": {"type": "integer"},
        }), ["path"]),
        "handler": "t_fs_tail",
    },
    {
        "name": "fs_hash",
        "description": "sha256/sha1/md5 of a remote file, for verifying a transfer or a build.",
        "inputSchema": _schema(_host({
            "path": {"type": "string"},
            "algo": {"type": "string"},
        }), ["path"]),
        "handler": "t_fs_hash",
    },
    {
        "name": "proc_list",
        "description":
            "List processes read straight from /proc: pid, ppid, user, cpu%, rss, state, elapsed, "
            "full cmdline. sort by cpu|mem|pid|time. filter is a substring match on name+cmdline. "
            "cpu% is measured between two calls, so the first call after a while may show 0.",
        "inputSchema": _schema(_host({
            "filter": {"type": "string"},
            "sort": {"type": "string", "enum": ["cpu", "mem", "pid", "time"]},
            "limit": {"type": "integer"},
        })),
        "handler": "t_proc_list",
    },
    {
        "name": "proc_kill",
        "description": "Send a signal to a pid, or to every process matching an exact name.",
        "inputSchema": _schema(_host({
            "pid": {"type": "integer"},
            "name": {"type": "string"},
            "signal": {"type": "integer"},
        })),
        "handler": "t_proc_kill",
    },
    {
        "name": "svc",
        "description":
            "systemd/openrc/sysv service control: status, start, stop, restart, enable, disable, "
            "list, or logs (journalctl tail). Auto-detects the init system.",
        "inputSchema": _schema(_host({
            "name": {"type": "string"},
            "action": {"type": "string",
                       "enum": ["status", "start", "stop", "restart", "reload",
                                "enable", "disable", "list", "logs"]},
            "lines": {"type": "integer"},
        })),
        "handler": "t_svc",
    },
    {
        "name": "net",
        "description":
            "Network view of the target. action=info (interfaces + routes), sockets (listening/"
            "established from /proc/net, optionally with the owning pid), probe (can the target "
            "reach host:port), dns (resolve a name from the target).",
        "inputSchema": _schema(_host({
            "action": {"type": "string", "enum": ["info", "sockets", "probe", "dns"]},
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "states": {"type": "array", "items": {"type": "string"}},
            "with_pid": {"type": "boolean"},
            "limit": {"type": "integer"},
            "timeout": {"type": "number"},
        })),
        "handler": "t_net",
    },
    {
        "name": "pkg",
        "description":
            "Package manager operations (apt/dnf/yum/pacman/zypper/apk, auto-detected): "
            "install, remove, update, upgrade, search, info, list. Requires the agent to be started "
            "with --allow-pkg. Installs run non-interactively and can take minutes.",
        "inputSchema": _schema(_host({
            "action": {"type": "string",
                       "enum": ["install", "remove", "update", "upgrade", "search", "info", "list"]},
            "packages": {"type": "array", "items": {"type": "string"}},
            "manager": {"type": "string"},
            "timeout": {"type": "number"},
        }), ["action"]),
        "handler": "t_pkg",
    },
    {
        "name": "power",
        "description":
            "Reboot, shut down, suspend or cancel a pending shutdown. Requires --allow-power on "
            "the agent AND confirm=<action>. This disconnects the machine, so do it last and tell "
            "the user first.",
        "inputSchema": _schema(_host({
            "action": {"type": "string", "enum": ["reboot", "shutdown", "suspend", "cancel"]},
            "confirm": {"type": "string", "description": "Must equal the action, verbatim"},
        }), ["action", "confirm"]),
        "handler": "t_power",
    },
]

BY_NAME = {t["name"]: t for t in TOOLS}


# ------------------------------------------------------------------- handlers

def t_hosts(ctx, args):
    cfg = ctx.cfg
    default = cfg.get("default")
    out = []
    for alias, entry in sorted((cfg.get("hosts") or {}).items()):
        item = {"alias": alias, "host": entry.get("host"), "port": entry.get("port", 7900),
                "default": alias == default, "note": entry.get("note")}
        t0 = time.time()
        try:
            remote = ctx.conn(alias)
            remote.ping(timeout=3)
            item["online"] = True
            item["ms"] = round((time.time() - t0) * 1000, 1)
            item["os"] = remote.info.get("os")
            item["hostname"] = remote.info.get("host")
        except Exception as exc:  # noqa: BLE001
            item["online"] = False
            item["error"] = str(exc)
        out.append(item)
    return {"default": default, "hosts": out,
            "note": "Pass host=<alias> to any tool to target a specific machine."}


def t_host_info(ctx, args):
    return ctx.conn(args.get("host")).request("sys.info", {}, timeout=15)


def t_host_probe(ctx, args):
    remote = ctx.conn(args.get("host"))
    return remote.ping()


def t_run(ctx, args):
    params = dict(args)
    params.pop("host", None)
    timeout = float(params.get("timeout") or 60)
    if not params.get("max_output"):
        params["max_output"] = 60000
    res = ctx.conn(args.get("host")).request("exec.run", params, timeout=timeout + 10)
    return res


def t_run_script(ctx, args):
    params = dict(args)
    params.pop("host", None)
    timeout = float(params.get("timeout") or 60)
    res = ctx.conn(args.get("host")).request("exec.script", params, timeout=timeout + 10)
    return res


def t_job_list(ctx, args):
    params = dict(args)
    params.pop("host", None)
    return ctx.conn(args.get("host")).request("job.list", params, timeout=15)


def t_job_poll(ctx, args):
    params = dict(args)
    params.pop("host", None)
    wait = float(params.get("wait") or 0)
    return ctx.conn(args.get("host")).request("job.poll", params, timeout=wait + 20)


def t_job_kill(ctx, args):
    params = dict(args)
    params.pop("host", None)
    return ctx.conn(args.get("host")).request("job.kill", params, timeout=20)


def t_tty_open(ctx, args):
    params = dict(args)
    params.pop("host", None)
    return ctx.conn(args.get("host")).request("tty.open", params, timeout=20)


def t_tty_write(ctx, args):
    params = dict(args)
    params.pop("host", None)
    return ctx.conn(args.get("host")).request("tty.write", params, timeout=20)


def t_tty_read(ctx, args):
    params = dict(args)
    params.pop("host", None)
    wait = float(params.get("wait") or 0)
    return ctx.conn(args.get("host")).request("tty.read", params, timeout=wait + 15)


def t_tty_close(ctx, args):
    params = dict(args)
    params.pop("host", None)
    return ctx.conn(args.get("host")).request("tty.close", params, timeout=20)


def _strip_host(args):
    params = dict(args)
    params.pop("host", None)
    return params


def t_fs_ls(ctx, args):
    return ctx.conn(args.get("host")).request("fs.ls", _strip_host(args), timeout=30)


def t_fs_read(ctx, args):
    return ctx.conn(args.get("host")).request("fs.read", _strip_host(args), timeout=30)


def t_fs_write(ctx, args):
    return ctx.conn(args.get("host")).request("fs.write", _strip_host(args), timeout=60)


def t_fs_edit(ctx, args):
    return ctx.conn(args.get("host")).request("fs.edit", _strip_host(args), timeout=30)


def t_fs_stat(ctx, args):
    return ctx.conn(args.get("host")).request("fs.stat", _strip_host(args), timeout=20)


def t_fs_find(ctx, args):
    return ctx.conn(args.get("host")).request("fs.find", _strip_host(args), timeout=40)


def t_fs_grep(ctx, args):
    return ctx.conn(args.get("host")).request("fs.grep", _strip_host(args), timeout=40)


def t_fs_manage(ctx, args):
    return ctx.conn(args.get("host")).request("fs.manage", _strip_host(args), timeout=60)


def t_fs_tail(ctx, args):
    return ctx.conn(args.get("host")).request("fs.tail", _strip_host(args), timeout=20)


def t_fs_hash(ctx, args):
    return ctx.conn(args.get("host")).request("fs.hash", _strip_host(args), timeout=60)


def t_fs_pull(ctx, args):
    remote = ctx.conn(args.get("host"))
    remote_path = args["path"]
    local = args.get("local_path")
    if not local:
        base = os.path.basename(remote_path.rstrip("/\\")) or "download.bin"
        stamp = time.strftime("%H%M%S")
        local = os.path.join(ctx.downloads, "%s.%s" % (base, stamp))
    info = remote.pull(remote_path, local, timeout=args.get("timeout"))
    info["hint"] = "Read this local path with your normal file tools."
    return info


def t_fs_push(ctx, args):
    remote = ctx.conn(args.get("host"))
    return remote.push(args["local_path"], args["path"], timeout=args.get("timeout"))


def t_proc_list(ctx, args):
    return ctx.conn(args.get("host")).request("proc.list", _strip_host(args), timeout=30)


def t_proc_kill(ctx, args):
    return ctx.conn(args.get("host")).request("proc.kill", _strip_host(args), timeout=20)


def t_svc(ctx, args):
    return ctx.conn(args.get("host")).request("svc.action", _strip_host(args), timeout=45)


def t_net(ctx, args):
    return ctx.conn(args.get("host")).request("net.info", _strip_host(args), timeout=30)


def t_pkg(ctx, args):
    params = _strip_host(args)
    return ctx.conn(args.get("host")).request("pkg.action", params,
                                              timeout=float(args.get("timeout") or 300) + 20)


def t_power(ctx, args):
    return ctx.conn(args.get("host")).request("sys.power", _strip_host(args), timeout=20)


def dispatch(ctx, name, args):
    tool = BY_NAME.get(name)
    if not tool:
        raise KeyError(name)
    handler = globals()[tool["handler"]]
    try:
        return _result(handler(ctx, args or {}))
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


def tool_list_payload():
    return [{"name": t["name"], "description": t["description"],
             "inputSchema": t["inputSchema"]} for t in TOOLS]
