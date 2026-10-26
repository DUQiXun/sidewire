#!/usr/bin/env python3
"""End-to-end test: spawn a real agentd, drive it with the real client.

    python tests/e2e.py

It runs on Windows and Linux.  On Windows the agent falls back to cmd.exe and
pipe-based "tty", so a couple of POSIX-only assertions are skipped — everything
protocol level still gets exercised.
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

from sidewire import config as cfgmod          # noqa: E402
from sidewire import protocol as P             # noqa: E402
from sidewire.client import Remote, RemoteError, open_remote  # noqa: E402

IS_WIN = os.name == "nt"
RESULTS = []


def check(name, fn):
    t0 = time.time()
    try:
        fn()
        RESULTS.append((name, True, (time.time() - t0) * 1000, ""))
    except Exception as exc:  # noqa: BLE001
        RESULTS.append((name, False, (time.time() - t0) * 1000,
                        "%s: %s" % (type(exc).__name__, exc)))


def eq(a, b, what=""):
    if a != b:
        raise AssertionError("%s expected %r got %r" % (what, b, a))


def truthy(v, what=""):
    if not v:
        raise AssertionError("expected truthy: %s" % what)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.4)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    tmp = tempfile.mkdtemp(prefix="cw-e2e-")
    os.environ["SIDEWIRE_HOME"] = tmp
    port = free_port()
    key = P.format_key(P.gen_key(32))
    key_file = os.path.join(tmp, "agent.key")
    cfgmod.write_key_file(key_file, key)

    agent = os.path.join(ROOT, "agent", "sidewire_agentd.py")
    workdir = os.path.join(tmp, "work")
    os.makedirs(workdir, exist_ok=True)
    log = open(os.path.join(tmp, "agentd.log"), "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, agent, "--bind", "127.0.0.1", "--port", str(port),
         "--key-file", key_file, "--workdir", workdir],
        stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_port(port):
            print("agentd did not come up; log tail:")
            print(open(os.path.join(tmp, "agentd.log")).read()[-3000:])
            return 2

        cfg = cfgmod.load()
        cfgmod.add_host("local", "127.0.0.1", port, key=key, set_default=True)
        cfg = cfgmod.load()

        remote = open_remote(cfg, "local")

        # ---------------------------------------------------------- handshake
        def t_ping():
            info = remote.ping()
            truthy(info["ok"], "ping")
            eq(info["os"], "Windows" if IS_WIN else "Linux", "os")
        check("handshake + ping", t_ping)

        def t_info():
            info = remote.request("sys.info", {})
            truthy(info["hostname"], "hostname")
            truthy(info["cpu_count"] >= 1, "cpu_count")
            truthy(info["python"], "python")
        check("sys.info", t_info)

        def t_bad_key():
            bad = Remote(dict(cfg["hosts"]["local"], alias="bad"),
                         P.format_key(P.gen_key(32)))
            try:
                bad.connect()
            except RemoteError as exc:
                eq(exc.code, "auth_failed", "code")
                return
            raise AssertionError("wrong key was accepted")
        check("wrong key rejected", t_bad_key)

        # --------------------------------------------------------------- exec
        def t_echo():
            r = remote.request("exec.run", {"command": "echo hello-sidewire"})
            eq(r["exit"], 0, "exit")
            truthy("hello-sidewire" in r["stdout"], "stdout")
        check("exec.run echo", t_echo)

        def t_exit_code():
            r = remote.request("exec.run",
                               {"command": "exit 3" if IS_WIN else "exit 3"})
            eq(r["exit"], 3, "exit code")
        check("exec.run exit code", t_exit_code)

        def t_stderr():
            cmd = ("echo oops 1>&2" if IS_WIN else "echo oops >&2")
            r = remote.request("exec.run", {"command": cmd})
            truthy("oops" in r["stderr"], "stderr")
        check("exec.run stderr", t_stderr)

        def t_cwd():
            r = remote.request("exec.run",
                               {"command": "cd" if IS_WIN else "pwd", "cwd": workdir})
            truthy(workdir.replace("\\", "/").lower() in
                   r["stdout"].replace("\\", "/").lower(), "cwd honoured")
        check("exec.run cwd", t_cwd)

        def t_env():
            r = remote.request("exec.run",
                               {"command": "echo %CW_TEST%" if IS_WIN else "echo $CW_TEST",
                                "env": {"CW_TEST": "42"}})
            truthy("42" in r["stdout"], "env var")
        check("exec.run env", t_env)

        def t_script():
            script = "print(6*7)\n" if True else ""
            r = remote.request("exec.script", {"script": script, "lang": "python"})
            truthy("42" in r["stdout"], "script output")
        check("exec.script", t_script)

        def t_timeout_job():
            cmd = "ping -n 7 127.0.0.1 >nul" if IS_WIN else "sleep 6"
            r = remote.request("exec.run", {"command": cmd, "timeout": 1}, timeout=20)
            truthy(r.get("job_id"), "job_id")
            eq(r.get("state"), "running", "state")
            jid = r["job_id"]
            k = remote.request("job.kill", {"job_id": jid})
            truthy(k["killed"], "killed")
        check("long command becomes a job", t_timeout_job)

        def t_background():
            cmd = "ping -n 4 127.0.0.1 >nul" if IS_WIN else "sleep 0.4; echo done"
            r = remote.request("exec.run", {"command": cmd, "background": True})
            jid = r["job_id"]
            time.sleep(1.0)
            poll = remote.request("job.poll", {"job_id": jid})
            truthy(poll["state"] in ("exited", "running"), "state")
            if not IS_WIN:
                truthy("done" in poll["stdout"], "output")
        check("background job + poll", t_background)

        def t_job_list():
            r = remote.request("job.list", {})
            truthy(len(r["jobs"]) >= 1, "jobs listed")
        check("job.list", t_job_list)

        # ---------------------------------------------------------------- tty
        def t_tty():
            t = remote.request("tty.open", {})
            tid = t["tty_id"]
            try:
                time.sleep(0.4)
                remote.request("tty.write", {"tty_id": tid, "data": "echo tty-alive\n"})
                time.sleep(0.8)
                r = remote.request("tty.read", {"tty_id": tid, "offset": 0, "wait": 1.5})
                if not IS_WIN:
                    truthy("tty-alive" in r["data"], "tty echo: %r" % r["data"][:200])
            finally:
                remote.request("tty.close", {"tty_id": tid})
        check("tty open/write/read/close", t_tty)

        # -------------------------------------------------------------- files
        base = os.path.join(workdir, "sub dir" if not IS_WIN else "subdir")
        text_path = os.path.join(base, "hello.txt")

        def t_write_read():
            r = remote.request("fs.write", {"path": text_path,
                                            "data": "line one\nline two\nline three\n",
                                            "create_parents": True})
            eq(r["written"], 29, "bytes written")
            r = remote.request("fs.read", {"path": text_path})
            truthy("line two" in r["data"], "content")
            eq(r["truncated"], False, "truncated")
        check("fs.write + fs.read", t_write_read)

        def t_read_lines():
            r = remote.request("fs.read", {"path": text_path, "start_line": 2, "end_line": 2})
            eq(r["data"].strip(), "line two", "line slice")
        check("fs.read line slice", t_read_lines)

        def t_stat_ls():
            s = remote.request("fs.stat", {"path": text_path})
            truthy(s["size"] > 0, "size")
            l = remote.request("fs.ls", {"path": workdir, "all": True})
            names = [e["name"] for e in l["entries"]]
            truthy("subdir" in names or "sub dir" in names, "listing: %s" % names)
        check("fs.stat + fs.ls", t_stat_ls)

        def t_edit():
            r = remote.request("fs.edit", {"path": text_path,
                                           "old": "line two", "new": "LINE 2"})
            eq(r["replaced"], 1, "replaced")
            r = remote.request("fs.read", {"path": text_path})
            truthy("LINE 2" in r["data"], "edited")
        check("fs.edit", t_edit)

        def t_edit_missing():
            try:
                remote.request("fs.edit", {"path": text_path, "old": "nope", "new": "x"})
            except RemoteError as exc:
                eq(exc.code, "not_found", "code")
                return
            raise AssertionError("missing string did not raise")
        check("fs.edit missing string", t_edit_missing)

        def t_tail_hash():
            t = remote.request("fs.tail", {"path": text_path, "lines": 1})
            truthy(t["lines"], "tail")
            h = remote.request("fs.hash", {"path": text_path})
            eq(len(h["hash"]), 64, "sha256 length")
        check("fs.tail + fs.hash", t_tail_hash)

        def t_find_grep():
            f = remote.request("fs.find", {"root": workdir, "pattern": "*.txt"})
            truthy(len(f["matches"]) >= 1, "find")
            g = remote.request("fs.grep", {"root": workdir, "pattern": "LINE"})
            truthy(len(g["matches"]) >= 1, "grep")
        check("fs.find + fs.grep", t_find_grep)

        def t_manage():
            d = os.path.join(workdir, "made", "deep")
            remote.request("fs.manage", {"op": "mkdir", "path": d})
            truthy(os.path.isdir(d), "mkdir")
            src = os.path.join(workdir, "copy.txt")
            remote.request("fs.manage", {"op": "cp", "path": text_path, "dest": src})
            truthy(os.path.isfile(src), "cp")
            remote.request("fs.manage", {"op": "rm", "path": src})
            truthy(not os.path.exists(src), "rm")
            try:
                remote.request("fs.manage", {"op": "rm", "path": os.path.join(workdir, "made")})
            except RemoteError:
                pass
            else:
                raise AssertionError("rm of a directory without recursive should fail")
        check("fs.manage", t_manage)

        def t_binary_read():
            binpath = os.path.join(workdir, "blob.bin")
            with open(binpath, "wb") as fh:
                fh.write(bytes(range(256)) * 4)
            r = remote.request("fs.read", {"path": binpath})
            eq(r["encoding"], "base64", "binary detection")
        check("binary detection", t_binary_read)

        # ------------------------------------------------------------- blobs
        def t_push_pull():
            src = os.path.join(tmp, "upload.bin")
            payload = os.urandom(300 * 1024)
            with open(src, "wb") as fh:
                fh.write(payload)
            remote_path = os.path.join(workdir, "uploaded.bin")
            info = remote.push(src, remote_path)
            eq(info["size"], len(payload), "uploaded size")
            back = remote.pull(remote_path, os.path.join(tmp, "back.bin"))
            with open(back["local_path"], "rb") as fh:
                got = fh.read()
            eq(len(got), len(payload), "downloaded size")
            eq(got, payload, "payload identical")
        check("fs.push + fs.pull (300 KB)", t_push_pull)

        def t_big_output():
            cmd = ("for /l %i in (1,1,2000) do @echo line-%i" if IS_WIN
                   else "seq 1 2000")
            r = remote.request("exec.run", {"command": cmd, "max_output": 500})
            truthy(r["truncated"]["stdout"], "truncation flag")
            truthy(len(r["stdout"]) <= 500, "capped length")
        check("output truncation", t_big_output)

        # ------------------------------------------------------------ policy
        def t_denied():
            p2 = subprocess.Popen(
                [sys.executable, agent, "--bind", "127.0.0.1", "--port", str(port + 1),
                 "--key-file", key_file, "--allow-root", workdir],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                if not wait_port(port + 1):
                    raise AssertionError("second agent did not start")
                r2 = Remote(dict(cfg["hosts"]["local"], alias="strict", port=port + 1), key)
                r2.connect()
                try:
                    r2.request("fs.read", {"path": "/etc/hostname" if not IS_WIN else
                                           os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "win.ini")})
                except RemoteError as exc:
                    eq(exc.code, "denied", "code")
                else:
                    raise AssertionError("read outside allow_root was permitted")
                r2.close()
            finally:
                p2.terminate()
                p2.wait(timeout=5)
        check("allow_root enforcement", t_denied)

        # ------------------------------------------------------- concurrency
        def t_concurrent():
            import threading
            errs = []

            def worker(i):
                try:
                    r = remote.request("exec.run", {"command": "echo %d" % i})
                    if str(i) not in r["stdout"]:
                        errs.append("missing output for %d" % i)
                except Exception as exc:  # noqa: BLE001
                    errs.append(str(exc))

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(20)
            if errs:
                raise AssertionError("; ".join(errs[:3]))
        check("12 concurrent requests", t_concurrent)

        # --------------------------------------------------------- reconnect
        def t_reconnect():
            r3 = open_remote(cfg, "local")
            r3.sock.close()          # simulate a dropped link
            time.sleep(0.3)
            r3._closed = True
            info = r3.ping(timeout=5)   # should dial again transparently
            truthy(info["ok"], "reconnected")
            r3.close()
        check("transparent reconnect", t_reconnect)

        remote.close()

    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        log.close()

    # ------------------------------------------------------------- report
    print()
    width = max(len(r[0]) for r in RESULTS) + 2
    failed = 0
    for name, okflag, ms, err in RESULTS:
        mark = "PASS" if okflag else "FAIL"
        print("%-6s %-*s %6.0fms %s" % (mark, width, name, ms, err))
        if not okflag:
            failed += 1
    print("\n%d/%d passed" % (len(RESULTS) - failed, len(RESULTS)))
    if failed:
        print("\nagentd log tail:")
        print(open(os.path.join(tmp, "agentd.log"), encoding="utf-8", errors="replace").read()[-2000:])
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
