#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sidewire_agentd — SideWire agent daemon (runs on the machine you want to control)

Single file, Python 3.8+, standard library only.  Copy it to the target box,
generate a key, start it, done.  No pip install, no Node, no SSH daemon.

    # on the target
    python3 sidewire_agentd.py --keygen --key-file /etc/sidewire/agent.key
    python3 sidewire_agentd.py --key-file /etc/sidewire/agent.key --port 7900

It speaks the SideWire binary protocol (see docs/PROTOCOL.md): 16-byte frame
headers, multiplexed streams, one TCP connection, no server-side session state.
System facts are read straight out of /proc and /sys instead of shelling out to
ps/ss/netstat, so a bare container with no procps still works.
"""

import argparse
import errno
import fnmatch
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import stat as statmod
import struct
import subprocess
import sys
import threading
import time
import traceback
import zlib

# ===========================================================================
# 1. protocol (byte-compatible with sidewire/protocol.py — verified by tests)
# ===========================================================================

MAGIC = b"CWP1"
VERSION = 1
HEADER = struct.Struct("!4sBBHII")
HEADER_SIZE = 16
MAX_PAYLOAD = 1 << 20
BLOB_CHUNK = 64 * 1024

T_HELLO, T_CHALLENGE, T_AUTH, T_AUTH_OK, T_AUTH_FAIL = 0x01, 0x02, 0x03, 0x04, 0x05
T_REQ, T_RES, T_EVT, T_CANCEL = 0x10, 0x11, 0x12, 0x13
T_PING, T_PONG = 0x20, 0x21
T_BLOB, T_BYE = 0x30, 0x40

F_SEALED, F_FIN, F_ERR = 0x01, 0x02, 0x04

IS_WIN = os.name == "nt"
IS_POSIX = not IS_WIN


class ProtocolError(Exception):
    pass


class AuthError(Exception):
    pass


class Denied(Exception):
    pass


class NotFound(Exception):
    pass


def encode_frame(ftype, stream=0, payload=b"", flags=0):
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError("payload too large")
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return HEADER.pack(MAGIC, ftype, flags, stream, len(payload), crc) + payload


def pack_json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def unpack_json(payload):
    return json.loads(payload.decode("utf-8"))


def recv_exact(sock, n):
    chunks, remaining = [], n
    while remaining:
        try:
            buf = sock.recv(remaining)
        except OSError:
            raise EOFError("reset")
        if not buf:
            raise EOFError("closed")
        chunks.append(buf)
        remaining -= len(buf)
    return b"".join(chunks)


def unpack_header(head):
    """-> (ftype, flags, stream, length, crc); raises on a bad header."""
    magic, ftype, flags, stream, length, crc = struct.unpack("!4sBBHII", head)
    if magic != MAGIC:
        raise ProtocolError("bad magic %r" % (magic,))
    if length > MAX_PAYLOAD:
        raise ProtocolError("frame too large: %d" % length)
    return ftype, flags, stream, length, crc


class Writer(object):
    def __init__(self, sock):
        self.sock = sock
        self._lock = threading.Lock()

    def write(self, ftype, stream=0, payload=b"", flags=0):
        data = encode_frame(ftype, stream, payload, flags)
        with self._lock:
            self.sock.sendall(data)

    def write_json(self, ftype, stream=0, obj=None, flags=0):
        self.write(ftype, stream, pack_json(obj if obj is not None else {}), flags)


def _hmac(key, *parts):
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


class Sealer(object):
    TAG = 8

    def __init__(self, key):
        self.key = key
        self.counter = 0
        self.lock = threading.Lock()

    def _keystream(self, ctr, length):
        out, block = bytearray(), 0
        while len(out) < length:
            out += _hmac(self.key, b"K", ctr.to_bytes(8, "big"), block.to_bytes(4, "big"))
            block += 1
        return bytes(out[:length])

    def seal(self, plaintext):
        with self.lock:
            self.counter += 1
            ctr = self.counter
        ks = self._keystream(ctr, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, ks)) if plaintext else b""
        return ct + _hmac(self.key, b"T", ctr.to_bytes(8, "big"), ct)[:self.TAG]

    def open(self, sealed):
        if len(sealed) < self.TAG:
            raise ProtocolError("short sealed payload")
        ct, tag = sealed[:-self.TAG], sealed[-self.TAG:]
        with self.lock:
            self.counter += 1
            ctr = self.counter
        if not hmac.compare_digest(tag, _hmac(self.key, b"T", ctr.to_bytes(8, "big"), ct)[:self.TAG]):
            raise ProtocolError("bad frame tag")
        ks = self._keystream(ctr, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks)) if ct else b""


def client_proof(key, nc, ns):
    return _hmac(key, b"CWP1/AUTH/c", nc, ns)


def server_proof(key, nc, ns):
    return _hmac(key, b"CWP1/AUTH/s", ns, nc)


def session_key(key, nc, ns):
    return _hmac(key, b"CWP1/SESSION", nc, ns)


def parse_key(text):
    """Accept bare hex or a short-prefixed hex key.

    Any prefix is tolerated, not just `sw1_`. Older installs carry a key
    labelled with the project's previous name and there is no reason to make
    them regenerate it. Must stay identical to the client's version; the
    byte-for-byte test in tests/test_protocol.py enforces that.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii", "ignore")
    text = (text or "").strip()
    head, sep, tail = text.partition("_")
    if sep and len(head) <= 8 and tail and all(c in "0123456789abcdefABCDEF" for c in tail):
        text = tail
    text = text.replace("-", "").replace(" ", "")
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise AuthError("key is not valid hex")
    if len(raw) < 16:
        raise AuthError("key too short")
    return raw


# ===========================================================================
# 2. logging
# ===========================================================================

_log_lock = threading.Lock()
_log_path = None
_verbose = False


def set_log(path, verbose=False):
    global _log_path, _verbose
    _log_path = path
    _verbose = verbose


def log(msg, level="info"):
    line = "%s [%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level, msg)
    with _log_lock:
        if _verbose or level != "debug":
            try:
                sys.stderr.write(line + "\n")
                sys.stderr.flush()
            except Exception:
                pass
        if _log_path:
            try:
                with open(_log_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except Exception:
                pass


# ===========================================================================
# 3. path policy
# ===========================================================================

class Policy(object):
    def __init__(self, allow_roots=None, deny_roots=None,
                 allow_sudo=False, allow_power=False, allow_pkg=False,
                 allow_proc_kill=True, max_read_bytes=8 << 20,
                 max_write_bytes=256 << 20):
        self.allow_roots = [os.path.realpath(p) for p in (allow_roots or ["/"])]
        self.deny_roots = [os.path.realpath(p) for p in (deny_roots or [])]
        self.allow_sudo = allow_sudo
        self.allow_power = allow_power
        self.allow_pkg = allow_pkg
        self.allow_proc_kill = allow_proc_kill
        self.max_read_bytes = max_read_bytes
        self.max_write_bytes = max_write_bytes

    def check(self, path, must_exist=False):
        if not path:
            raise Denied("empty path")
        raw = os.path.expanduser(str(path))
        if not os.path.isabs(raw):
            raw = os.path.join(WORKDIR, raw)
        real = os.path.realpath(raw)
        for deny in self.deny_roots:
            if real == deny or real.startswith(deny + os.sep):
                raise Denied("path denied by policy: %s" % real)
        for root in self.allow_roots:
            if root == os.sep:
                return real
            if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
                return real
        raise Denied("path outside allowed roots: %s" % real)


WORKDIR = os.path.expanduser("~")


# ===========================================================================
# 4. /proc + /sys introspection (Linux); graceful fallbacks elsewhere
# ===========================================================================

_CLK_TCK = 100
try:
    _CLK_TCK = os.sysconf("SC_CLK_TCK") or 100
except Exception:
    pass

_PAGE = 4096
try:
    _PAGE = os.sysconf("SC_PAGE_SIZE") or 4096
except Exception:
    pass


def _read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return default


def _read_bytes(path, limit=65536):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except Exception:
        return b""


def mem_total_bytes():
    for line in _read("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return 0


def mem_available_bytes():
    for line in _read("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return 0


def uptime_seconds():
    try:
        return float(_read("/proc/uptime").split()[0])
    except Exception:
        return 0.0


def load_avg():
    parts = _read("/proc/loadavg").split()
    try:
        return [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        return []


def cpu_count():
    try:
        return len(os.sched_getaffinity(0))
    except Exception:
        return os.cpu_count() or 1


def cpu_model():
    for line in _read("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return ""


def os_release():
    info = {}
    for line in _read("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k] = v.strip().strip('"')
    return info


def _parse_stat(pid):
    """Parse /proc/<pid>/stat robustly (comm may contain spaces/parens)."""
    raw = _read("/proc/%s/stat" % pid)
    if not raw:
        return None
    lpar, rpar = raw.find("("), raw.rfind(")")
    if lpar < 0 or rpar < 0:
        return None
    comm = raw[lpar + 1:rpar]
    rest = raw[rpar + 2:].split()
    try:
        return {
            "pid": int(pid),
            "comm": comm,
            "state": rest[0],
            "ppid": int(rest[1]),
            "utime": int(rest[11]) / _CLK_TCK,
            "stime": int(rest[12]) / _CLK_TCK,
            "threads": int(rest[17]),
            "starttime": int(rest[19]) / _CLK_TCK,
            "vsize": int(rest[20]),
            "rss": int(rest[21]) * _PAGE,
        }
    except (IndexError, ValueError):
        return None


def _proc_owner(pid):
    st = None
    try:
        st = os.stat("/proc/%s" % pid)
    except Exception:
        return ""
    uid = st.st_uid
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


_cpu_snapshot = {"t": 0.0, "total": 0.0, "per": {}}
_cpu_lock = threading.Lock()


def proc_list(filt=None, sort="cpu", limit=40, with_cmdline=True):
    """Enumerate processes from /proc. Falls back to ps(1) off Linux."""
    if not os.path.isdir("/proc"):
        return _proc_list_ps(filt, sort, limit)

    now = time.time()
    with _cpu_lock:
        prev_t, prev_total, prev_per = _cpu_snapshot["t"], _cpu_snapshot["total"], _cpu_snapshot["per"]

    pids = [d for d in os.listdir("/proc") if d.isdigit()]
    rows, total_cpu = [], 0.0
    for pid in pids:
        st = _parse_stat(pid)
        if not st:
            continue
        cpu_total = st["utime"] + st["stime"]
        total_cpu += cpu_total
        st["cpu_time"] = round(cpu_total, 2)
        prev = prev_per.get(pid)
        if prev is not None and now > prev_t:
            st["cpu"] = round(max(0.0, (cpu_total - prev) / (now - prev_t) * 100.0), 1)
        else:
            st["cpu"] = 0.0
        st["_raw"] = cpu_total
        st["user"] = _proc_owner(pid)
        st["rss_mb"] = round(st["rss"] / 1048576.0, 1)
        st["elapsed"] = round(max(0.0, uptime_seconds() - st["starttime"]), 1)
        st["cmdline"] = ""
        if with_cmdline:
            cl = _read_bytes("/proc/%s/cmdline" % pid, 4096)
            st["cmdline"] = cl.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        st["name"] = st["comm"]
        if filt and filt.lower() not in (st["name"] + " " + st["cmdline"]).lower():
            continue
        rows.append(st)

    with _cpu_lock:
        _cpu_snapshot["t"] = now
        _cpu_snapshot["total"] = total_cpu
        _cpu_snapshot["per"] = {r["pid"]: r["_raw"] for r in rows}

    key = {"cpu": lambda r: r.get("cpu", 0), "mem": lambda r: r["rss"],
           "pid": lambda r: r["pid"], "time": lambda r: r.get("elapsed", 0)}.get(sort, lambda r: r["pid"])
    rows.sort(key=key, reverse=(sort in ("cpu", "mem", "time")))
    out = []
    for r in rows[:max(1, int(limit))]:
        r = dict(r)
        r.pop("_raw", None)
        r.pop("starttime", None)
        out.append(r)
    return out


def _proc_list_ps(filt, sort, limit):
    ps_sort = {"cpu": "-pcpu", "mem": "-pmem", "pid": "pid", "time": "etime"}.get(sort, "pid")
    argv = ["ps", "-eo", "pid=,ppid=,user=,pcpu=,pmem=,rss=,stat=,etime=,comm=,args=", "--sort=" + ps_sort]
    try:
        res = run_capture(argv, timeout=10)
    except Exception:
        return []
    rows = []
    for line in res["stdout"].splitlines()[1:]:
        parts = line.split(None, 9)
        if len(parts) < 10:
            continue
        if filt and filt.lower() not in line.lower():
            continue
        rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "user": parts[2],
                     "cpu": float(parts[3]), "mem": float(parts[4]),
                     "rss": int(parts[5]) * 1024, "state": parts[6],
                     "elapsed": parts[7], "name": parts[8], "cmdline": parts[9]})
    return rows[:max(1, int(limit))]


def iface_list():
    """IPv4/IPv6 addresses without shelling out."""
    out = []
    if os.path.isdir("/sys/class/net"):
        for name in sorted(os.listdir("/sys/class/net")):
            entry = {"name": name, "mac": _read("/sys/class/net/%s/address" % name).strip(),
                     "state": _read("/sys/class/net/%s/operstate" % name).strip(),
                     "mtu": _read("/sys/class/net/%s/mtu" % name).strip(),
                     "ipv4": [], "ipv6": []}
            out.append(entry)
        by_name = {e["name"]: e for e in out}
        try:
            import fcntl
            for name in list(by_name):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    packed = fcntl.ioctl(sock.fileno(), 0x8915,
                                         struct.pack("256s", name.encode()[:15]))
                    by_name[name]["ipv4"].append(socket.inet_ntoa(packed[20:24]))
                except Exception:
                    pass
                finally:
                    sock.close()
        except Exception:
            pass
        for line in _read("/proc/net/if_inet6").splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            raw, name = parts[0], parts[5]
            addr = ":".join(raw[i:i + 4] for i in range(0, 32, 4))
            try:
                addr = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(raw))
            except Exception:
                pass
            if name in by_name:
                by_name[name]["ipv6"].append(addr)
        return out
    # fallback
    try:
        for line in run_capture(["ip", "-o", "addr"], timeout=5)["stdout"].splitlines():
            parts = line.split()
            if len(parts) >= 4:
                out.append({"name": parts[1], "ipv4": [parts[3].split("/")[0]] if ":" not in parts[2] else [],
                            "ipv6": [parts[3].split("/")[0]] if ":" in parts[2] else [], "mac": "", "state": ""})
    except Exception:
        pass
    return out


def _hex_ip4(h):
    try:
        return socket.inet_ntoa(struct.pack("<I", int(h, 16)))
    except Exception:
        return h


def _hex_ip6(h):
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes.fromhex(h))
    except Exception:
        return h


def _parse_proc_net(path, proto, v6=False):
    rows = []
    for line in _read(path).splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, remote, st = parts[1], parts[2], parts[3]
        try:
            lip, lport = local.split(":")
            rip, rport = remote.split(":")
        except ValueError:
            continue
        rows.append({
            "proto": proto,
            "local": ("[%s]" % _hex_ip6(lip) if v6 else _hex_ip4(lip)) + ":" + str(int(lport, 16)),
            "remote": ("[%s]" % _hex_ip6(rip) if v6 else _hex_ip4(rip)) + ":" + str(int(rport, 16)),
            "state": {"01": "ESTABLISHED", "02": "SYN_SENT", "06": "TIME_WAIT",
                      "0A": "LISTEN", "07": "CLOSE"}.get(st, st),
            "inode": parts[9],
            "uid": parts[7] if len(parts) > 7 else "",
        })
    return rows


def _inode_to_pid():
    mapping = {}
    for pid in os.listdir("/proc") if os.path.isdir("/proc") else []:
        if not pid.isdigit():
            continue
        fddir = "/proc/%s/fd" % pid
        try:
            for fd in os.listdir(fddir):
                try:
                    target = os.readlink(os.path.join(fddir, fd))
                except OSError:
                    continue
                if target.startswith("socket:["):
                    mapping[target[8:-1]] = int(pid)
        except OSError:
            continue
    return mapping


def socket_list(states=None, with_pid=False, limit=200):
    if not os.path.isdir("/proc/net"):
        return _socket_list_ss(states, limit)
    rows = []
    rows += _parse_proc_net("/proc/net/tcp", "tcp")
    rows += _parse_proc_net("/proc/net/tcp6", "tcp6", v6=True)
    rows += _parse_proc_net("/proc/net/udp", "udp")
    rows += _parse_proc_net("/proc/net/udp6", "udp6", v6=True)
    if states:
        wanted = {s.upper() for s in states}
        rows = [r for r in rows if r["state"].upper() in wanted]
    rows = [r for r in rows if r["state"] != "LISTEN" or True]
    if with_pid:
        m = _inode_to_pid()
        for r in rows:
            r["pid"] = m.get(r["inode"])
    rows.sort(key=lambda r: (r["state"] != "LISTEN", r["local"]))
    return rows[:max(1, int(limit))]


def _socket_list_ss(states, limit):
    try:
        out = run_capture(["ss", "-tunap"], timeout=5)["stdout"]
    except Exception:
        return []
    return [{"raw": line} for line in out.splitlines()[1:limit + 1]]


# ===========================================================================
# 5. command execution
# ===========================================================================

def _default_shell():
    if IS_WIN:
        return ["cmd.exe", "/c"]
    for cand in ("/bin/bash", "/usr/bin/bash", "/bin/sh"):
        if os.path.exists(cand):
            return [cand, "-lc"]
    return ["/bin/sh", "-c"]


def build_argv(params):
    """Turn (command | argv | shell) into an argv list."""
    if params.get("argv"):
        return [str(x) for x in params["argv"]], True
    cmd = params.get("command")
    if cmd is None:
        raise ValueError("either 'command' or 'argv' is required")
    shell = params.get("shell")
    if shell:
        parts = shell.split()
        if len(parts) == 1:
            parts += ["-lc"] if not IS_WIN else ["/c"]
        return parts + [cmd], True
    return _default_shell() + [cmd], True


def _sudo_prefix(params):
    """Return (argv_prefix, stdin_prefix_bytes)."""
    if not params.get("sudo"):
        return [], b""
    pw = params.get("sudo_password") or SUDO_PASSWORD
    if pw:
        return ["sudo", "-S", "-p", ""], (pw + "\n").encode()
    return ["sudo", "-n"], b""


def run_capture(argv, cwd=None, env=None, timeout=60, stdin_data=b"", input_bytes=None):
    proc = subprocess.Popen(argv, cwd=cwd, env=env,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            start_new_session=IS_POSIX)
    try:
        out, err = proc.communicate(input=input_bytes if input_bytes is not None else stdin_data,
                                    timeout=timeout)
        return {"exit": proc.returncode,
                "stdout": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace")}
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        out, err = proc.communicate()
        return {"exit": -1, "timed_out": True,
                "stdout": out.decode("utf-8", "replace"),
                "stderr": err.decode("utf-8", "replace")}


def _kill_tree(proc, sig=signal.SIGTERM if IS_POSIX else None):
    try:
        if IS_POSIX:
            os.killpg(os.getpgid(proc.pid), sig or signal.SIGTERM)
        else:
            proc.terminate()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ===========================================================================
# 6. ring buffer + jobs
# ===========================================================================

class Ring(object):
    """Append-only byte ring keeping a bounded tail, addressable by absolute offset."""

    def __init__(self, cap=1 << 20):
        self.cap = cap
        self.buf = bytearray()
        self.start = 0
        self.end = 0
        self.lock = threading.Lock()

    def append(self, data):
        if not data:
            return
        with self.lock:
            self.buf += data
            self.end += len(data)
            over = len(self.buf) - self.cap
            if over > 0:
                del self.buf[:over]
                self.start += over

    def read(self, offset=0):
        with self.lock:
            offset = max(0, int(offset))
            gap = 0
            if offset < self.start:
                gap = self.start - offset
                offset = self.start
            if offset > self.end:
                offset = self.end
            return bytes(self.buf[offset - self.start:]), self.end, gap


class Job(object):
    _seq = 0
    _lock = threading.Lock()

    def __init__(self, argv, cwd=None, env=None, label=None):
        with Job._lock:
            Job._seq += 1
            self.id = "j%d" % Job._seq
        self.argv = argv
        self.label = label or " ".join(argv)[:200]
        self.cwd = cwd
        self.started = time.time()
        self.ended = None
        self.exit = None
        self.error = None
        self.out = Ring()
        self.err = Ring()
        self.proc = None
        self._closed = threading.Event()
        try:
            self.proc = subprocess.Popen(argv, cwd=cwd, env=env,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         start_new_session=IS_POSIX)
        except Exception as exc:
            self.error = "%s: %s" % (type(exc).__name__, exc)
            self.exit = -2
            self.ended = time.time()
            self._closed.set()
            return
        self._threads = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, self.out), daemon=True),
            threading.Thread(target=self._pump, args=(self.proc.stderr, self.err), daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _pump(self, stream, ring):
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                ring.append(chunk)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def write_stdin(self, data):
        if not self.proc or self.proc.stdin is None:
            return 0
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
            return len(data)
        except Exception:
            return 0

    def wait(self, timeout):
        if self._closed.is_set():
            return True
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        self.exit = self.proc.returncode
        self.ended = time.time()
        self._closed.set()
        return True

    def kill(self, sig=None):
        if not self.proc or self._closed.is_set():
            return False
        try:
            if IS_POSIX:
                os.killpg(os.getpgid(self.proc.pid), sig or signal.SIGTERM)
            else:
                self.proc.terminate()
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                return False
        try:
            self.proc.wait(timeout=3)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.exit = self.proc.returncode
        self.ended = time.time()
        self._closed.set()
        return True

    def state(self):
        if not self._closed.is_set() and self.proc is not None:
            if self.proc.poll() is not None:
                self.exit = self.proc.returncode
                self.ended = time.time()
                self._closed.set()
        return "exited" if self._closed.is_set() else "running"

    def summary(self):
        return {"id": self.id, "label": self.label, "argv": self.argv,
                "cwd": self.cwd, "state": self.state(), "exit": self.exit,
                "error": self.error,
                "started": round(self.started, 3),
                "ended": round(self.ended, 3) if self.ended else None,
                "duration": round((self.ended or time.time()) - self.started, 2),
                "pid": self.proc.pid if self.proc else None}


JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_KEEP = 300


def _gc_jobs():
    now = time.time()
    with JOBS_LOCK:
        for jid, job in list(JOBS.items()):
            if job.ended and now - job.ended > JOB_KEEP:
                JOBS.pop(jid, None)


# ===========================================================================
# 7. interactive TTY
# ===========================================================================

class Tty(object):
    _seq = 0
    _lock = threading.Lock()

    def __init__(self, shell=None, cwd=None, env=None, cols=120, rows=40):
        with Tty._lock:
            Tty._seq += 1
            self.id = "t%d" % Tty._seq
        self.ring = Ring(1 << 20)
        self.alive = True
        self.started = time.time()
        self.pid = None
        self.master = None
        self._closed = threading.Event()
        self.shell = shell or (["cmd.exe"] if IS_WIN else ["/bin/bash", "-l"])
        self._spawn(cwd, env, cols, rows)

    def _spawn(self, cwd, env, cols, rows):
        if IS_POSIX:
            import pty
            self.master, slave = pty.openpty()
            try:
                import fcntl
                import termios
                fcntl.ioctl(self.master, termios.TIOCSWINSZ,
                            struct.pack("HHHH", int(rows), int(cols), 0, 0))
            except Exception:
                pass
            self.proc = subprocess.Popen(self.shell, cwd=cwd, env=env,
                                         stdin=slave, stdout=slave, stderr=slave,
                                         preexec_fn=os.setsid, close_fds=True)
            os.close(slave)
            self.pid = self.proc.pid
            os.set_blocking(self.master, False)
            self._threads = [threading.Thread(target=self._pump_pty, daemon=True)]
        else:
            self.proc = subprocess.Popen(self.shell, cwd=cwd, env=env,
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT,
                                         creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            self.pid = self.proc.pid
            self._threads = [threading.Thread(target=self._pump_pipe, daemon=True)]
        for t in self._threads:
            t.start()

    def _pump_pty(self):
        while not self._closed.is_set():
            try:
                chunk = os.read(self.master, 65536)
            except BlockingIOError:
                time.sleep(0.02)
                continue
            except OSError:
                break
            if not chunk:
                break
            self.ring.append(chunk)
        self.alive = False
        self._closed.set()

    def _pump_pipe(self):
        try:
            while True:
                chunk = self.proc.stdout.read(1)
                if not chunk:
                    break
                self.ring.append(chunk)
        except Exception:
            pass
        self.alive = False
        self._closed.set()

    def write(self, data, raw=False):
        if not self.alive:
            raise NotFound("tty %s is closed" % self.id)
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not raw and IS_POSIX:
            data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r")
        try:
            if IS_POSIX:
                os.write(self.master, data)
            else:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
        except OSError as exc:
            raise NotFound("tty write failed: %s" % exc)
        return len(data)

    def read(self, offset=0, wait=0.0, until=None):
        deadline = time.time() + max(0.0, float(wait))
        data, end, gap = self.ring.read(offset)
        while not data and time.time() < deadline and self.alive:
            time.sleep(0.03)
            data, end, gap = self.ring.read(offset)
        if data and until:
            # wait a little longer for the pattern to show up
            while time.time() < deadline and until.encode() not in self.ring.read(0)[0]:
                time.sleep(0.03)
            data, end, gap = self.ring.read(offset)
        return data, end, gap

    def close(self):
        self._closed.set()
        try:
            if IS_POSIX and self.master is not None:
                os.close(self.master)
        except Exception:
            pass
        try:
            _kill_tree(self.proc)
        except Exception:
            pass
        self.alive = False
        return True


TTYS = {}
TTYS_LOCK = threading.Lock()


# ===========================================================================
# 8. service / package managers
# ===========================================================================

def init_system():
    if IS_WIN:
        return "windows"
    if os.path.isdir("/run/systemd/system"):
        return "systemd"
    if shutil.which("rc-service"):
        return "openrc"
    if shutil.which("service"):
        return "sysvinit"
    return "unknown"


def pkg_manager():
    if IS_WIN:
        return "winget" if shutil.which("winget") else "unknown"
    for mgr, probe in (("apt", "apt-get"), ("dnf", "dnf"), ("yum", "yum"),
                       ("pacman", "pacman"), ("zypper", "zypper"), ("apk", "apk")):
        if shutil.which(probe):
            return mgr
    return "unknown"


PKG_CMDS = {
    "apt": {"install": "apt-get install -y {p}", "remove": "apt-get remove -y {p}",
            "update": "apt-get update", "upgrade": "apt-get upgrade -y",
            "search": "apt-cache search {p}", "info": "apt-cache show {p}",
            "list": "apt list --installed 2>/dev/null"},
    "dnf": {"install": "dnf install -y {p}", "remove": "dnf remove -y {p}",
            "update": "dnf check-update", "upgrade": "dnf upgrade -y",
            "search": "dnf search {p}", "info": "dnf info {p}", "list": "dnf list installed"},
    "yum": {"install": "yum install -y {p}", "remove": "yum remove -y {p}",
            "update": "yum check-update", "upgrade": "yum update -y",
            "search": "yum search {p}", "info": "yum info {p}", "list": "yum list installed"},
    "pacman": {"install": "pacman -S --noconfirm {p}", "remove": "pacman -R --noconfirm {p}",
               "update": "pacman -Sy", "upgrade": "pacman -Su --noconfirm",
               "search": "pacman -Ss {p}", "info": "pacman -Si {p}", "list": "pacman -Q"},
    "zypper": {"install": "zypper -n install {p}", "remove": "zypper -n remove {p}",
               "update": "zypper refresh", "upgrade": "zypper -n update",
               "search": "zypper search {p}", "info": "zypper info {p}", "list": "zypper se -i"},
    "apk": {"install": "apk add {p}", "remove": "apk del {p}", "update": "apk update",
            "upgrade": "apk upgrade", "search": "apk search {p}", "info": "apk info {p}",
            "list": "apk info"},
    "winget": {"install": "winget install --accept-package-agreements {p}",
               "remove": "winget uninstall {p}", "update": "winget upgrade",
               "upgrade": "winget upgrade --all", "search": "winget search {p}",
               "info": "winget show {p}", "list": "winget list"},
}


# ===========================================================================
# 9. request handlers
# ===========================================================================

SUDO_PASSWORD = None
POLICY = Policy()
SERVER_STARTED = time.time()
CONFIG = {}


def _ok(**kw):
    return kw


def h_sys_ping(conn, p):
    return {"pong": True, "t": round(time.time(), 3),
            "uptime": round(time.time() - SERVER_STARTED, 1)}


def h_sys_info(conn, p):
    rel = os_release()
    total, avail = mem_total_bytes(), mem_available_bytes()
    du = shutil.disk_usage("/")
    ifaces = iface_list()
    try:
        user = os.getlogin()
    except Exception:
        try:
            import pwd
            user = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
    return {
        "hostname": socket.gethostname(),
        "os": ("Windows" if IS_WIN else (rel.get("PRETTY_NAME") or rel.get("NAME") or "Linux")),
        "kernel": (" ".join(os.uname()) if hasattr(os, "uname") else sys.platform),
        "arch": os.uname().machine if hasattr(os, "uname") else os.environ.get("PROCESSOR_ARCHITECTURE", ""),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "user": user,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "is_root": (os.geteuid() == 0) if hasattr(os, "geteuid") else False,
        "cwd": WORKDIR,
        "home": os.path.expanduser("~"),
        "cpu_count": cpu_count(),
        "cpu_model": cpu_model(),
        "loadavg": load_avg(),
        "mem_total_mb": round(total / 1048576.0, 1),
        "mem_available_mb": round(avail / 1048576.0, 1),
        "disk_total_gb": round(du.total / 1073741824.0, 1),
        "disk_free_gb": round(du.free / 1073741824.0, 1),
        "uptime_s": round(uptime_seconds(), 0),
        "init": init_system(),
        "pkg_manager": pkg_manager(),
        "shell": _default_shell()[0],
        "sudo_nopasswd": _has_nopasswd_sudo(),
        "allow_sudo": POLICY.allow_sudo,
        "allow_power": POLICY.allow_power,
        "allow_pkg": POLICY.allow_pkg,
        "ipv4": [ip for i in ifaces for ip in i.get("ipv4", [])],
        "interfaces": ifaces,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "agent_version": CONFIG.get("version", "1.0.0"),
        "boot": round(time.time() - uptime_seconds(), 0),
    }


def _has_nopasswd_sudo():
    if IS_WIN or not shutil.which("sudo"):
        return False
    try:
        r = run_capture(["sudo", "-n", "true"], timeout=5)
        return r["exit"] == 0
    except Exception:
        return False


def h_exec_run(conn, p):
    argv, _ = build_argv(p)
    prefix, pw = _sudo_prefix(p)
    if prefix and not POLICY.allow_sudo and not _has_nopasswd_sudo():
        raise Denied("sudo is disabled by the agent policy (start agentd with --allow-sudo)")
    argv = prefix + argv
    cwd = POLICY.check(p["cwd"]) if p.get("cwd") else WORKDIR
    if not os.path.isdir(cwd):
        raise NotFound("cwd does not exist: %s" % cwd)
    env = os.environ.copy()
    if p.get("env"):
        env.update({str(k): str(v) for k, v in p["env"].items()})
    if p.get("clean_env"):
        env = {k: env[k] for k in ("PATH", "HOME", "LANG", "TERM", "USER") if k in env}

    job = Job(argv, cwd=cwd, env=env, label=p.get("label") or " ".join(argv)[:200])
    if pw:
        job.write_stdin(pw)
    if p.get("stdin"):
        job.write_stdin(p["stdin"].encode("utf-8") if isinstance(p["stdin"], str) else p["stdin"])

    timeout = float(p.get("timeout") or 60)
    if p.get("background"):
        _register_job(job)
        return {"job_id": job.id, "state": "running", "pid": job.proc.pid if job.proc else None}

    finished = job.wait(timeout)
    if not finished:
        _register_job(job)
        return {"job_id": job.id, "state": "running", "timed_out": True,
                "pid": job.proc.pid if job.proc else None,
                "note": "still running after %ss; poll with job_poll" % timeout}

    out, _, gap_o = job.out.read(0)
    err, _, gap_e = job.err.read(0)
    limit = int(p.get("max_output") or 200000)
    return {
        "job_id": job.id,
        "exit": job.exit,
        "state": "exited",
        "stdout": out.decode("utf-8", "replace")[:limit],
        "stderr": err.decode("utf-8", "replace")[:limit],
        "stdout_bytes": len(out),
        "stderr_bytes": len(err),
        "truncated": {"stdout": len(out) > limit, "stderr": len(err) > limit},
        "lost": {"stdout": gap_o, "stderr": gap_e},
        "duration_ms": int((job.ended - job.started) * 1000),
        "cwd": cwd,
        "argv": argv,
    }


def h_exec_script(conn, p):
    """Write a script to a temp file and run it — avoids all quoting hell."""
    lang = (p.get("lang") or "bash").lower()
    body = p.get("script") or ""
    if not body:
        raise ValueError("script is required")
    ext = {"bash": ".sh", "sh": ".sh", "python": ".py", "python3": ".py",
           "perl": ".pl", "node": ".js", "powershell": ".ps1", "pwsh": ".ps1"}.get(lang, ".sh")
    tmpdir = p.get("dir") or os.path.join("/tmp" if IS_POSIX else os.environ.get("TEMP", "."))
    path = os.path.join(tmpdir, "cw_script_%d_%d%s" % (os.getpid(), int(time.time() * 1000) % 1000000, ext))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    os.chmod(path, 0o700)
    runner = {"bash": "/bin/bash", "sh": "/bin/sh", "python": sys.executable,
              "python3": sys.executable, "perl": "perl", "node": "node",
              "powershell": "powershell", "pwsh": "pwsh"}.get(lang, "/bin/bash")
    sub = dict(p)
    sub.pop("script", None)
    sub["argv"] = [runner, path]
    sub.pop("command", None)
    try:
        result = h_exec_run(conn, sub)
    finally:
        if not p.get("keep"):
            try:
                os.unlink(path)
            except Exception:
                pass
    result["script_path"] = path
    return result


def _register_job(job):
    with JOBS_LOCK:
        JOBS[job.id] = job
    _gc_jobs()


def h_job_list(conn, p):
    _gc_jobs()
    with JOBS_LOCK:
        jobs = [j.summary() for j in JOBS.values()]
    jobs.sort(key=lambda j: j["started"], reverse=True)
    return {"jobs": jobs[:int(p.get("limit") or 50)]}


def h_job_poll(conn, p):
    jid = p.get("job_id")
    with JOBS_LOCK:
        job = JOBS.get(jid)
    if not job:
        raise NotFound("no such job: %s" % jid)
    if p.get("wait"):
        job.wait(float(p["wait"]))
    out, out_end, gap_o = job.out.read(int(p.get("stdout_offset") or 0))
    err, err_end, gap_e = job.err.read(int(p.get("stderr_offset") or 0))
    limit = int(p.get("max_output") or 200000)
    return {
        "job_id": job.id, "state": job.state(), "exit": job.exit,
        "stdout": out.decode("utf-8", "replace")[:limit],
        "stderr": err.decode("utf-8", "replace")[:limit],
        "stdout_offset": out_end, "stderr_offset": err_end,
        "lost": {"stdout": gap_o, "stderr": gap_e},
        "truncated": {"stdout": len(out) > limit, "stderr": len(err) > limit},
        "duration": round((job.ended or time.time()) - job.started, 2),
    }


def h_job_kill(conn, p):
    jid = p.get("job_id")
    with JOBS_LOCK:
        job = JOBS.get(jid)
    if not job:
        raise NotFound("no such job: %s" % jid)
    sig = int(p.get("signal") or (signal.SIGTERM if IS_POSIX else 15))
    ok = job.kill(sig)
    return {"job_id": jid, "killed": ok, "state": job.state(), "exit": job.exit}


def h_job_input(conn, p):
    jid = p.get("job_id")
    with JOBS_LOCK:
        job = JOBS.get(jid)
    if not job:
        raise NotFound("no such job: %s" % jid)
    n = job.write_stdin((p.get("data") or "").encode("utf-8"))
    return {"job_id": jid, "written": n}


def h_tty_open(conn, p):
    shell = p.get("shell")
    argv = shell.split() if isinstance(shell, str) and shell else None
    tty = Tty(shell=argv, cwd=(POLICY.check(p["cwd"]) if p.get("cwd") else WORKDIR),
              cols=p.get("cols") or 120, rows=p.get("rows") or 40)
    with TTYS_LOCK:
        TTYS[tty.id] = tty
    return {"tty_id": tty.id, "pid": tty.pid, "shell": tty.shell}


def h_tty_write(conn, p):
    tid = p.get("tty_id")
    with TTYS_LOCK:
        tty = TTYS.get(tid)
    if not tty:
        raise NotFound("no such tty: %s" % tid)
    n = tty.write(p.get("data") or "", raw=bool(p.get("raw")))
    return {"tty_id": tid, "written": n}


def h_tty_read(conn, p):
    tid = p.get("tty_id")
    with TTYS_LOCK:
        tty = TTYS.get(tid)
    if not tty:
        raise NotFound("no such tty: %s" % tid)
    data, end, gap = tty.read(int(p.get("offset") or 0),
                              float(p.get("wait") or 0),
                              p.get("until"))
    return {"tty_id": tid, "data": data.decode("utf-8", "replace"),
            "offset": end, "lost": gap, "alive": tty.alive,
            "pid": tty.pid}


def h_tty_close(conn, p):
    tid = p.get("tty_id")
    with TTYS_LOCK:
        tty = TTYS.pop(tid, None)
    if not tty:
        raise NotFound("no such tty: %s" % tid)
    tty.close()
    return {"tty_id": tid, "closed": True}


def _entry(path, name):
    full = os.path.join(path, name)
    try:
        st = os.lstat(full)
    except OSError as exc:
        return {"name": name, "path": full, "error": str(exc)}
    kind = ("dir" if statmod.S_ISDIR(st.st_mode) else
            "link" if statmod.S_ISLNK(st.st_mode) else
            "file" if statmod.S_ISREG(st.st_mode) else
            "fifo" if statmod.S_ISFIFO(st.st_mode) else
            "sock" if statmod.S_ISSOCK(st.st_mode) else "other")
    item = {"name": name, "path": full, "type": kind, "size": st.st_size,
            "mode": oct(st.st_mode & 0o7777), "mtime": round(st.st_mtime, 3),
            "uid": getattr(st, "st_uid", None), "gid": getattr(st, "st_gid", None)}
    if kind == "link":
        try:
            item["target"] = os.readlink(full)
        except OSError:
            pass
    return item


def h_fs_ls(conn, p):
    path = POLICY.check(p.get("path") or WORKDIR, must_exist=True)
    if not os.path.isdir(path):
        raise NotFound("not a directory: %s" % path)
    show_all = bool(p.get("all"))
    depth = max(0, min(int(p.get("depth") or 1), 8))
    limit = int(p.get("limit") or 500)

    def walk(base, level):
        items = []
        try:
            names = sorted(os.listdir(base), key=lambda n: (not os.path.isdir(os.path.join(base, n)), n.lower()))
        except OSError as exc:
            return [{"name": ".", "path": base, "error": str(exc)}]
        for name in names:
            if not show_all and name.startswith("."):
                continue
            e = _entry(base, name)
            if level < depth and e.get("type") == "dir" and not os.path.islink(e["path"]):
                e["children"] = walk(e["path"], level + 1)
            items.append(e)
            if len(items) >= limit:
                break
        return items

    entries = walk(path, 0)
    return {"path": path, "entries": entries, "truncated": len(entries) >= limit}


def h_fs_stat(conn, p):
    path = POLICY.check(p.get("path"), must_exist=True)
    try:
        st = os.stat(path)
        lst = os.lstat(path)
    except OSError as exc:
        raise NotFound(str(exc))
    info = {
        "path": path, "exists": True, "type": "dir" if os.path.isdir(path) else "file",
        "size": st.st_size, "mode": oct(st.st_mode & 0o7777),
        "mtime": round(st.st_mtime, 3), "atime": round(st.st_atime, 3),
        "uid": getattr(st, "st_uid", None), "gid": getattr(st, "st_gid", None),
        "is_link": os.path.islink(path), "inode": st.st_ino,
        "hardlinks": st.st_nlink,
    }
    if os.path.isdir(path):
        try:
            info["entries"] = len(os.listdir(path))
        except OSError:
            pass
    if info["is_link"]:
        info["target"] = os.readlink(path)
    return info


def h_fs_read(conn, p):
    path = POLICY.check(p.get("path"), must_exist=True)
    if os.path.isdir(path):
        raise ValueError("%s is a directory; use fs_ls" % path)
    size = os.path.getsize(path)
    max_bytes = int(p.get("max_bytes") or POLICY.max_read_bytes)
    offset = int(p.get("offset") or 0)
    with open(path, "rb") as fh:
        fh.seek(offset)
        raw = fh.read(min(max_bytes, max(0, size - offset)))
    binary = b"\x00" in raw[:8192] or bool(p.get("binary"))
    result = {"path": path, "size": size, "offset": offset, "bytes": len(raw),
              "truncated": offset + len(raw) < size}
    if binary and not p.get("as_text"):
        import base64
        result.update({"encoding": "base64", "data": base64.b64encode(raw).decode("ascii")})
        return result
    text = raw.decode(p.get("encoding") or "utf-8", "replace")
    start_line = int(p.get("start_line") or 0)
    end_line = int(p.get("end_line") or 0)
    if start_line or end_line:
        lines = text.splitlines()
        s = max(0, start_line - 1) if start_line else 0
        e = end_line if end_line else len(lines)
        text = "\n".join(lines[s:e])
        result["lines_total"] = len(lines)
        result["lines_returned"] = [s + 1, min(e, len(lines))]
    result.update({"encoding": "utf-8", "data": text})
    return result


def h_fs_tail(conn, p):
    path = POLICY.check(p.get("path"), must_exist=True)
    n = int(p.get("lines") or 50)
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        block = min(size, max(4096, n * 200))
        fh.seek(size - block)
        data = fh.read(block)
    lines = data.decode("utf-8", "replace").splitlines()[-n:]
    return {"path": path, "lines": lines, "size": size}


def h_fs_write(conn, p):
    path = POLICY.check(p.get("path"))
    if os.path.isdir(path):
        raise ValueError("%s is a directory" % path)
    mode = p.get("mode") or "w"
    if mode not in ("w", "a", "x"):
        raise ValueError("mode must be w, a or x")
    if p.get("create_parents", True):
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
    if p.get("data_b64") is not None:
        import base64
        payload = base64.b64decode(p["data_b64"])
    else:
        payload = (p.get("data") or "").encode(p.get("encoding") or "utf-8")
    if len(payload) > POLICY.max_write_bytes:
        raise ValueError("payload exceeds max_write_bytes")
    with open(path, mode + "b") as fh:
        fh.write(payload)
    if p.get("chmod"):
        os.chmod(path, int(str(p["chmod"]), 8))
    st = os.stat(path)
    return {"path": path, "written": len(payload), "size": st.st_size,
            "mode": oct(st.st_mode & 0o7777),
            "sha256": hashlib.sha256(payload).hexdigest()}


def h_fs_edit(conn, p):
    path = POLICY.check(p.get("path"), must_exist=True)
    with open(path, "r", encoding=p.get("encoding") or "utf-8") as fh:
        text = fh.read()
    old, new = p.get("old"), p.get("new")
    if old is None or new is None:
        raise ValueError("both 'old' and 'new' are required")
    if p.get("regex"):
        flags = re.MULTILINE | (re.IGNORECASE if p.get("ignore_case") else 0)
        pattern = re.compile(old, flags)
        count = 0 if not p.get("count") else int(p["count"])
        new_text, n = pattern.subn(new, text, count=count)
    else:
        limit = int(p["count"]) if p.get("count") else -1
        n = text.count(old) if limit < 0 else min(limit, text.count(old))
        if n == 0 and not p.get("allow_missing"):
            raise NotFound("old string not found in %s" % path)
        new_text = text.replace(old, new, n if limit < 0 else limit)
    if p.get("dry_run"):
        return {"path": path, "replaced": n, "dry_run": True}
    if n:
        if p.get("backup"):
            shutil.copy2(path, path + ".sw-bak")
        with open(path, "w", encoding=p.get("encoding") or "utf-8") as fh:
            fh.write(new_text)
    return {"path": path, "replaced": n, "size": os.path.getsize(path)}


def h_fs_manage(conn, p):
    op = p.get("op")
    src = p.get("path")
    if op in ("mkdir",):
        path = POLICY.check(src)
        os.makedirs(path, exist_ok=bool(p.get("parents", True)))
        return {"op": op, "path": path, "ok": True}
    if op == "touch":
        path = POLICY.check(src)
        with open(path, "a"):
            pass
        os.utime(path, None)
        return {"op": op, "path": path, "ok": True}
    if op == "rm":
        path = POLICY.check(src, must_exist=True)
        recursive = bool(p.get("recursive"))
        if os.path.isdir(path) and not os.path.islink(path):
            if not recursive:
                raise ValueError("refusing to remove directory without recursive=true")
            shutil.rmtree(path)
        else:
            os.unlink(path)
        return {"op": op, "path": path, "ok": True}
    if op in ("mv", "cp"):
        a = POLICY.check(src, must_exist=True)
        b = POLICY.check(p.get("dest"))
        if op == "mv":
            shutil.move(a, b)
        elif os.path.isdir(a) and p.get("recursive", True):
            if os.path.isdir(b):
                b = os.path.join(b, os.path.basename(a))
            shutil.copytree(a, b, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(a, b)
        return {"op": op, "path": a, "dest": b, "ok": True}
    if op == "chmod":
        path = POLICY.check(src, must_exist=True)
        mode = int(str(p.get("mode")), 8)
        if p.get("recursive"):
            for root, dirs, files in os.walk(path):
                for n in dirs + files:
                    try:
                        os.chmod(os.path.join(root, n), mode)
                    except OSError:
                        pass
        os.chmod(path, mode)
        return {"op": op, "path": path, "mode": oct(mode), "ok": True}
    if op == "chown":
        path = POLICY.check(src, must_exist=True)
        uid, gid = p.get("uid"), p.get("gid")
        os.chown(path, int(uid) if uid is not None else -1,
                 int(gid) if gid is not None else -1)
        return {"op": op, "path": path, "ok": True}
    if op == "symlink":
        link = POLICY.check(p.get("link") or src)
        os.symlink(p.get("dest"), link)
        return {"op": op, "link": link, "dest": p.get("dest"), "ok": True}
    if op == "truncate":
        path = POLICY.check(src, must_exist=True)
        with open(path, "r+b") as fh:
            fh.truncate(int(p.get("size") or 0))
        return {"op": op, "path": path, "ok": True}
    raise ValueError("unsupported op: %s" % op)


def h_fs_find(conn, p):
    root = POLICY.check(p.get("root") or WORKDIR, must_exist=True)
    pattern = p.get("pattern") or "*"
    kind = p.get("type") or "any"
    max_depth = int(p.get("max_depth") or 8)
    limit = int(p.get("limit") or 200)
    min_size = int(p.get("min_size") or 0)
    max_size = int(p.get("max_size") or 0)
    newer = float(p.get("newer_than") or 0)
    deadline = time.time() + float(p.get("timeout") or 15)
    results = []
    root_depth = root.rstrip(os.sep).count(os.sep)
    for base, dirs, files in os.walk(root, followlinks=bool(p.get("follow_links"))):
        if time.time() > deadline:
            break
        depth = base.rstrip(os.sep).count(os.sep) - root_depth
        if depth >= max_depth:
            dirs[:] = []
        for name in list(dirs) + files:
            if len(results) >= limit:
                break
            full = os.path.join(base, name)
            is_dir = os.path.isdir(full) and not os.path.islink(full)
            if kind == "file" and is_dir:
                continue
            if kind == "dir" and not is_dir:
                continue
            rel = os.path.relpath(full, root)
            if not (fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(rel, pattern)):
                continue
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if min_size and st.st_size < min_size:
                continue
            if max_size and st.st_size > max_size:
                continue
            if newer and st.st_mtime < newer:
                continue
            results.append({"path": full, "rel": rel, "type": "dir" if is_dir else "file",
                            "size": st.st_size, "mtime": round(st.st_mtime, 3)})
        if len(results) >= limit:
            break
    return {"root": root, "pattern": pattern, "matches": results,
            "truncated": len(results) >= limit}


def h_fs_grep(conn, p):
    root = POLICY.check(p.get("root") or WORKDIR, must_exist=True)
    pattern = p.get("pattern")
    if not pattern:
        raise ValueError("pattern is required")
    flags = re.MULTILINE
    if p.get("ignore_case"):
        flags |= re.IGNORECASE
    try:
        rx = re.compile(pattern if not p.get("fixed") else re.escape(pattern), flags)
    except re.error as exc:
        raise ValueError("bad regex: %s" % exc)
    glob = p.get("glob") or "*"
    max_matches = int(p.get("max_matches") or 100)
    max_file_size = int(p.get("max_file_size") or 2 << 20)
    deadline = time.time() + float(p.get("timeout") or 20)
    matches, files_scanned = [], 0
    for base, dirs, files in os.walk(root):
        if time.time() > deadline or len(matches) >= max_matches:
            break
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__") or p.get("include_hidden")]
        for name in files:
            if len(matches) >= max_matches or time.time() > deadline:
                break
            if not fnmatch.fnmatch(name, glob):
                continue
            full = os.path.join(base, name)
            try:
                if os.path.getsize(full) > max_file_size or os.path.islink(full):
                    continue
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b"\x00" in raw[:4096]:
                continue
            files_scanned += 1
            text = raw.decode("utf-8", "replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    matches.append({"path": full, "line": lineno, "text": line[:400]})
                    if len(matches) >= max_matches:
                        break
    return {"root": root, "pattern": pattern, "matches": matches,
            "files_scanned": files_scanned, "truncated": len(matches) >= max_matches}


def h_fs_hash(conn, p):
    path = POLICY.check(p.get("path"), must_exist=True)
    algo = p.get("algo") or "sha256"
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return {"path": path, "algo": algo, "hash": h.hexdigest(), "size": os.path.getsize(path)}


# --------------------------------------------------------------- blob transfer

class Incoming(object):
    def __init__(self, sid, path, size, sha256):
        self.sid = sid
        self.path = path
        self.tmp = path + ".sw-part"
        self.size = size
        self.sha256 = sha256
        self.received = 0
        self.hasher = hashlib.sha256()
        self.done = threading.Event()
        self.ok = False
        self.error = None
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.fh = open(self.tmp, "wb")

    def feed(self, data):
        self.fh.write(data)
        self.hasher.update(data)
        self.received += len(data)

    def finish(self):
        try:
            self.fh.close()
        except Exception:
            pass
        digest = self.hasher.hexdigest()
        if self.size and self.received != self.size:
            self.error = "size mismatch: got %d want %d" % (self.received, self.size)
        elif self.sha256 and digest != self.sha256:
            self.error = "sha256 mismatch"
        if self.error:
            try:
                os.unlink(self.tmp)
            except Exception:
                pass
            self.ok = False
        else:
            os.replace(self.tmp, self.path)
            self.ok = True
        self.done.set()
        return self.ok


INCOMING = {}
INCOMING_LOCK = threading.Lock()


def h_fs_push(conn, p):
    path = POLICY.check(p.get("path"))
    size = int(p.get("size") or 0)
    if size > POLICY.max_write_bytes:
        raise Denied("file too large for policy")
    sid = int(p.get("sid") or conn.next_stream())
    inc = Incoming(sid, path, size, p.get("sha256"))
    with INCOMING_LOCK:
        INCOMING[sid] = inc
    return {"sid": sid, "path": path, "ready": True}


def h_fs_pull(conn, p):
    path = POLICY.check(p.get("path"), must_exist=True)
    if os.path.isdir(path):
        raise ValueError("%s is a directory (tar it first)" % path)
    size = os.path.getsize(path)
    offset = int(p.get("offset") or 0)
    sha = None
    if not offset:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        sha = h.hexdigest()
    sid = int(p.get("sid") or conn.next_stream())
    conn.spawn(lambda: _send_blob(conn, sid, path, offset, size, sha))
    return {"sid": sid, "path": path, "size": size, "offset": offset, "sha256": sha}


def _send_blob(conn, sid, path, offset, size, sha):
    sent = 0
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            while True:
                chunk = fh.read(BLOB_CHUNK)
                if not chunk:
                    break
                sent += len(chunk)
                conn.send_blob(sid, chunk, 0)
        conn.send(T_EVT, sid, {"k": "blob_done", "sid": sid, "ok": True,
                               "bytes": sent, "sha256": sha, "size": size})
    except Exception as exc:
        try:
            conn.send(T_EVT, sid, {"k": "blob_done", "sid": sid, "ok": False,
                                   "error": "%s: %s" % (type(exc).__name__, exc)})
        except Exception:
            pass


# ---------------------------------------------------------------- system ops

def h_proc_list(conn, p):
    return {"processes": proc_list(p.get("filter"), p.get("sort") or "cpu",
                                   int(p.get("limit") or 40),
                                   with_cmdline=not p.get("no_cmdline")),
            "cpu_count": cpu_count(), "mem_total_mb": round(mem_total_bytes() / 1048576.0, 1)}


def h_proc_kill(conn, p):
    if not POLICY.allow_proc_kill:
        raise Denied("process kill disabled by policy")
    sig = int(p.get("signal") or 15)
    killed = []
    if p.get("pid"):
        pids = [int(p["pid"])]
    elif p.get("name"):
        pids = [r["pid"] for r in proc_list(p["name"], "pid", 100) if r["name"] == p["name"]]
    else:
        raise ValueError("pid or name is required")
    for pid in pids:
        try:
            os.kill(pid, sig)
            killed.append({"pid": pid, "signal": sig, "ok": True})
        except OSError as exc:
            killed.append({"pid": pid, "ok": False, "error": str(exc)})
    return {"killed": killed}


def h_svc(conn, p):
    name = p.get("name")
    action = p.get("action") or "status"
    init = init_system()
    if not name and action != "list":
        raise ValueError("service name is required")
    if action == "list":
        if init == "systemd":
            r = run_capture(["systemctl", "list-units", "--type=service", "--no-pager",
                             "--plain", "--no-legend"], timeout=15)
        else:
            r = run_capture(["service", "--status-all"], timeout=15)
        return {"init": init, "output": r["stdout"] + r["stderr"]}
    if action == "logs":
        lines = int(p.get("lines") or 50)
        r = run_capture(["journalctl", "-u", name, "-n", str(lines), "--no-pager"], timeout=20)
        return {"name": name, "output": r["stdout"] + r["stderr"]}
    if init == "systemd":
        cmd = ["systemctl", action, name]
        if action in ("start", "stop", "restart", "enable", "disable", "reload") and not POLICY.allow_sudo:
            pass
    elif init == "openrc":
        cmd = ["rc-service", name, action]
    else:
        cmd = ["service", name, action]
    if action == "status":
        cmd = ["systemctl", "status", name, "--no-pager", "-l"] if init == "systemd" else cmd
    r = run_capture(cmd, timeout=30)
    return {"name": name, "action": action, "exit": r["exit"],
            "output": (r["stdout"] + r["stderr"])[:20000], "init": init}


def h_net(conn, p):
    action = p.get("action") or "info"
    if action == "info":
        return {"hostname": socket.gethostname(), "interfaces": iface_list(),
                "routes": _routes()}
    if action == "sockets":
        return {"sockets": socket_list(p.get("states"), bool(p.get("with_pid")),
                                       int(p.get("limit") or 200))}
    if action == "probe":
        host, port = p.get("host"), int(p.get("port") or 0)
        if not host or not port:
            raise ValueError("host and port are required")
        t0 = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(p.get("timeout") or 3))
        try:
            sock.connect((host, port))
            ok = True
            err = None
        except Exception as exc:
            ok = False
            err = str(exc)
        finally:
            sock.close()
        return {"host": host, "port": port, "open": ok, "error": err,
                "ms": round((time.time() - t0) * 1000, 1)}
    if action == "dns":
        try:
            return {"host": p.get("host"), "addresses": socket.getaddrinfo(p.get("host"), None)[0][4]}
        except Exception as exc:
            return {"host": p.get("host"), "error": str(exc)}
    raise ValueError("unsupported net action: %s" % action)


def _routes():
    if IS_WIN:
        return []
    rows = []
    for line in _read("/proc/net/route").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            dest = socket.inet_ntoa(struct.pack("<I", int(parts[1], 16)))
            mask = socket.inet_ntoa(struct.pack("<I", int(parts[7], 16)))
            gw = socket.inet_ntoa(struct.pack("<I", int(parts[2], 16)))
        except Exception:
            continue
        rows.append({"iface": parts[0], "dest": dest, "gateway": gw, "mask": mask,
                     "metric": parts[6]})
    return rows


def h_pkg(conn, p):
    if not POLICY.allow_pkg:
        raise Denied("package management disabled by policy (restart agentd with --allow-pkg)")
    mgr = p.get("manager") or pkg_manager()
    action = p.get("action") or "list"
    pkgs = " ".join(p.get("packages") or [])
    table = PKG_CMDS.get(mgr)
    if not table:
        raise ValueError("unsupported package manager: %s" % mgr)
    tmpl = table.get(action)
    if not tmpl:
        raise ValueError("unsupported action %r for %s" % (action, mgr))
    cmd = tmpl.format(p=pkgs)
    prefix = "sudo -n " if (IS_POSIX and action not in ("search", "info", "list", "update")) and not _is_root() else ""
    r = run_capture(["/bin/sh", "-c", prefix + cmd], timeout=float(p.get("timeout") or 300))
    return {"manager": mgr, "action": action, "cmd": cmd, "exit": r["exit"],
            "output": (r["stdout"] + r["stderr"])[-20000:]}


def _is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def h_sys_power(conn, p):
    if not POLICY.allow_power:
        raise Denied("power control disabled by policy (restart agentd with --allow-power)")
    action = p.get("action")
    if p.get("confirm") != action:
        raise Denied("power action requires confirm=%r" % action)
    cmds = {"reboot": ["systemctl", "reboot"] if init_system() == "systemd" else ["reboot"],
            "shutdown": ["systemctl", "poweroff"] if init_system() == "systemd" else ["shutdown", "-h", "now"],
            "cancel": ["systemctl", "cancel"] if init_system() == "systemd" else ["shutdown", "-c"],
            "suspend": ["systemctl", "suspend"] if init_system() == "systemd" else ["pm-suspend"]}
    if action not in cmds:
        raise ValueError("action must be one of %s" % ", ".join(cmds))
    if not _is_root() and init_system() == "systemd":
        cmds[action] = ["sudo", "-n"] + cmds[action]
    r = run_capture(cmds[action], timeout=15)
    return {"action": action, "exit": r["exit"], "output": r["stdout"] + r["stderr"]}


HANDLERS = {
    "sys.ping": h_sys_ping,
    "sys.info": h_sys_info,
    "sys.power": h_sys_power,
    "exec.run": h_exec_run,
    "exec.script": h_exec_script,
    "job.list": h_job_list,
    "job.poll": h_job_poll,
    "job.kill": h_job_kill,
    "job.input": h_job_input,
    "tty.open": h_tty_open,
    "tty.write": h_tty_write,
    "tty.read": h_tty_read,
    "tty.close": h_tty_close,
    "fs.ls": h_fs_ls,
    "fs.stat": h_fs_stat,
    "fs.read": h_fs_read,
    "fs.tail": h_fs_tail,
    "fs.write": h_fs_write,
    "fs.edit": h_fs_edit,
    "fs.manage": h_fs_manage,
    "fs.find": h_fs_find,
    "fs.grep": h_fs_grep,
    "fs.hash": h_fs_hash,
    "fs.push": h_fs_push,
    "fs.pull": h_fs_pull,
    "proc.list": h_proc_list,
    "proc.kill": h_proc_kill,
    "svc.action": h_svc,
    "net.info": h_net,
    "pkg.action": h_pkg,
}


# ===========================================================================
# 10. connection
# ===========================================================================

class Conn(object):
    def __init__(self, sock, addr, key, opts):
        self.sock = sock
        self.addr = addr
        self.key = key
        self.opts = opts
        self.writer = Writer(sock)
        self.tx = None
        self.rx = None
        self.sealed = False
        self.stream_seq = 100
        self.stream_lock = threading.Lock()
        self._seal_lock = threading.Lock()
        self.closed = False
        self.client_info = {}

    def next_stream(self):
        with self.stream_lock:
            self.stream_seq += 1
            return self.stream_seq

    def send(self, ftype, stream=0, obj=None, flags=0):
        payload = pack_json(obj) if obj is not None else b""
        # seal+write is one atomic step; the sealer counter defines wire order
        with self._seal_lock:
            if self.sealed and self.tx:
                payload = self.tx.seal(payload)
                flags |= F_SEALED
            self.writer.write(ftype, stream, payload, flags)

    def send_blob(self, sid, data, flags=0):
        with self._seal_lock:
            if self.sealed and self.tx:
                data = self.tx.seal(data)
                flags |= F_SEALED
            self.writer.write(T_BLOB, sid, data, flags)

    def spawn(self, fn):
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        return t

    # ------------------------------------------------------------- handshake
    def handshake(self):
        head = recv_exact(self.sock, HEADER_SIZE)
        ftype, flags, stream, length, crc = unpack_header(head)
        if ftype != T_HELLO:
            raise AuthError("expected HELLO")
        hello = unpack_json(recv_exact(self.sock, length))
        if int(hello.get("v", 0)) != VERSION:
            self.writer.write_json(T_AUTH_FAIL, 0, {"error": "protocol version mismatch",
                                                    "want": VERSION, "got": hello.get("v")})
            raise AuthError("version mismatch")
        nonce_c = bytes.fromhex(hello.get("nonce", ""))
        if len(nonce_c) != 16:
            raise AuthError("bad client nonce")
        nonce_s = os.urandom(16)
        self.writer.write_json(T_CHALLENGE, 0, {
            "v": VERSION, "nonce": nonce_s.hex(),
            "host": socket.gethostname(),
            "crypto": "hmac-ctr" if self.opts.get("crypto", True) else "none",
            "time": int(time.time()),
        })
        head = recv_exact(self.sock, HEADER_SIZE)
        ftype, flags, stream, length, crc = unpack_header(head)
        if ftype != T_AUTH:
            raise AuthError("expected AUTH")
        auth = unpack_json(recv_exact(self.sock, length))
        expect = client_proof(self.key, nonce_c, nonce_s)
        try:
            got = bytes.fromhex(auth.get("proof", ""))
        except ValueError:
            raise AuthError("bad proof encoding")
        if not hmac.compare_digest(got, expect):
            self.writer.write_json(T_AUTH_FAIL, 0, {"error": "bad key"})
            raise AuthError("bad key from %s" % (self.addr[0],))

        self.writer.write_json(T_AUTH_OK, 0, {
            "proof": server_proof(self.key, nonce_c, nonce_s).hex(),
            "host": socket.gethostname(),
            "os": "Windows" if IS_WIN else "Linux",
            "agent": CONFIG.get("version", "1.0.0"),
            "pid": os.getpid(),
            "caps": sorted(HANDLERS),
        })
        if auth.get("crypto") != "none" and self.opts.get("crypto", True):
            sk = session_key(self.key, nonce_c, nonce_s)
            self.tx = Sealer(sk)
            self.rx = Sealer(sk)
            self.sealed = True
        self.client_info = auth

    # ------------------------------------------------------------------ loop
    def serve(self):
        try:
            self.handshake()
        except (AuthError, EOFError, ProtocolError, OSError) as exc:
            log("handshake failed from %s: %s" % (self.addr[0], exc), "warn")
            self.close()
            return
        log("client %s connected (client=%s)" % (self.addr[0], self.client_info.get("client", "?")))
        last_ping = time.time()
        try:
            while not self.closed:
                try:
                    head = recv_exact(self.sock, HEADER_SIZE)
                except EOFError:
                    break
                ftype, flags, stream, length, crc = unpack_header(head)
                payload = recv_exact(self.sock, length) if length else b""
                if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
                    raise ProtocolError("crc mismatch")
                if flags & F_SEALED:
                    if not self.rx:
                        raise ProtocolError("sealed frame before auth")
                    payload = self.rx.open(payload)

                if ftype == T_REQ:
                    self.on_req(stream, payload)
                elif ftype == T_BLOB:
                    self.on_blob(stream, payload, flags)
                elif ftype == T_PING:
                    self.send(T_PONG, stream, {"t": time.time()})
                elif ftype == T_CANCEL:
                    self.on_cancel(payload)
                elif ftype == T_BYE:
                    break
                else:
                    log("unexpected frame type 0x%02x" % ftype, "warn")
        except (EOFError, OSError):
            pass
        except ProtocolError as exc:
            log("protocol error from %s: %s" % (self.addr[0], exc), "warn")
        except Exception:
            log("connection crash: %s" % traceback.format_exc(), "error")
        finally:
            self.close()
            log("client %s disconnected" % (self.addr[0],))

    def on_req(self, stream, payload):
        try:
            req = unpack_json(payload)
        except ProtocolError as exc:
            self.send(T_RES, stream, {"id": None, "ok": False,
                                      "e": {"code": "bad_request", "msg": str(exc)}})
            return
        rid = req.get("id")
        method = req.get("m")
        params = req.get("p") or {}
        handler = HANDLERS.get(method)
        if not handler:
            self.send(T_RES, stream, {"id": rid, "ok": False,
                                      "e": {"code": "unsupported", "msg": "unknown method %r" % method}})
            return

        def work():
            t0 = time.time()
            try:
                result = handler(self, params)
                self.send(T_RES, stream, {"id": rid, "ok": True, "r": result})
                self.audit(method, params, t0, True, None)
            except Denied as exc:
                self.send(T_RES, stream, {"id": rid, "ok": False,
                                          "e": {"code": "denied", "msg": str(exc)}})
                self.audit(method, params, t0, False, str(exc))
            except NotFound as exc:
                self.send(T_RES, stream, {"id": rid, "ok": False,
                                          "e": {"code": "not_found", "msg": str(exc)}})
                self.audit(method, params, t0, False, str(exc))
            except (ValueError, FileNotFoundError, PermissionError, IsADirectoryError) as exc:
                self.send(T_RES, stream, {"id": rid, "ok": False,
                                          "e": {"code": "bad_request", "msg": str(exc)}})
                self.audit(method, params, t0, False, str(exc))
            except Exception as exc:
                log("handler %s failed: %s" % (method, traceback.format_exc()), "error")
                self.send(T_RES, stream, {"id": rid, "ok": False,
                                          "e": {"code": "internal",
                                                "msg": "%s: %s" % (type(exc).__name__, exc)}})
                self.audit(method, params, t0, False, str(exc))

        self.spawn(work)

    def on_blob(self, sid, payload, flags):
        with INCOMING_LOCK:
            inc = INCOMING.get(sid)
        if not inc:
            log("blob for unknown sid %d" % sid, "warn")
            return
        try:
            if flags & F_ERR:
                inc.error = "peer aborted"
                inc.finish()
                with INCOMING_LOCK:
                    INCOMING.pop(sid, None)
                self.send(T_EVT, sid, {"k": "blob_done", "sid": sid, "ok": False,
                                       "error": inc.error})
                return
            inc.feed(payload)
            if flags & F_FIN:
                ok = inc.finish()
                with INCOMING_LOCK:
                    INCOMING.pop(sid, None)
                self.send(T_EVT, sid, {"k": "blob_done", "sid": sid, "ok": ok,
                                       "path": inc.path, "bytes": inc.received,
                                       "sha256": inc.hasher.hexdigest(),
                                       "error": inc.error})
        except Exception as exc:
            log("blob error: %s" % exc, "error")
            with INCOMING_LOCK:
                INCOMING.pop(sid, None)

    def on_cancel(self, payload):
        try:
            req = unpack_json(payload)
        except ProtocolError:
            return
        jid = req.get("job_id")
        with JOBS_LOCK:
            job = JOBS.get(jid)
        if job:
            job.kill()

    def audit(self, method, params, t0, ok, err):
        if not CONFIG.get("audit", True):
            return
        dur = (time.time() - t0) * 1000
        brief = {k: (str(v)[:120] if not isinstance(v, (int, float, bool)) else v)
                 for k, v in list(params.items())[:8]}
        log("%s %s %.0fms ok=%s%s | %s" % (self.addr[0], method, dur, ok,
                                           "" if ok else " err=" + str(err)[:160],
                                           json.dumps(brief, ensure_ascii=False)), "audit")

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


# ===========================================================================
# 11. server
# ===========================================================================

def _cidr_match(ip, cidr):
    try:
        net, bits = cidr.split("/")
        bits = int(bits)
    except ValueError:
        return ip == cidr
    try:
        ip_i = struct.unpack("!I", socket.inet_aton(ip))[0]
        net_i = struct.unpack("!I", socket.inet_aton(net))[0]
    except OSError:
        return False
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    return (ip_i & mask) == (net_i & mask)


def serve_forever(bind, port, key, opts):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
    srv.bind((bind, port))
    srv.listen(16)
    allow = opts.get("allow_cidrs") or []
    log("agentd listening on %s:%d (crypto=%s, allow=%s)" %
        (bind, port, "on" if opts.get("crypto", True) else "off", allow or "any"))
    try:
        while True:
            try:
                sock, addr = srv.accept()
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                raise
            if allow and not any(_cidr_match(addr[0], c) for c in allow):
                log("rejected connection from %s (not in allowlist)" % (addr[0],), "warn")
                try:
                    sock.close()
                except Exception:
                    pass
                continue
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn = Conn(sock, addr, key, opts)
            threading.Thread(target=conn.serve, daemon=True).start()
    except KeyboardInterrupt:
        log("interrupted, shutting down")
    finally:
        srv.close()
        with JOBS_LOCK:
            for job in JOBS.values():
                job.kill()
        with TTYS_LOCK:
            for tty in TTYS.values():
                tty.close()


def main(argv=None):
    global WORKDIR, SUDO_PASSWORD, POLICY, CONFIG
    ap = argparse.ArgumentParser(
        prog="sidewire_agentd",
        description="SideWire agent daemon — lets a Windows-side AI agent drive this machine.")
    ap.add_argument("--bind", default=None, help="listen address (default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=None, help="listen port (default 7900)")
    ap.add_argument("--key", default=None, help="shared key (hex), prefer --key-file")
    ap.add_argument("--key-file", default=None, help="file holding the shared key")
    ap.add_argument("--keygen", action="store_true", help="generate a key and exit")
    ap.add_argument("--out", default=None, help="where --keygen writes the key")
    ap.add_argument("--config", default=None, help="JSON config file")
    ap.add_argument("--allow-cidr", action="append", default=None,
                    help="only accept clients from these CIDRs (repeatable)")
    ap.add_argument("--allow-root", action="append", default=None,
                    help="filesystem roots the agent may touch (repeatable, default /)")
    ap.add_argument("--deny-root", action="append", default=None)
    ap.add_argument("--allow-sudo", action="store_true")
    ap.add_argument("--allow-power", action="store_true")
    ap.add_argument("--allow-pkg", action="store_true")
    ap.add_argument("--sudo-password", default=None)
    ap.add_argument("--no-crypto", action="store_true", help="disable payload sealing (debug)")
    ap.add_argument("--log", default=None, help="append logs to this file")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--workdir", default=None, help="default cwd for commands")
    ap.add_argument("--print-unit", action="store_true", help="print a systemd unit and exit")
    args = ap.parse_args(argv)

    if args.keygen:
        raw = os.urandom(32)
        key_text = "sw1_" + raw.hex()
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(key_text + "\n")
            try:
                os.chmod(args.out, 0o600)
            except Exception:
                pass
            print("wrote %s" % args.out)
        print(key_text)
        return 0

    if args.print_unit:
        print(_systemd_unit(args))
        return 0

    cfg = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    CONFIG = cfg
    CONFIG.setdefault("version", "1.0.0")

    set_log(args.log or cfg.get("log"), args.verbose or cfg.get("verbose", False))

    bind = args.bind or cfg.get("bind") or "0.0.0.0"
    port = args.port or int(cfg.get("port") or 7900)
    WORKDIR = os.path.expanduser(args.workdir or cfg.get("workdir") or "~")
    SUDO_PASSWORD = args.sudo_password or cfg.get("sudo_password")

    key_text = args.key or os.environ.get("SIDEWIRE_KEY")
    key_file = args.key_file or cfg.get("key_file")
    if not key_text and key_file and os.path.exists(key_file):
        with open(key_file, "r", encoding="utf-8") as fh:
            key_text = fh.read().strip()
    if not key_text:
        log("no key configured — run with --keygen --out /etc/sidewire/agent.key "
            "then --key-file /etc/sidewire/agent.key", "error")
        return 2
    key = parse_key(key_text)

    POLICY = Policy(
        allow_roots=args.allow_root or cfg.get("allow_roots") or ["/"],
        deny_roots=args.deny_root or cfg.get("deny_roots") or [],
        allow_sudo=args.allow_sudo or cfg.get("allow_sudo", False),
        allow_power=args.allow_power or cfg.get("allow_power", False),
        allow_pkg=args.allow_pkg or cfg.get("allow_pkg", False),
        max_read_bytes=int(cfg.get("max_read_bytes") or (8 << 20)),
        max_write_bytes=int(cfg.get("max_write_bytes") or (256 << 20)),
    )

    opts = {
        "crypto": not args.no_crypto and cfg.get("crypto", True),
        "allow_cidrs": args.allow_cidr or cfg.get("allow_cidrs") or [],
    }
    log("sidewire agentd %s starting (pid %d, python %s)" %
        (CONFIG["version"], os.getpid(), sys.version.split()[0]))
    serve_forever(bind, port, key, opts)
    return 0


def _systemd_unit(args):
    exe = os.path.abspath(__file__)
    return """[Unit]
Description=SideWire agent daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s %s --key-file /etc/sidewire/agent.key --port %d
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
""" % (sys.executable, exe, args.port or 7900)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
