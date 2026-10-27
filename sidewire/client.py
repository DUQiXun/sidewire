"""Client side of SideWire: one multiplexed TCP connection per host.

The client keeps a single socket per host alive and dispatches concurrent
requests over it.  If the socket dies it is dropped; the next request dials a
fresh one and re-authenticates.  There is no session token to go stale, which
is the whole point of not doing this over HTTP.
"""

from __future__ import annotations

import hashlib
import os
import socket
import threading
import time

from . import protocol as P
from . import config as cfgmod
from . import discover


class RemoteError(Exception):
    def __init__(self, code, msg, detail=None):
        super().__init__(msg)
        self.code = code
        self.msg = msg
        self.detail = detail

    def as_dict(self):
        out = {"code": self.code, "message": self.msg}
        if self.detail:
            out["detail"] = self.detail
        return out


class _Pending(object):
    __slots__ = ("event", "result", "error")

    def __init__(self):
        self.event = threading.Event()
        self.result = None
        self.error = None


class _BlobSink(object):
    """Collects an inbound file transfer."""

    def __init__(self, path):
        self.path = path
        self.tmp = path + ".sw-part"
        self.fh = open(self.tmp, "wb")
        self.hasher = hashlib.sha256()
        self.received = 0
        self.done = threading.Event()
        self.error = None
        self.meta = {}

    def feed(self, data):
        self.fh.write(data)
        self.hasher.update(data)
        self.received += len(data)

    def finish(self, meta):
        self.meta = meta or {}
        try:
            self.fh.close()
        except Exception:
            pass
        if not self.meta.get("ok"):
            self.error = self.meta.get("error") or "transfer failed"
        elif self.meta.get("sha256") and self.hasher.hexdigest() != self.meta["sha256"]:
            self.error = "sha256 mismatch after transfer"
        if self.error:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass
        else:
            os.replace(self.tmp, self.path)
        self.done.set()


class _AckSink(object):
    """Just waits for the peer's blob_done event (used for uploads)."""

    def __init__(self):
        self.done = threading.Event()
        self.error = None
        self.meta = {}
        self.received = 0

    def feed(self, data):
        self.received += len(data)

    def finish(self, meta):
        self.meta = meta or {}
        if not self.meta.get("ok"):
            self.error = self.meta.get("error") or "transfer failed"
        self.done.set()


def _handshake_on(sock, key):
    """Authenticate an open socket.  Returns the session bits, or raises.

    Kept outside the class so the discovery sweep can verify a candidate
    without building (and then throwing away) a whole Remote.
    """
    reader = P.Reader(sock)
    writer = P.Writer(sock)
    nonce_c = os.urandom(16)
    writer.write_json(P.T_HELLO, 0, {
        "v": P.VERSION, "nonce": nonce_c.hex(), "client": "sidewire/1.0",
    })
    frame = reader.read()
    if frame.type == P.T_AUTH_FAIL:
        info = frame.json()
        raise RemoteError("auth_failed", info.get("error", "rejected"), detail=info)
    if frame.type != P.T_CHALLENGE:
        raise RemoteError("protocol", "expected CHALLENGE, got %r" % frame)
    ch = frame.json()
    if int(ch.get("v", 0)) != P.VERSION:
        raise RemoteError("protocol", "version mismatch: server speaks v%s" % ch.get("v"))
    nonce_s = bytes.fromhex(ch["nonce"])
    crypto = ch.get("crypto", "none")

    writer.write_json(P.T_AUTH, 0, {
        "proof": P.client_proof(key, nonce_c, nonce_s).hex(),
        "crypto": "hmac-ctr" if crypto != "none" else "none",
        "client": "sidewire/1.0",
    })
    frame = reader.read()
    if frame.type == P.T_AUTH_FAIL:
        info = frame.json()
        raise RemoteError("auth_failed",
                          "server rejected the key (%s)" % info.get("error", ""),
                          detail="the key on this side does not match the key file on the target")
    if frame.type != P.T_AUTH_OK:
        raise RemoteError("protocol", "expected AUTH_OK, got %r" % frame)
    ok = frame.json()
    expect = P.server_proof(key, nonce_c, nonce_s)
    if not _safe_eq(bytes.fromhex(ok.get("proof", "")), expect):
        raise RemoteError("auth_failed",
                          "server failed to prove it knows the key",
                          detail="possible man-in-the-middle or wrong key")
    session = {"reader": reader, "writer": writer, "info": ok, "sealed": False,
               "sealer_tx": None, "sealer_rx": None}
    if crypto != "none":
        sk = P.session_key(key, nonce_c, nonce_s)
        session["sealer_tx"] = P.Sealer(sk)
        session["sealer_rx"] = P.Sealer(sk)
        session["sealed"] = True
    return session


def probe(host, port, key, timeout=2.0):
    """Does *host* speak SideWire with *key*?  Returns its identity or None."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return _handshake_on(sock, key)["info"]
    except Exception:  # noqa: BLE001 - a failed probe is just a miss
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class Remote(object):
    """A live connection to one SideWire agent."""

    def __init__(self, host_entry, key_text, limits=None, logger=None):
        self.entry = host_entry
        self.alias = host_entry.get("alias") or host_entry.get("host")
        self.host = host_entry["host"]
        self.port = int(host_entry.get("port") or cfgmod.DEFAULT_PORT)
        self.key = P.parse_key(key_text)
        self.limits = limits or {}
        self.log = logger or (lambda *a, **k: None)

        self.sock = None
        self.reader = None
        self.writer = None
        self.sealer_tx = None
        self.sealer_rx = None
        self.sealed = False

        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending = {}
        self._blobs = {}
        self._id = 0
        self._stream = 100
        self._reader_thread = None
        self._closed = False
        self._last_rx = 0.0
        self._keepalive_thread = None
        self.info = {}

    # ------------------------------------------------------------- lifecycle
    def connect(self, timeout=None):
        timeout = float(timeout or self.limits.get("connect_timeout") or 5)
        self._closed = False
        # On a LAN a live host answers in milliseconds, so waiting the full
        # timeout at an address that has gone stale is just dead time before
        # the sweep that would have fixed it.
        dial_timeout = timeout
        if self.limits.get("auto_discover", True) and discover.is_lan_address(self.host):
            fast = float(self.limits.get("discover_fast_dial") or 1.5)
            dial_timeout = min(timeout, fast)
        try:
            sock = socket.create_connection((self.host, self.port), timeout=dial_timeout)
        except OSError as exc:
            moved = self._rediscover(exc)
            if moved is None:
                raise RemoteError("unreachable",
                                  "cannot reach %s:%s (%s)" % (self.host, self.port, exc),
                                  detail="check the address, the agentd process, and the firewall")
            try:
                sock = socket.create_connection((self.host, self.port), timeout=timeout)
            except OSError as exc2:
                raise RemoteError("unreachable",
                                  "cannot reach %s:%s (%s)" % (self.host, self.port, exc2),
                                  detail="address was rediscovered but the second dial failed")
        sock.settimeout(None)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.sock = sock
        try:
            self._handshake()
        except RemoteError:
            try:
                sock.close()
            except OSError:
                pass
            self.sock = None
            raise
        except (OSError, EOFError, ValueError) as exc:
            # A peer that accepts and then hangs up, or answers with garbage.
            # Left raw, this surfaces to the agent as "EOFError: connection
            # reset", which says nothing about what to do next.
            try:
                sock.close()
            except OSError:
                pass
            self.sock = None
            raise RemoteError("connection_lost",
                              "%s:%s dropped the connection during the handshake (%s)"
                              % (self.host, self.port, exc),
                              detail="agentd is probably restarting, or something other than "
                                     "sidewire is listening on that port")
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()
        ka = float(self.limits.get("keepalive") or 0)
        if ka > 0:
            self._keepalive_thread = threading.Thread(target=self._keepalive, args=(ka,), daemon=True)
            self._keepalive_thread.start()
        return self

    def _rediscover(self, exc):
        """Sweep the local subnet for this host after a failed dial.

        Returns the new address on success (already persisted to hosts.json),
        or None when the sweep is disabled, pointless, or came up empty.
        """
        if not self.limits.get("auto_discover", True):
            return None
        if not discover.is_lan_address(self.host):
            return None
        if isinstance(exc, socket.gaierror):
            pass  # name resolution failed; a sweep may still find the box
        self.log("dial to %s:%s failed (%s); sweeping local subnet" % (self.host, self.port, exc))
        try:
            found = discover.scan(self.port,
                                  timeout=float(self.limits.get("discover_scan_timeout") or 0.25))
        except OSError:
            return None
        for ip, rtt in found:
            if ip == self.host:
                continue
            info = probe(ip, self.port, self.key,
                         timeout=float(self.limits.get("discover_probe_timeout") or 2.0))
            if info is None:
                continue
            old = self.host
            self.host = ip
            self._persist_host(ip)
            self.log("host moved %s -> %s (%.1f ms, %s)" % (old, ip, rtt, info.get("host")))
            return ip
        return None

    def _persist_host(self, ip):
        """Write the new address back so the next process starts warm."""
        try:
            cfg = cfgmod.load()
        except RuntimeError:
            return
        entry = (cfg.get("hosts") or {}).get(self.alias)
        if not entry:
            return
        entry["host"] = ip
        try:
            cfgmod.save(cfg)
        except OSError:
            pass

    def _handshake(self):
        session = _handshake_on(self.sock, self.key)
        self.reader = session["reader"]
        self.writer = session["writer"]
        self.info = session["info"]
        self.sealed = session["sealed"]
        self.sealer_tx = session["sealer_tx"]
        self.sealer_rx = session["sealer_rx"]

    def close(self):
        self._closed = True
        try:
            if self.writer:
                self.writer.write(P.T_BYE, 0, b"")
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        for pend in list(self._pending.values()):
            pend.error = RemoteError("connection_lost", "connection closed")
            pend.event.set()
        self._pending.clear()

    @property
    def alive(self):
        return bool(self.sock) and not self._closed

    # ------------------------------------------------------------------ send
    def _send(self, ftype, stream, obj, flags=0):
        payload = P.pack_json(obj) if obj is not None else b""
        # sealing and writing must be one atomic step: the counter inside the
        # sealer defines the wire order, so two threads must not interleave
        # "seal()" and "send()".
        with self._write_lock:
            if self.sealed and self.sealer_tx:
                payload = self.sealer_tx.seal(payload)
                flags |= P.F_SEALED
            self.writer.write(ftype, stream, payload, flags)

    def _write_blob(self, sid, data, flags=0):
        with self._write_lock:
            if self.sealed and self.sealer_tx:
                data = self.sealer_tx.seal(data)
                flags |= P.F_SEALED
            self.writer.write(P.T_BLOB, sid, data, flags)

    def _keepalive(self, interval):
        while not self._closed:
            time.sleep(interval)
            if self._closed:
                return
            if time.time() - self._last_rx > interval * 3 and self.alive:
                try:
                    self._send(P.T_PING, 0, {"t": time.time()})
                except Exception:
                    return

    # ---------------------------------------------------------------- receive
    def _read_loop(self):
        try:
            while not self._closed:
                frame = self.reader.read()
                self._last_rx = time.time()
                if frame.flags & P.F_SEALED:
                    if not self.sealer_rx:
                        raise P.ProtocolError("sealed frame but crypto was never negotiated")
                    frame.payload = self.sealer_rx.open(frame.payload)
                self._dispatch(frame)
        except (EOFError, OSError):
            err = RemoteError("connection_lost", "connection to %s dropped" % self.alias,
                              detail="if a command was in flight it may or may not have run; "
                                     "re-run it or check the target")
        except Exception as exc:  # noqa: BLE001
            err = RemoteError("protocol", "connection error: %s" % exc)
        else:
            err = RemoteError("connection_lost", "connection closed")
        self._closed = True
        for pend in list(self._pending.values()):
            if not pend.event.is_set():
                pend.error = err
                pend.event.set()
        self._pending.clear()
        for sink in list(self._blobs.values()):
            if not sink.done.is_set():
                sink.error = "connection lost during transfer"
                sink.done.set()

    def _dispatch(self, frame):
        if frame.type == P.T_RES:
            msg = frame.json()
            pend = self._pending.pop(msg.get("id"), None)
            if not pend:
                return
            if msg.get("ok"):
                pend.result = msg.get("r") or {}
            else:
                e = msg.get("e") or {}
                pend.error = RemoteError(e.get("code", "error"),
                                         e.get("msg", "remote error"), e.get("detail"))
            pend.event.set()
        elif frame.type == P.T_BLOB:
            sink = self._blobs.get(frame.stream)
            if sink:
                try:
                    sink.feed(frame.payload)
                except Exception as exc:  # noqa: BLE001
                    sink.error = str(exc)
                    sink.done.set()
        elif frame.type == P.T_EVT:
            msg = frame.json()
            if msg.get("k") == "blob_done":
                sink = self._blobs.pop(msg.get("sid"), None)
                if sink:
                    sink.finish(msg)
            elif msg.get("k") == "log":
                self.log("[remote] %s" % msg.get("d"))
        elif frame.type == P.T_PONG:
            pass
        elif frame.type == P.T_BYE:
            raise EOFError("server said bye")

    # --------------------------------------------------------------- request
    def next_id(self):
        with self._lock:
            self._id += 1
            return self._id

    def next_stream(self):
        with self._lock:
            self._stream += 1
            return self._stream

    def request(self, method, params=None, timeout=None):
        if not self.alive:
            self.connect()
        rid = self.next_id()
        pend = _Pending()
        self._pending[rid] = pend
        try:
            self._send(P.T_REQ, 0, {"id": rid, "m": method, "p": params or {}})
        except (OSError, P.ProtocolError) as exc:
            self._pending.pop(rid, None)
            self._closed = True
            raise RemoteError("connection_lost",
                              "failed to send %s to %s: %s" % (method, self.alias, exc))
        wait = float(timeout if timeout is not None else
                     self.limits.get("default_timeout") or 60) + 15
        if not pend.event.wait(wait):
            self._pending.pop(rid, None)
            raise RemoteError("timeout",
                              "%s on %s did not answer within %.0fs" % (method, self.alias, wait))
        if pend.error:
            raise pend.error
        return pend.result

    def ping(self, timeout=5):
        t0 = time.time()
        res = self.request("sys.ping", {}, timeout=timeout)
        return {"ok": True, "ms": round((time.time() - t0) * 1000, 1),
                "host": self.info.get("host"), "os": self.info.get("os"),
                "agent": self.info.get("agent"), "pong": res.get("pong")}

    # ------------------------------------------------------------------ blob
    def pull(self, remote_path, local_path, timeout=None):
        """Download a remote file. Returns metadata dict."""
        local_path = os.path.abspath(os.path.expanduser(local_path))
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        sid = self.next_stream()
        sink = _BlobSink(local_path)
        self._blobs[sid] = sink          # registered before the request: no race
        try:
            meta = self.request("fs.pull", {"path": remote_path, "sid": sid},
                                timeout=timeout or 60)
        except Exception:
            self._blobs.pop(sid, None)
            raise
        size = int(meta.get("size") or 0)
        wait = float(timeout or max(60, size / (256 * 1024)))
        if not sink.done.wait(wait):
            self._blobs.pop(sid, None)
            raise RemoteError("timeout", "transfer of %s stalled" % remote_path)
        if sink.error:
            raise RemoteError("transfer_failed", sink.error)
        return {"local_path": local_path, "remote_path": meta.get("path"),
                "size": sink.received, "sha256": sink.hasher.hexdigest()}

    def push(self, local_path, remote_path, timeout=None):
        local_path = os.path.abspath(os.path.expanduser(local_path))
        if not os.path.isfile(local_path):
            raise RemoteError("not_found", "local file does not exist: %s" % local_path)
        size = os.path.getsize(local_path)
        h = hashlib.sha256()
        with open(local_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        digest = h.hexdigest()
        sid = self.next_stream()
        ack = _AckSink()
        self._blobs[sid] = ack
        try:
            start = self.request("fs.push",
                                 {"path": remote_path, "size": size,
                                  "sha256": digest, "sid": sid},
                                 timeout=timeout or 60)
            with open(local_path, "rb") as fh:
                while True:
                    chunk = fh.read(P.BLOB_CHUNK)
                    if not chunk:
                        break
                    self._write_blob(sid, chunk, 0)
            self._write_blob(sid, b"", P.F_FIN)
        except OSError as exc:
            self._blobs.pop(sid, None)
            raise RemoteError("transfer_failed", "read error: %s" % exc)
        except Exception:
            self._blobs.pop(sid, None)
            raise
        wait = float(timeout or max(60, size / (256 * 1024)))
        if not ack.done.wait(wait):
            self._blobs.pop(sid, None)
            raise RemoteError("timeout", "upload of %s stalled" % remote_path)
        if ack.error:
            raise RemoteError("transfer_failed", ack.error)
        return {"remote_path": start.get("path"), "size": size, "sha256": digest}


def _safe_eq(a, b):
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def open_remote(cfg=None, alias=None, logger=None):
    cfg = cfg or cfgmod.load()
    alias, entry = cfgmod.resolve_host(cfg, alias)
    key_text = cfgmod.host_key(entry, cfg)
    remote = Remote(entry, key_text, cfg.get("limits"), logger)
    remote.connect()
    return remote
