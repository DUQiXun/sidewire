"""
CrossWire wire protocol, v1.

Design notes
------------
CrossWire does not speak HTTP.  It puts a 16-byte binary header in front of
every message and multiplexes an arbitrary number of logical streams over one
long-lived TCP connection.

    +--------+------+-------+--------+--------+------------------+
    | "CWP1" | type | flags | stream | length | crc32 | payload  |
    |  4 B   | 1 B  |  1 B  |  2 B   |  4 B   |  4 B  | length B |
    +--------+------+-------+--------+--------+------------------+

Why this shape
--------------
* ``stream`` gives us multiplexing: a 40-minute build job never blocks a
  ``fs_read`` issued 2 seconds later.
* ``length`` + ``crc`` let both sides reject corruption instead of silently
  desynchronising, which is the failure mode that makes HTTP relays flaky.
* There is no session object on the server.  A connection *is* the session.
  Kill the daemon, the socket dies, the client reconnects and re-authenticates.
  There is no "connected but every call returns Session not found" state.

Payload confidentiality/integrity (optional, on by default) is provided by a
stdlib-only construction: an HMAC-SHA256 counter-mode keystream with an
encrypt-then-MAC truncated tag.  See :class:`Sealer`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import threading
import zlib

MAGIC = b"CWP1"
VERSION = 1

# magic, type, flags, stream, length, crc32
HEADER = struct.Struct("!4sBBHII")
HEADER_SIZE = HEADER.size  # 16

MAX_PAYLOAD = 1 << 20          # 1 MiB hard cap per frame
BLOB_CHUNK = 64 * 1024         # file transfer chunk size

# ---------------------------------------------------------------- frame types
T_HELLO      = 0x01
T_CHALLENGE  = 0x02
T_AUTH       = 0x03
T_AUTH_OK    = 0x04
T_AUTH_FAIL  = 0x05

T_REQ        = 0x10
T_RES        = 0x11
T_EVT        = 0x12
T_CANCEL     = 0x13

T_PING       = 0x20
T_PONG       = 0x21

T_BLOB       = 0x30
T_BYE        = 0x40

# --------------------------------------------------------------------- flags
F_SEALED = 0x01   # payload went through Sealer
F_FIN    = 0x02   # last blob chunk
F_ERR    = 0x04   # blob carried an error instead of data

TYPE_NAMES = {
    T_HELLO: "HELLO", T_CHALLENGE: "CHALLENGE", T_AUTH: "AUTH",
    T_AUTH_OK: "AUTH_OK", T_AUTH_FAIL: "AUTH_FAIL",
    T_REQ: "REQ", T_RES: "RES", T_EVT: "EVT", T_CANCEL: "CANCEL",
    T_PING: "PING", T_PONG: "PONG", T_BLOB: "BLOB", T_BYE: "BYE",
}


class ProtocolError(Exception):
    """Malformed or unexpected frame."""


class AuthError(Exception):
    """Handshake rejected."""


# --------------------------------------------------------------------- codec

def encode_frame(ftype, stream=0, payload=b"", flags=0):
    """Serialise one frame."""
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError("payload %d exceeds MAX_PAYLOAD" % len(payload))
    if not 0 <= stream <= 0xFFFF:
        raise ProtocolError("stream id out of range")
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    return HEADER.pack(MAGIC, ftype, flags, stream, len(payload), crc) + payload


def decode_header(buf):
    """Return (ftype, flags, stream, length, crc) or raise."""
    if len(buf) < HEADER_SIZE:
        raise ProtocolError("short header")
    magic, ftype, flags, stream, length, crc = HEADER.unpack_from(buf, 0)
    if magic != MAGIC:
        raise ProtocolError("bad magic %r (is the peer speaking CWP1?)" % (magic,))
    if length > MAX_PAYLOAD:
        raise ProtocolError("frame too large: %d" % length)
    return ftype, flags, stream, length, crc


def verify_payload(payload, crc):
    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
        raise ProtocolError("crc mismatch")


class Frame:
    __slots__ = ("type", "flags", "stream", "payload")

    def __init__(self, ftype, flags, stream, payload):
        self.type = ftype
        self.flags = flags
        self.stream = stream
        self.payload = payload

    def __repr__(self):
        return "<Frame %s stream=%d len=%d flags=0x%02x>" % (
            TYPE_NAMES.get(self.type, hex(self.type)), self.stream,
            len(self.payload), self.flags)

    @property
    def is_blob(self):
        return self.type == T_BLOB

    def json(self):
        return unpack_json(self.payload)


def pack_json(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def unpack_json(payload):
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError("bad json payload: %s" % exc)


# ----------------------------------------------------------------- transport

def recv_exact(sock, n):
    """Read exactly *n* bytes or raise EOFError."""
    chunks = []
    remaining = n
    while remaining:
        try:
            buf = sock.recv(remaining)
        except (ConnectionResetError, OSError):
            raise EOFError("connection reset")
        if not buf:
            raise EOFError("connection closed")
        chunks.append(buf)
        remaining -= len(buf)
    return b"".join(chunks)


class Reader:
    """Blocking frame reader bound to a socket."""

    def __init__(self, sock):
        self.sock = sock

    def read(self):
        head = recv_exact(self.sock, HEADER_SIZE)
        ftype, flags, stream, length, crc = decode_header(head)
        payload = recv_exact(self.sock, length) if length else b""
        verify_payload(payload, crc)
        return Frame(ftype, flags, stream, payload)


class Writer:
    """Serialised frame writer (safe for concurrent callers)."""

    def __init__(self, sock):
        self.sock = sock
        self._lock = threading.Lock()

    def write(self, ftype, stream=0, payload=b"", flags=0):
        data = encode_frame(ftype, stream, payload, flags)
        with self._lock:
            self.sock.sendall(data)

    def write_json(self, ftype, stream=0, obj=None, flags=0):
        self.write(ftype, stream, pack_json(obj if obj is not None else {}), flags)

    def write_frame(self, frame):
        with self._lock:
            self.sock.sendall(encode_frame(frame.type, frame.stream,
                                           frame.payload, frame.flags))


# --------------------------------------------------------------------- crypto

def _hmac(key, *parts):
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(part)
    return mac.digest()


class Sealer:
    """Encrypt-then-MAC frame payloads with an HMAC-SHA256 CTR keystream.

    Not a replacement for TLS against a determined attacker who can record the
    handshake, but it removes cleartext credentials/paths from a shared LAN and
    gives every frame an integrity tag, using nothing outside the stdlib.
    """

    TAG = 8
    __slots__ = ("key", "counter", "lock")

    def __init__(self, key):
        self.key = key
        self.counter = 0
        self.lock = threading.Lock()

    def _keystream(self, ctr, length):
        out = bytearray()
        block = 0
        while len(out) < length:
            out += _hmac(self.key, b"K", ctr.to_bytes(8, "big"),
                         block.to_bytes(4, "big"))
            block += 1
        return bytes(out[:length])

    def seal(self, plaintext):
        with self.lock:
            self.counter += 1
            ctr = self.counter
        ks = self._keystream(ctr, len(plaintext))
        ct = bytes(a ^ b for a, b in zip(plaintext, ks)) if plaintext else b""
        tag = _hmac(self.key, b"T", ctr.to_bytes(8, "big"), ct)[:self.TAG]
        return ct + tag

    def open(self, sealed):
        if len(sealed) < self.TAG:
            raise ProtocolError("sealed payload too short")
        ct, tag = sealed[:-self.TAG], sealed[-self.TAG:]
        with self.lock:
            self.counter += 1
            ctr = self.counter
        expect = _hmac(self.key, b"T", ctr.to_bytes(8, "big"), ct)[:self.TAG]
        if not hmac.compare_digest(tag, expect):
            raise ProtocolError("bad frame tag (tampered or desynchronised)")
        ks = self._keystream(ctr, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks)) if ct else b""


# ------------------------------------------------------------------ handshake

def client_proof(key, nonce_c, nonce_s):
    return _hmac(key, b"CWP1/AUTH/c", nonce_c, nonce_s)


def server_proof(key, nonce_c, nonce_s):
    return _hmac(key, b"CWP1/AUTH/s", nonce_s, nonce_c)


def session_key(key, nonce_c, nonce_s):
    return _hmac(key, b"CWP1/SESSION", nonce_c, nonce_s)


def new_nonce():
    return os.urandom(16)


def parse_key(text):
    """Accept 64 hex chars, 32-byte raw, or ``cw1_``-prefixed hex."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "ignore")
    text = (text or "").strip()
    if text.startswith("cw1_"):
        text = text[4:]
    text = text.replace("-", "").replace(" ", "")
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise AuthError("key is not valid hex")
    if len(raw) < 16:
        raise AuthError("key must be at least 16 bytes (32 hex chars)")
    return raw


def format_key(raw):
    return "cw1_" + raw.hex()


def gen_key(nbytes=32):
    return os.urandom(nbytes)


# ------------------------------------------------------------------- constants

class ErrorCode:
    BAD_REQUEST   = "bad_request"
    NOT_FOUND     = "not_found"
    DENIED        = "denied"
    TIMEOUT       = "timeout"
    INTERNAL      = "internal"
    UNSUPPORTED   = "unsupported"
    TOO_LARGE     = "too_large"
    CANCELLED     = "cancelled"
    AUTH          = "auth_failed"
