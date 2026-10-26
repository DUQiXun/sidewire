# Wire protocol (CWP/1)

This is the whole protocol. If you want to write a client in another language,
this file plus `sidewire/protocol.py` is all you need.

## 1. Frame

Every message, in both directions, is:

```
 offset  size  field
 ------  ----  -----------------------------------------------------------
   0      4    magic      "CWP1"
   4      1    type       see §2
   5      1    flags      see §3
   6      2    stream     uint16, big endian. 0 = connection level
   8      4    length     uint32, big endian, payload byte count
  12      4    crc32      uint32, big endian, zlib.crc32(payload)
  16      N    payload
```

Hard limits: payload ≤ 1 MiB (`MAX_PAYLOAD`). Larger things are chunked, see §6.

`stream` is the multiplexing key. A response frame carries the same `stream`
value as the request it answers, so an arbitrary number of calls can be in
flight at once on one socket. Stream 0 is reserved for connection-level frames
(HELLO/CHALLENGE/AUTH/PING).

CRC is checked before anything else touches the payload. A mismatch is fatal
for the connection — we do not try to resynchronise, because a wrong length
field would mean reading garbage forever.

## 2. Types

| code | name | direction | payload |
|------|------|-----------|---------|
| 0x01 | HELLO | C→S | JSON `{v, nonce, client}` |
| 0x02 | CHALLENGE | S→C | JSON `{v, nonce, host, crypto, time}` |
| 0x03 | AUTH | C→S | JSON `{proof, crypto, client}` |
| 0x04 | AUTH_OK | S→C | JSON `{proof, host, os, agent, pid, caps}` |
| 0x05 | AUTH_FAIL | S→C | JSON `{error}` |
| 0x10 | REQ | C→S | JSON `{id, m, p}` |
| 0x11 | RES | S→C | JSON `{id, ok, r}` or `{id, ok:false, e}` |
| 0x12 | EVT | S→C | JSON, keyed by `k` |
| 0x13 | CANCEL | C→S | JSON `{job_id}` |
| 0x20 | PING | both | JSON `{t}` |
| 0x21 | PONG | both | JSON `{t}` |
| 0x30 | BLOB | both | raw bytes |
| 0x40 | BYE | both | empty |

## 3. Flags

| bit | name | meaning |
|-----|------|---------|
| 0x01 | SEALED | payload went through the sealer (§5) |
| 0x02 | FIN | last BLOB of a transfer |
| 0x04 | ERR | BLOB aborted |

`SEALED` is set independently on every frame, so a peer can tell whether a
given payload is ciphertext without keeping extra state.

## 4. Handshake

```
C                                    S
|-- HELLO {v:1, nonce:nc, client} -->|
|<-- CHALLENGE {v, nonce:ns, ...} ---|
|-- AUTH {proof:pc, crypto} -------->|
|<-- AUTH_OK {proof:ps, caps, ...} --|
|====== everything below is sealed ==|
```

Both nonces are 16 random bytes.

```
pc = HMAC-SHA256(key, "CWP1/AUTH/c" || nc || ns)
ps = HMAC-SHA256(key, "CWP1/AUTH/s" || ns || nc)
session_key = HMAC-SHA256(key, "CWP1/SESSION" || nc || ns)
```

The client checks `ps` before sending anything else, so a server that does not
hold the key cannot get the client to talk to it. `nc` is fresh per connection,
so an old handshake cannot be replayed.

`caps` in AUTH_OK is the sorted list of methods the agent implements. A client
can use it to fail fast instead of discovering missing features one call at a
time.

If `crypto` is `"none"` on either side, sealing is skipped for the whole
connection. There is no per-frame negotiation.

## 5. Sealing

Encrypt-then-MAC, stdlib only.

```
tx_counter starts at 0, increments once per sealed frame

keystream(ctr, n) = HMAC(key, "K" || u64(ctr) || u32(block)) for block = 0,1,2,…
                    concatenated, truncated to n

ct  = plaintext XOR keystream(ctr, len(plaintext))
tag = HMAC(session_key, "T" || u64(ctr) || ct)[0:8]
payload = ct || tag
```

Receiving is the mirror image. A bad tag raises immediately and the connection
is dropped.

The counter is per direction and shared by every stream, which means **sealing
and sending must happen as one atomic step**. Two threads that seal then send
separately will interleave and the peer will reject the frame — this is not
theoretical, it happened during development with 12 concurrent calls. Both
implementations hold one lock across "seal + write".

Known weakness: a truncated 8-byte tag and a handshake with no ephemeral key
exchange means a recorded session plus the shared key is decryptable. That is
an accepted trade for zero dependencies on a LAN. Use WireGuard if you need
real transport security.

## 6. Blob transfer

BLOB frames are raw bytes on a stream id chosen by the **client**, so the
receiver can register its sink before the request goes out (otherwise the
first chunk can arrive before the sender's reply is processed — also a bug
that actually happened).

**Download (client pulls)**

```
C: REQ  {id, m:"fs.pull", p:{path, sid}}
S: RES  {id, ok:true, r:{sid, path, size, sha256}}
S: BLOB sid=<sid> …            (64 KiB chunks)
S: EVT  sid=<sid> {k:"blob_done", ok:true, sha256, bytes}
```

**Upload (client pushes)**

```
C: REQ  {id, m:"fs.push", p:{path, size, sha256, sid}}
S: RES  {id, ok:true, r:{sid, path, ready:true}}
C: BLOB sid=<sid> …  with FIN on the last frame (payload empty)
S: EVT  sid=<sid> {k:"blob_done", ok:true, bytes, sha256}
```

The receiver writes to `<path>.sw-part` and `os.replace()`s it into place only
after size and sha256 match. A failed transfer leaves no half file behind.

## 7. Request / response

```json
{"id": 7, "m": "exec.run", "p": {"command": "df -h", "timeout": 10}}
{"id": 7, "ok": true, "r": {"exit": 0, "stdout": "...", "stderr": ""}}
{"id": 7, "ok": false, "e": {"code": "denied", "msg": "path outside allowed roots"}}
```

`id` is a client-chosen integer, unique per connection. Responses may arrive
out of order.

Methods are `namespace.verb`: `sys.info`, `exec.run`, `job.poll`, `tty.write`,
`fs.read`, `proc.list`, `svc.action`, `net.info`, `pkg.action`.

Error codes: `bad_request`, `not_found`, `denied`, `timeout`, `internal`,
`unsupported`, `too_large`, `cancelled`.

`denied` specifically means the agent's own policy refused (path outside
`allow_root`, or a feature started without its flag). A client should not retry
those with different arguments; it should tell the user to change the config.

## 8. Jobs and offsets

`exec.run` with `background:true` (or a `timeout` that expires first) returns
`{job_id, state:"running"}`. Output is kept in a per-job ring buffer addressed
by absolute byte offset:

```json
{"id": 9, "m": "job.poll", "p": {"job_id": "j3", "stdout_offset": 1024, "wait": 2}}
→ {"r": {"stdout": "...", "stdout_offset": 2048, "lost": 0, "state": "running"}}
```

`lost > 0` means the reader fell behind the ring and bytes were dropped. That
is reported rather than hidden.

## 9. Versioning

`v` is the protocol major version and currently 1. Any mismatch fails the
handshake with AUTH_FAIL and a human-readable reason. There is no minor
version — new methods are additive and announced through `caps`.
