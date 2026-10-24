# CrossWire

Let an AI agent running on one machine drive another machine on the same LAN.
No SSH, no HTTP, no dependencies.

Windows box runs the agent (DeepSeek Harness, Claude, Codex — anything that
speaks MCP over stdio). Linux box runs a small daemon. The agent gets shell,
files, processes, services and network on the Linux box.

```
you (Windows) ── MCP stdio ──> crosswire ──TCP──> crosswire_agentd (Linux)
```

---

## Why this exists

I had `winremote-deploy-kit` before this: a deployment wrapper around
`winremote-mcp`, plus a relay to paper over the `Session not found` problem
that streamable-HTTP MCP has when the server restarts. The relay worked, but
it was fixing a symptom of the transport choice.

So this one doesn't wrap anything. Own wire protocol:

- one long-lived TCP connection, 16-byte binary frame header with CRC32
- stream ids in the frame, so requests really run in parallel — a 40-minute
  build doesn't block the `fs_read` you issue two seconds later
- **no session object on the server.** The connection is the session. Process
  dies, socket dies, client redials and re-authenticates. There is no
  "connected but every call fails" state to get stuck in.

You pay for maintaining a protocol. You stop paying for the class of bugs above.

---

## Install

**Windows (the machine with the agent)**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1
```

**Linux (the machine being controlled)**

```bash
sudo ./install-agent.sh --allow-sudo --allow-pkg
```

It copies `crosswire_agentd.py` to `/opt/crosswire`, generates
`/etc/crosswire/agent.key`, writes a systemd unit, and tries to open the
firewall port. Then it prints the address and key.

**Back on Windows**

```bash
python cw.py add sub 192.168.1.50 --key cw1_...
python cw.py doctor
python cw.py sh "uname -a"
```

`sub` is just an alias. Use whatever you like.

---

## Wire it into the agent

DeepSeek Harness: `python cw.py dsh-install` appends a
`@deepseek-ai/dsh-mcp-client` entry to every profile under `~/.dsh/profiles`.

Anything else: `python cw.py mcp-config --client claude` (or `codex`) prints
the block to paste.

---

## 30 tools

`hosts` `host_info` `host_probe` · `run` `run_script` `job_list` `job_poll`
`job_kill` · `tty_open` `tty_write` `tty_read` `tty_close` · `fs_ls` `fs_read`
`fs_write` `fs_edit` `fs_stat` `fs_find` `fs_grep` `fs_manage` `fs_pull`
`fs_push` `fs_tail` `fs_hash` · `proc_list` `proc_kill` `svc` `net` `pkg`
`power`

Every tool takes an optional `host` argument. `fs_pull` copies a remote file
onto local disk and returns the local path — use it for binaries and big logs
instead of stuffing base64 through the conversation.

---

## Tests

```bash
python tests/test_protocol.py   # 18  framing, crypto, client/agent parity
python tests/e2e.py             # 27  real daemon, real client, loopback
python tests/test_mcp.py        # 13  JSON-RPC handshake, tools/list, tools/call
```

58 total. `e2e.py` covers handshake, wrong-key rejection, exit codes, timeout
to job promotion, PTY, the whole file surface, a 300 KB binary round trip,
output truncation, `allow_root` enforcement, 12 concurrent requests and
transparent reconnect.

---

## Security, plainly

This hands out a shell. Treat it that way.

- the key is the whole credential — `/etc/crosswire/agent.key` and
  `~/.crosswire/` on the client side
- default is full filesystem access; narrow it with `--allow-root <dir>`
- `--allow-sudo`, `--allow-pkg`, `--allow-power` are off unless you turn them on
- **do not port-forward this to the internet.** Cross-network means WireGuard
  or Tailscale, plus `--allow-cidr`
- payloads are sealed with an HMAC-SHA256 keystream + truncated tag, which
  keeps commands and paths out of plain sight on a shared LAN. It is not TLS
  and it is not meant to survive a motivated attacker.

---

## Known limits

- agentd on Windows works but `tty` is a pipe, not a PTY, and `proc_list`
  degrades. Windows is for testing the protocol; production goes on Linux.
- `proc_list` cpu% is a delta between calls, so the first call after connecting
  usually reads 0.
- `fs_grep` is a Python file walk. Tens of thousands of files and you should
  just `run "grep -r"` instead.
- no compression, no automatic heartbeat-redial (keepalive yes, redial on next
  request only).

---

MIT.
