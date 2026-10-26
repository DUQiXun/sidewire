# SideWire

Drive a Linux box from an AI agent running on Windows. Same LAN is enough. No SSH, nothing to install on the Linux side.

The Windows machine has the agent (DeepSeek Harness, Claude, Codex, doesn't matter). The Linux machine runs one Python file. After that the agent can run commands, read and write files, look at processes, restart services. Roughly like working locally.

```
you (Windows) -- MCP stdio --> sidewire -- TCP --> sidewire_agentd (Linux)
```

## Why another one

I had `winremote-deploy-kit` first. That one wrapped someone else's project: install a service, open a firewall port, add a relay to work around `Session not found`. It also only did Windows to Windows.

The awkward part was the base it sat on. Streamable HTTP keeps session state on the server. Restart the server and the `mcp-session-id` in the client's hand is stale, but the connection itself stays up. You end up with a client that looks connected and fails every tool call. The relay existed to patch that.

So the problem came from the transport, not from the code around it. This time I wrote the wire protocol.

- One long-lived TCP connection, my own binary frames. 16-byte header, CRC32 over the payload.
- Every frame carries a stream id, so requests really do run in parallel. A 40-minute compile doesn't block the `fs_read` behind it.
- No sessions on the server. The connection is the session. Kill the process and the socket dies; the client reconnects and re-authenticates. There's no in-between state to get stuck in.

The cost is that I maintain a protocol now. The benefit is that the above stops happening.

## Install

Three steps. Pretend the Linux box is `192.168.1.50`.

**1. Windows side**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1
```

It finds Python, copies things into `%LOCALAPPDATA%\sidewire`, makes a key, then asks whether it should register itself into DeepSeek Harness. Pass `-NoDsh` to skip that question, or `-InstallDir D:\tools\sidewire` if you don't want it under AppData.

**2. Linux side**

Copy the `agent/` directory across. USB stick, scp, whatever you have.

```bash
sudo ./install-agent.sh --allow-sudo --allow-pkg
```

Four things happen: `sidewire_agentd.py` lands in `/opt/sidewire`, a key is generated at `/etc/sidewire/agent.key`, a systemd unit gets written, and it tries to open the firewall (ufw or firewalld, gives up quietly if it finds neither).

It prints the key and address when it finishes:

```
  address  : 192.168.1.50
  port     : 7900
  key      : sw1_9f3a...e21c
```

**3. Back on Windows**

```bash
python sw.py add sub 192.168.1.50 --key sw1_9f3a...e21c --default
python sw.py doctor
```

`sub` is just an alias. Call it `lab`, `spare`, `nas`, whatever. `doctor` walks config, key, connectivity and agent version, and tells you which one broke.

Then try it:

```bash
python sw.py sh "uname -a && df -h"
```

## Telling the agent about it

For DeepSeek Harness:

```bash
python sw.py dsh-install
```

One warning, because this cost me an evening: DSH keeps MCP config in **two different places**, and which one matters depends on how you start it.

| How you start DSH | File it reads |
|---|---|
| `dsh` from a terminal | `~/.dsh/profiles/<name>/cordis.patch.yml` |
| the desktop app | `~/.dsh/.agent-presets/<name>/agent.cordis.yml` |

`dsh-install` writes both now. Earlier versions only did the first, which meant the desktop app silently ignored the whole thing — no error, nothing in the log, the tools just never showed up. `--preset <name>` targets one preset, `--no-preset` stays on profiles only.

The desktop app reads presets once at startup, so close it properly and reopen. Quitting to the tray doesn't count.

For Claude Desktop, Cursor and anything else that takes a JSON block:

```bash
python sw.py mcp-config --client claude
```

Codex uses `--client codex`. It prints the block, you paste it in.

## The 30 tools

Names are short on purpose. Every one takes an optional `host` argument, which is how you switch between machines.

**Which machines**: `hosts`, `host_info`, `host_probe` (latency)

**Commands**: `run`, `run_script` (writes a temp file and runs it, so you skip quote hell), `job_list`, `job_poll`, `job_kill`

**Interactive**: `tty_open`, `tty_write`, `tty_read`, `tty_close`. Real PTY. You can ssh onward to a third machine or drive an interactive installer.

**Files**: `fs_ls`, `fs_read`, `fs_write`, `fs_edit` (patch one spot, leave the rest alone), `fs_stat`, `fs_find`, `fs_grep` (search on the target instead of pulling the tree over), `fs_manage` (mkdir/rm/mv/cp/chmod/chown/symlink/truncate in one), `fs_pull`, `fs_push`, `fs_tail`, `fs_hash`

**System**: `proc_list`, `proc_kill`, `svc` (systemctl, openrc or sysv, detected), `net` (interfaces, listening ports, reachability, DNS), `pkg` (apt, dnf, pacman, zypper, apk, detected), `power`

`fs_pull` deserves a note. It downloads the file to local disk and hands back a local path, so the agent can use its own file tools on it. Binaries, images, a 50 MB log — all of that goes this way instead of base64 into the context window.

## Design choices, briefly

**Not HTTP.** Tried it. HTTP needs either long polling or SSE, and multiplexing over one connection means inventing a lot of semantics. "Connection fine, session dead" is a state that exists by construction. Frames on raw TCP are simpler: if something is wrong the connection breaks and you reconnect.

**Not plain SSH.** SSH is right there and the agent could just use it, but a few things get annoying. Credential handling, a new session per exec (slow), assembling output and exit codes by hand, timeouts and process groups. Plenty of Windows boxes also ship without an ssh client. All solvable, but solving them is most of what I wrote here anyway.

**Crypto.** No TLS, because I didn't want an openssl dependency just for a self-signed cert. It's assembled from stdlib: HMAC-SHA256 in counter mode as the keystream, an 8-byte truncated tag, encrypt-then-MAC. Enough to stop someone casually sniffing the LAN from reading your paths and commands. Not enough for anyone actually trying. Anything off-LAN should go over WireGuard or Tailscale, don't count on this.

**Frame ordering.** Worth remembering: seal and write have to be one atomic operation. The first version split them, and 12 concurrent requests were enough to put the counter out of order — the peer answered `bad frame tag`. Both sides now hold one lock across encrypt-and-send.

## Tests

```bash
python tests/e2e.py             # 27
python tests/test_protocol.py   # 18
python tests/test_mcp.py        # 13
python tests/test_dsh.py        #  7
```

65 total.

`e2e.py` starts a real agentd and hits it with a real client. Handshake, wrong key rejected, command execution, exit codes, timeout turning into a job, PTY, the whole file family, a 300 KB binary round trip, output truncation, `allow_root` refusing an escape, 12 concurrent requests, reconnect after a drop.

`test_protocol.py` covers frame encode/decode, CRC, keystream, tag tampering, counter reordering, plus a byte-for-byte comparison of the two protocol implementations. agentd is a single file, so it carries its own copy of the protocol code, and that test is what keeps the copies honest.

`test_dsh.py` parses the generated DSH YAML back in both shapes. Wrong nesting still produces a file that looks fine and gets ignored, which is the failure mode worth testing for.

Numbers from this machine: `sys.ping` around 0.3 ms, file read/write 1-5 ms, 300 KB push and pull 90 ms. Command execution on Linux is basically the command's own time. On Windows every exec spawns a `cmd.exe`, so add about 120 ms. That's the OS, not the protocol.

## Permissions, and things not to do

This hands over a shell. Think about it while installing, not after.

- **The key is everything.** `/etc/sidewire/agent.key` and the copy in `~/.sidewire/` on the Windows side. Leaking either is equivalent to losing the machine.
- The default is `--allow-root /`, meaning the whole filesystem is readable and writable. Narrow it with `--allow-root /home/you/project`; anything outside comes back `denied`.
- `--allow-sudo`, `--allow-pkg` and `--allow-power` are all off by default. `power` also wants a `confirm` argument that has to match the action name exactly.
- **Don't port-forward this to the internet.** If you need it across networks, WireGuard or Tailscale plus `--allow-cidr 10.0.0.0/24`.
- Every request goes to the audit log (address, method, duration, result, argument summary). `journalctl -u sidewire-agentd`.

## Known issues

- Running agentd on Windows gives you a fake `tty` (a pipe, not a PTY) and a degraded `proc_list`. Windows is only there so I could test the protocol. Use Linux for real.
- `proc_list` CPU% is a delta between two calls, so the first call after connecting usually reports zeros.
- `fs_grep` walks files in pure Python. Tens of thousands of small files will be slow. If it matters, have the agent `run "grep -r"` instead.
- No compression. Text goes over as-is. The LAN is fast enough that I didn't bother.
- Reconnect happens on the next request, not proactively. There's a keepalive ping but it doesn't redial on its own.
- If the target is a shared machine and the other person should be able to cut you off, don't install a service. Use `agent/run-on-windows.bat`, which binds only to the Radmin LAN address and dies when its window closes. `docs/DEPLOY.md` explains the trade-off.

## Layout

```
sidewire/            client (MCP server + CLI)
  protocol.py         frame format, sealing, handshake
  client.py           connection, multiplexing, file transfer
  config.py           ~/.sidewire/hosts.json
  cli.py              command line
  mcp/server.py       JSON-RPC over stdio
  mcp/tools.py        the 30 tool definitions and handlers
agent/
  sidewire_agentd.py single-file daemon, stdlib only, reads /proc directly
  install-agent.sh    one-shot installer (Linux)
  run-on-windows.bat  foreground launcher for a Windows target, no service
sw.py                 launcher, no install needed
docs/                 protocol, deployment, security, agent notes
tests/                65 tests
```

agentd is a single file on purpose. Copy one `.py` over and it runs. No dependencies, no virtualenv, no `pip install`. The price is that the protocol code exists twice, once in the client and once in agentd, and `test_protocol.py` exists to keep the two identical.

## License

MIT.

The name is arbitrary. Wire is the thing between two machines, cross is going across it. Rename it if you don't like it, nothing is hardcoded.
