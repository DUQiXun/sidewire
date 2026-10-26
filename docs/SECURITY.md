# Security model

Plainly: **this hands over a shell on the other machine.** Think about it before installing, not after.

## Where the trust boundary is

```
[ agent ]--stdio--[ sidewire ]--TCP + key--[ agentd ]--root/sudo--[ system ]
         (1)                (2)            (3)        (4)
```

1. The agent is fully trusted. It can call any tool, nothing asks twice.
2. The client holds the key and can reach any target it's been configured with.
3. This is the only segment worth defending. Someone on the LAN sniffing, someone scanning ports.
4. agentd's process privileges are the ceiling on what anything above can do.

**Segment 3 is the only real boundary.** Break it and every policy behind it is decoration.

## The key

One 32-byte shared secret, identical on both sides. It is the entire credential.

- Linux: `/etc/sidewire/agent.key`, mode 600, root only
- Windows: the `key` field in `~/.sidewire/hosts.json`, or `~/.sidewire/key`, mode 600
- `SIDEWIRE_KEY` in the environment takes precedence, which is handy for CI

Leaking it means that machine is fully taken over. So:

- Don't commit it. It's in `.gitignore` already.
- Don't paste it into chat logs.
- Don't reuse one key across machines. It works, but it widens the blast radius.
- To rotate: `--keygen` again on the Linux side, `sidewire add` again on Windows. There's no hot reload, so agentd needs a restart.

## Transport

The handshake is an HMAC challenge-response, verified both ways:

- The client proves it knows the key (`client_proof`)
- The server proves it too (`server_proof`), so a fake server can't fool a real client
- Fresh nonce per connection, so an old handshake can't be replayed

After that, everything is sealed: HMAC-SHA256 in counter mode as the keystream, an 8-byte truncated tag, encrypt-then-MAC.

**What it buys you**: someone casually sniffing the LAN can't see which commands ran, which paths were touched, or what was transferred. Change a single byte anywhere and the tag catches it.

**What it doesn't**:

- It isn't TLS. No forward secrecy. Anyone who gets the key and also recorded the handshake can decrypt past traffic.
- An 8-byte tag is shorter than the usual 16. Collision odds are theoretically higher. In practice 2^-64 is fine.
- No replay window. Nonces are random and the server keeps no history, so replaying a whole connection is theoretically possible. Doing that means hijacking a live TCP session, at which point the attacker has better options.

**If you actually need security**: put it inside WireGuard or Tailscale. That's also the only recommendation for anything crossing networks.

## agentd policy switches

Off by default, opt in explicitly:

| Switch | What it unlocks | Advice |
|---|---|---|
| (none) | Read and write the whole filesystem, run any command, see processes, manage services | At minimum narrow it with `--allow-root` |
| `--allow-sudo` | `run(sudo=true)` for privilege escalation | Only when you really need package installs or system changes |
| `--allow-pkg` | Install and remove packages | Same |
| `--allow-power` | Reboot, shutdown, suspend | Wants a `confirm` argument, still dangerous |

`--allow-root` can be given several times and the roots are unioned. Paths are `realpath`'d before comparison, so `../` traversal and symlinks don't get around it:

```
--allow-root /home/deploy/app
-> fs_read("/home/deploy/app/../../../etc/shadow")  ->  denied
```

`--allow-cidr` is a network-layer allowlist. Checked immediately after accept; anything outside the range is dropped before the handshake even starts.

## Audit

Every request writes one line:

```
2026-10-25 03:02:13 [audit] 192.168.1.20 exec.run 190ms ok=True | {"command": "systemctl restart nginx"}
```

Source address, method, duration, result, argument summary with each value truncated to 120 characters. Goes to stderr, which under systemd means journald:

```bash
journalctl -u sidewire-agentd | grep audit
```

The argument summary is a summary, not the payload. What `fs_write` writes does not end up in the log. If you need that, set `--log` and do your own rotation.

## Don't

- **Port-forward this to the internet.** Not once. The protocol wasn't designed for it and being scanned means being taken over.
- Put the key in a Dockerfile, an image, or a public compose file.
- Run agentd on a shared machine without `--allow-cidr`.
- Use `--no-crypto` because it's easier. All it does is turn encryption off, and on a LAN you can't measure the difference anyway.

## If something goes wrong

```bash
sudo systemctl stop sidewire-agentd
sudo systemctl disable sidewire-agentd
```

Then do the normal intrusion routine: journald, `last`, look for crontabs and systemd units that weren't there before.

Rotating the key is not enough on its own. The attacker is already inside. A new key locks the door with them still in the room.
