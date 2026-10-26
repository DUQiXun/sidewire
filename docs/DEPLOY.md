# Deployment

## Network

Both machines need to be on the same layer-2 network, or at least able to reach each other's ports directly. On the Linux side:

```bash
ip -4 addr | grep inet
```

Note the `192.168.x.x` or `10.x.x.x` address. Then from Windows:

```powershell
Test-NetConnection 192.168.1.50 -Port 7900
```

`TcpTestSucceeded : True` or it isn't working. When it isn't, check in this order: is agentd running, is the firewall open, are the two machines on different subnets with no route between them.

---

## Linux side: install agentd

### Option 1: the script

```bash
scp -r agent/ user@192.168.1.50:~/
ssh user@192.168.1.50
cd ~/agent && sudo ./install-agent.sh --allow-sudo --allow-pkg
```

No scp is fine too. USB stick, `python3 -m http.server`, whatever. It's one `.py` and two small files.

The script prints:

```
  address  : 192.168.1.50
  port     : 7900
  key      : sw1_9f3a...e21c
```

### Option 2: by hand

```bash
sudo mkdir -p /opt/sidewire /etc/sidewire
sudo install -m 755 sidewire_agentd.py /opt/sidewire/
sudo python3 /opt/sidewire/sidewire_agentd.py --keygen --out /etc/sidewire/agent.key
sudo chmod 600 /etc/sidewire/agent.key
```

Run it in the foreground once to watch it come up:

```bash
sudo python3 /opt/sidewire/sidewire_agentd.py \
     --key-file /etc/sidewire/agent.key --port 7900 --verbose
```

You should see:

```
[info] sidewire agentd 1.0.0 starting (pid 1234, python 3.11.6)
[info] agentd listening on 0.0.0.0:7900 (crypto=on, allow=any)
```

Ctrl-C, then turn it into a service:

```bash
sudo python3 /opt/sidewire/sidewire_agentd.py --print-unit \
  | sudo tee /etc/systemd/system/sidewire-agentd.service
sudo systemctl daemon-reload
sudo systemctl enable --now sidewire-agentd
sudo systemctl status sidewire-agentd
```

Firewall:

```bash
sudo ufw allow 7900/tcp
# or
sudo firewall-cmd --permanent --add-port=7900/tcp && sudo firewall-cmd --reload
```

### Flags

| Flag | What it does |
|---|---|
| `--bind` | Listen address, `0.0.0.0` by default. `127.0.0.1` for loopback only |
| `--port` | Defaults to 7900 |
| `--key-file` | Key file, mode 600 |
| `--allow-cidr` | Only accept connections from these ranges. Repeatable. **Set this**, e.g. `--allow-cidr 192.168.1.0/24` |
| `--allow-root` | Filesystem roots, repeatable, defaults to `/`. Use it to narrow things down |
| `--deny-root` | Explicitly refused paths. Beats `--allow-root` |
| `--allow-sudo` | Enables `run(sudo=true)` |
| `--allow-pkg` | Enables installing and removing packages |
| `--allow-power` | Enables reboot and shutdown |
| `--log` | Extra log file. Usually unnecessary under systemd |
| `--workdir` | Default working directory. The launching user's home by default |
| `--no-crypto` | Disables payload sealing. Only for packet-capture debugging |
| `--print-unit` | Print a systemd unit and exit |

---

## Windows side: install the client

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1
```

Goes to `%LOCALAPPDATA%\sidewire` by default. Somewhere else: `-InstallDir D:\tools\sidewire`.

Or skip installing and run `python sw.py ...` straight out of the source directory. `sw.py` puts itself on `sys.path`.

### Register a target

```bash
python sw.py add sub 192.168.1.50 --key sw1_9f3a...e21c --default --note "build box"
```

`--key` and `--key-file` are mutually exclusive. You can also skip hosts.json and use an environment variable:

```powershell
$env:SIDEWIRE_KEY = "sw1_..."
```

Precedence: `key` in hosts.json, then `SIDEWIRE_KEY`, then `key_file` in hosts.json, then `~/.sidewire/key`.

### Check it

```bash
python sw.py doctor
```

```
config
  home        C:\Users\you\.sidewire
  hosts.json  C:\Users\you\.sidewire\hosts.json ok
  hosts       1 configured, default=sub
python
  3.12.10 on Windows-11-...
hosts
  sub      online 3ms  Ubuntu 24.04.1 LTS  agent=1.0.0  sudo=True pkg=True power=False

all good
```

---

## Wiring it into an agent

### DeepSeek Harness

```bash
python sw.py dsh-install
```

It appends an `mcp-sidewire` entry to both places DSH reads from:

- `~/.dsh/profiles/*/cordis.patch.yml`, which the `dsh` command line uses
- `~/.dsh/.agent-presets/*/agent.cordis.yml`, which the desktop app uses

Existing entries are skipped, so running it twice is harmless. Restart DSH afterwards, and note that the desktop app only re-reads presets at startup, so close it fully rather than minimising to the tray.

Just one profile, or just one preset:

```bash
python sw.py dsh-install --profile desktop
python sw.py dsh-install --preset aaaa
python sw.py dsh-install --no-preset
```

### Claude Desktop

```bash
python sw.py mcp-config --client claude
```

Paste the output into `claude_desktop_config.json` and restart the client.

### Codex

```bash
python sw.py mcp-config --client codex
```

---

## Several Linux boxes

```bash
python sw.py add build 192.168.1.50 --key sw1_aaa...
python sw.py add gpu   192.168.1.51 --key sw1_bbb...
python sw.py add nas   192.168.1.60 --key sw1_ccc... --default
```

The agent calls `hosts` to see the list, then passes `host: "gpu"` to any tool.

Aliases can be anything, non-ASCII included (JSON is UTF-8). Keep them short, every tool call pays for the characters.

---

## A Windows target, reachable only through Radmin LAN

Sometimes the other machine is somewhere you can't touch, behind a NAT you don't
control, and someone else uses it too. Radmin LAN (Radmin VPN) handles the network
part: both machines join a named virtual network and get `26.x.x.x` addresses.
agentd then binds to that address and nothing else.

Run `agent\run-on-windows.bat` on the target. It is deliberately a console window,
not a service:

- it finds the `26.x.x.x` address and binds to it
- it restricts the allowlist to `26.0.0.0/8`
- it prints the `sw.py add` line to run on your side
- **closing the window stops it, and nothing is left behind**

That last point is the reason for the design. The machine may belong to someone
else, or be shared. When they close Radmin VPN, the `26.x.x.x` interface goes away
and the listener goes with it, so the connection is not merely refused, it has
nowhere to arrive. If they close the agent window, even that is gone. There is no
service, no scheduled task, no autostart entry to hunt down.

If you want it permanent, don't use the `.bat`; install a service instead and
accept that it will be running whether or not anyone is using the machine. Pick one
or the other, not both.

```
target:  run-on-windows.bat  ->  binds 26.101.253.132:7900
you:     python sw.py add far 26.101.253.132 --key sw1_...
```

Note the Windows agent has a fake `tty` (a pipe, not a PTY) and a degraded
`proc_list`, same as running it anywhere on Windows. See Known issues in the README.

---

## Troubleshooting

**`cannot reach 192.168.1.50:7900 (timed out)`**
Machine is off, agentd isn't running, or a firewall. On the Linux side, `ss -tlnp | grep 7900`. It should say `0.0.0.0:7900`; `127.0.0.1:7900` means `--bind` is wrong.

**`server rejected the key`**
The two keys differ. `sudo cat /etc/sidewire/agent.key` and compare against `~/.sidewire/hosts.json`. The `sw1_` prefix is optional on input, it gets stripped during parsing.

**`denied: path outside allowed roots`**
agentd was started with `--allow-root` and the path is outside it. Change the flag or use a path inside it.

**`denied: sudo is disabled by the agent policy`**
No `--allow-sudo`, and sudo isn't NOPASSWD either. Either add the flag or configure NOPASSWD for that user.

**Connected, but every tool returns `connection_lost`**
`journalctl -u sidewire-agentd -n 50`. If it says `bad frame tag`, the two sides are running different versions — the protocol changed at some point, so bring both up to date.

**`sys.info` returns an empty `ipv4`**
No `/sys/class/net` and no `ip` command, which is normal inside a minimal container. Nothing else breaks, though `net` may be degraded too.

**Non-ASCII text is mangled in a PTY**
The agentd shell has no `LANG`. Add `Environment=LANG=C.UTF-8` to the unit, or `export LANG=C.UTF-8` after `tty_open`.
