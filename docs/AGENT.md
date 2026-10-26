# Notes for the agent

This one is for whichever side is doing the work. Humans can stop at the README.

---

## 1. Find out what you're talking to first

The most common mistake with remote work is **assuming you're on the local machine**. So step one of any task:

```
hosts()
```

Returns the alias, address, whether it's reachable right now, and which one is the default. If you're not sure which machine the user means by "that box", ask with this instead of guessing.

Once you know the target:

```
host_info(host="sub")
```

Look at `hostname`, `os`, `user`, `is_root`, `allow_sudo`, `allow_pkg`, `allow_power`.

- `hostname` isn't what you expected → stop and ask, don't push on
- `allow_sudo: false` → don't try `run(sudo=true)`, it comes back `denied`. Tell the user first.
- `is_root: true` → everything from here on is root. Be more careful with anything destructive.

---

## 2. Every path is a path on that machine

`fs_read(path="/etc/nginx/nginx.conf")` reads the remote `/etc`, not yours. The one exception is the `local_path` that `fs_pull` returns — that one is on your machine and your own file tools can read it.

Confusing the two wastes a lot of turns.

---

## 3. Which tool for what

| You want to | Use | Not |
|---|---|---|
| run one command | `run` | — |
| run a script with quotes, newlines, variables | `run_script` | `run` (escaping will drive you mad) |
| run something slow | `run(timeout=…, background=true)` + `job_poll` | `run` and wait |
| keep a session alive (ssh, REPL, interactive installer) | `tty_*` | `run` |
| look at a file | `fs_read` | `run("cat …")` |
| look at the end of a file | `fs_tail` | `fs_read` on the whole thing |
| change one spot in a file | `fs_edit` | `fs_write` rewriting everything |
| find a file | `fs_find` | `run("find …")` |
| search contents | `fs_grep` | `run("grep -r …")` |
| grab a binary or a big file | `fs_pull` | `fs_read(binary=true)` |
| send a file over | `fs_push` | `fs_write(data_b64=…)` |
| see processes | `proc_list` | `run("ps aux")` |
| see ports | `net(action="sockets")` | `run("ss -tlnp")` |
| manage a service | `svc` | `run("systemctl …")` |

The right column isn't broken, it's just unnecessary. The left column returns structured data, which saves you a parse and a chance to get the parse wrong.

---

## 4. Traps worth knowing

**Output gets truncated.** `run` caps each stream at 60000 bytes by default and sets `truncated: {stdout: true}` when it cuts. That flag means you're not seeing everything — don't draw conclusions from a partial read. Pull the file with `fs_pull`, or use `fs_grep` to find the specific thing.

**A timeout is not a failure.** `run(timeout=30)` that runs long returns `state: "running"` plus a `job_id`, and the command keeps going. Either `job_poll(job_id, wait=5)` or `job_kill`. **Do not** just run it again, you'll end up with two.

**`job_poll` wants an offset.** Pass back the `stdout_offset` from last time to get only the new part. Without it you re-read from the start every time and burn tokens.

**The first `proc_list` reports zero CPU.** CPU% is a delta between two samples. Call it again a second or two later.

**`denied` is not a bug.** It means agentd's policy said no. Don't retry with a different path — tell the user which flag needs changing (`--allow-root`, `--allow-sudo`, `--allow-pkg` or `--allow-power`).

**`lost` above zero means dropped data.** Only appears in job and tty output, and it means you read too slowly and the ring buffer wrapped past you.

---

## 5. Recipes

**What is this machine**

```
run("uname -a; uptime; free -h; df -h /")
```

**Service is down**

```
svc(name="nginx", action="status")
svc(name="nginx", action="logs", lines=80)
svc(name="nginx", action="restart")
```

**Who's holding that port**

```
net(action="sockets", states=["LISTEN"], with_pid=true)
```

**Change a config value**

```
fs_read(path="/etc/foo/bar.conf")
fs_edit(path="/etc/foo/bar.conf", old="port = 8080", new="port = 9090", backup=true)
svc(name="foo", action="restart")
svc(name="foo", action="status")
```

**Install something**

```
pkg(action="search", packages=["redis-server"])
pkg(action="install", packages=["redis-server"], timeout=300)
```

**Ship a local build**

```
fs_push(local_path="C:\\build\\app.tar.gz", path="/opt/app/app.tar.gz")
run("cd /opt/app && tar xzf app.tar.gz && ./restart.sh")
```

**Pull a log back to look at it**

```
fs_pull(path="/var/log/app/error.log")
# then read local_path with your own file tools
```

**Get into an interactive shell**

```
tty_open()                                   -> tty_id
tty_write(tty_id, "sudo -i\n")               -> input
tty_read(tty_id, offset=0, wait=2)           -> output
tty_close(tty_id)
```

`\n` in `tty_write` is translated to a carriage return, so you don't need `\r\n`.

---

## 6. Destructive operations

Say what you're about to do, what it changes, and how to undo it, before doing any of these:

- `svc(action="stop"|"disable")`
- `pkg(action="remove"|"upgrade")`
- `proc_kill`
- `fs_manage(op="rm")`
- `fs_write` over an existing file
- `power` (kills the connection outright, always last)

`power` needs a `confirm` argument matching the action name exactly. That's deliberate — one extra word is one extra chance to think.

---

## 7. Splitting work between local and remote

- Local work uses local tools. Don't route it through the network for no reason.
- Remote work goes through sidewire. Don't try to reach its files with a local path.
- Moving data between the two: `fs_push` / `fs_pull`, never base64 in the conversation.
- Let the remote machine do its own computation where it can (`fs_grep`, `run("awk …")`). That's much faster than moving the data back and processing it here.
