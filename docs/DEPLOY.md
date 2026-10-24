# 部署

## 网络前提

两台机器在同一个二层网络里，或者至少能互相直连到端口。判断方法很简单，在副电脑上：

```bash
ip -4 addr | grep inet
```

记下 `192.168.x.x` 或 `10.x.x.x` 这种。然后从主电脑：

```powershell
Test-NetConnection 192.168.1.50 -Port 7900
```

`TcpTestSucceeded : True` 才算通。不通的话按这个顺序查：agentd 起没起 → 防火墙 → 是不是跨了网段（比如一个在 192.168.1.x 一个在 192.168.0.x 且没有路由）。

---

## 副电脑：装 agentd

### 方式一：脚本（推荐）

```bash
scp -r agent/ user@192.168.1.50:~/
ssh user@192.168.1.50
cd ~/agent && sudo ./install-agent.sh --allow-sudo --allow-pkg
```

没有 scp 也行，U 盘、`python3 -m http.server` 传、微信发文件都可以，就一个 `.py` 和两个附属文件。

脚本会打印：

```
  address  : 192.168.1.50
  port     : 7900
  key      : cw1_9f3a...e21c
```

### 方式二：手动

```bash
sudo mkdir -p /opt/crosswire /etc/crosswire
sudo install -m 755 crosswire_agentd.py /opt/crosswire/
sudo python3 /opt/crosswire/crosswire_agentd.py --keygen --out /etc/crosswire/agent.key
sudo chmod 600 /etc/crosswire/agent.key
```

先前台跑一次，看着它起来：

```bash
sudo python3 /opt/crosswire/crosswire_agentd.py \
     --key-file /etc/crosswire/agent.key --port 7900 --verbose
```

应该看到：

```
[info] crosswire agentd 1.0.0 starting (pid 1234, python 3.11.6)
[info] agentd listening on 0.0.0.0:7900 (crypto=on, allow=any)
```

然后 Ctrl-C，换成服务：

```bash
sudo python3 /opt/crosswire/crosswire_agentd.py --print-unit \
  | sudo tee /etc/systemd/system/crosswire-agentd.service
sudo systemctl daemon-reload
sudo systemctl enable --now crosswire-agentd
sudo systemctl status crosswire-agentd
```

防火墙：

```bash
sudo ufw allow 7900/tcp
# 或者
sudo firewall-cmd --permanent --add-port=7900/tcp && sudo firewall-cmd --reload
```

### 参数说明

| 参数 | 作用 |
|---|---|
| `--bind` | 监听地址，默认 `0.0.0.0`。只想本机回环就 `127.0.0.1` |
| `--port` | 默认 7900 |
| `--key-file` | 密钥文件，600 权限 |
| `--allow-cidr` | 只接受这些网段的连接，可重复。**强烈建议设**，比如 `--allow-cidr 192.168.1.0/24` |
| `--allow-root` | 文件系统根，可重复，默认 `/`。收窄权限用 |
| `--deny-root` | 显式拒绝的路径，优先级高于 allow-root |
| `--allow-sudo` | 允许 `run(sudo=true)` |
| `--allow-pkg` | 允许装/卸软件包 |
| `--allow-power` | 允许重启关机 |
| `--log` | 额外写一份日志到文件，systemd 下一般不需要 |
| `--workdir` | 默认工作目录，默认是启动用户的 home |
| `--no-crypto` | 关掉载荷加密。只在抓包调试时用 |
| `--print-unit` | 打印 systemd unit 然后退出 |

---

## 主电脑：装客户端

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1
```

默认装到 `%LOCALAPPDATA%\crosswire`。想换位置：`-InstallDir D:\tools\crosswire`。

或者干脆不装，直接在这个目录里用 `python cw.py ...`，`cw.py` 自己会把路径塞进 `sys.path`。

### 登记目标机

```bash
python cw.py add sub 192.168.1.50 --key cw1_9f3a...e21c --default --note "编译机"
```

`--key` 和 `--key-file` 二选一。也可以不放 hosts.json，改用环境变量：

```powershell
$env:CROSSWIRE_KEY = "cw1_..."
```

优先级：hosts.json 里的 `key` > 环境变量 `CROSSWIRE_KEY` > hosts.json 里的 `key_file` > `~/.crosswire/key`。

### 验证

```bash
python cw.py doctor
```

```
config
  home        C:\Users\you\.crosswire
  hosts.json  C:\Users\you\.crosswire\hosts.json ok
  hosts       1 configured, default=sub
python
  3.12.10 on Windows-11-...
hosts
  sub      online 3ms  Ubuntu 24.04.1 LTS  agent=1.0.0  sudo=True pkg=True power=False

all good
```

---

## 接进 Agent

### DeepSeek Harness

```bash
python cw.py dsh-install
```

它会给 `~/.dsh/profiles/*/cordis.patch.yml` 每个文件末尾追加一段 `mcp-crosswire`。已经有的会跳过，重复跑没事。改完重启 dsh。

只想给某一个 profile 装：

```bash
python cw.py dsh-install --profile desktop
```

### Claude Desktop

```bash
python cw.py mcp-config --client claude
```

输出粘进 `claude_desktop_config.json`，重启客户端。

### Codex

```bash
python cw.py mcp-config --client codex
```

---

## 多台副电脑

```bash
python cw.py add build 192.168.1.50 --key cw1_aaa...
python cw.py add gpu   192.168.1.51 --key cw1_bbb...
python cw.py add nas   192.168.1.60 --key cw1_ccc... --default
```

Agent 那边先调 `hosts` 看清单，然后每个工具传 `host: "gpu"`。

别名随便起，中文也行（YAML/JSON 都是 UTF-8）。建议起短一点，Agent 少打几个 token。

---

## 排障

**`cannot reach 192.168.1.50:7900 (timed out)`**
机器没开、agentd 没起、或者防火墙。先在副电脑上 `ss -tlnp | grep 7900` 看有没有监听，`0.0.0.0:7900` 才对，`127.0.0.1:7900` 说明 bind 错了。

**`server rejected the key`**
两边 key 不一样。副电脑上 `sudo cat /etc/crosswire/agent.key`，跟主电脑的 `~/.crosswire/hosts.json` 对一遍。注意 `cw1_` 前缀可以带也可以不带，解析的时候会剥掉。

**`denied: path outside allowed roots`**
agentd 启动时带了 `--allow-root`，路径不在范围内。要么改参数，要么用范围内的路径。

**`denied: sudo is disabled by the agent policy`**
副电脑没 `--allow-sudo`，而且 sudo 也不是 NOPASSWD。两个办法：加参数，或者给这个用户配 `NOPASSWD`。

**连上了但工具全报 `connection_lost`**
看 `journalctl -u crosswire-agentd -n 50`。如果是 `bad frame tag`，说明两边版本不一致（协议改过），统一一下。

**`sys.info` 返回的 `ipv4` 是空的**
容器里没有 `/sys/class/net`，也没有 `ip` 命令。不影响其他功能，`net` 工具可能也会退化。

**PTY 里中文乱码**
agentd 的 shell 环境没有 `LANG`。启动 unit 里加 `Environment=LANG=C.UTF-8`，或者在 `tty_open` 之后先 `export LANG=C.UTF-8`。
