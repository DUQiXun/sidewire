# CrossWire

让一台机器上的 AI Agent 直接操作另一台机器。同一个局域网就行，不用 SSH，不用装一堆东西。

主电脑跑 Windows + Agent（DeepSeek Harness、Claude、Codex 都行），副电脑跑 Linux。装完之后 Agent 就能在副电脑上跑命令、读写文件、看进程、重启服务，跟在本地差不多。

```
你（Windows）── MCP stdio ──> crosswire ──TCP──> crosswire_agentd（Linux）
```

---

## 为什么又写了一个

上一个仓库 `winremote-deploy-kit` 是给 `winremote-mcp` 做部署的，本质上是往别人的东西外面套了一层壳：装服务、开防火墙、加一个中继解决 `Session not found`。

用着别扭。别扭的地方不在于它不好用，而在于它解决的是 Windows 控制 Windows，而且底子是 streamable HTTP —— 服务端一重启，客户端手里那个 `mcp-session-id` 就废了，HTTP 连接又不断，于是出现"看起来连着，其实一个工具都调不动"这种状态。中继就是在补这个洞。

洞是从协议选型那儿来的。所以这次干脆不套了，自己写线协议：

- 一条 TCP 长连接，上面跑自己的二进制帧，16 字节头 + CRC32
- 帧里带 stream id，多个请求真正并行，跑一个 40 分钟的编译不会把后面的 `fs_read` 堵住
- **服务端没有 session 这个概念**。连接就是 session。进程挂了 socket 就断，客户端重连重认证，没有中间态

代价是协议得自己维护。好处是上面那些坑不存在了。

---

## 跑起来

三步。假设副电脑是 `192.168.1.50`。

**1. 主电脑（Windows）装客户端**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-client.ps1
```

它会找 Python、把东西复制到 `%LOCALAPPDATA%\crosswire`、生成一把 key、然后问要不要顺手注册进 DeepSeek Harness。不想让它碰 DSH 就加 `-NoDsh`。

**2. 副电脑（Linux）装 agentd**

把 `agent/` 整个目录拷过去（U 盘、scp、微信传文件都行），然后：

```bash
sudo ./install-agent.sh --allow-sudo --allow-pkg
```

脚本干四件事：把 `crosswire_agentd.py` 放进 `/opt/crosswire`、生成 key 到 `/etc/crosswire/agent.key`、写一个 systemd unit、尽力开一下防火墙（ufw 或 firewalld，认不出来就算了）。

结束时会打印 key 和 IP，长这样：

```
  address  : 192.168.1.50
  port     : 7900
  key      : cw1_9f3a...e21c
```

**3. 回主电脑登记这台机器**

```bash
python cw.py add sub 192.168.1.50 --key cw1_9f3a...e21c --default
python cw.py doctor
```

`sub` 是别名，你想叫 `xiaodi`、`lab`、`nas` 都行。`doctor` 会把配置、key、连通性、agent 版本全过一遍，有毛病会直接说是哪一步。

顺手验一下：

```bash
python cw.py sh "uname -a && df -h"
```

---

## Agent 那边怎么接

DeepSeek Harness 的话，`cw.py dsh-install` 就完事了，它会往 `~/.dsh/profiles/*/cordis.patch.yml` 里插一段：

```yaml
- insert:
    - id: mcp-crosswire
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: crosswire
        transport: stdio
        command: 'C:\...\python.exe'
        args: ['C:\...\cw.py', 'serve']
        toolCallTimeoutMs: 600000
        failOnStartupError: false
```

Claude Desktop / Cursor 这类吃 JSON 的，`python cw.py mcp-config --client claude` 会打印现成的块，粘进去就行。

Codex 用 `--client codex`。

---

## 30 个工具

工具名都尽量短，Agent 不用记长名字。全部支持一个可选的 `host` 参数，多台机器的时候用它切。

**认机器**：`hosts`（有哪些机器、通不通）、`host_info`（是什么系统、什么权限）、`host_probe`（延迟）

**跑命令**：`run`、`run_script`（写临时文件再执行，省掉引号地狱）、`job_list`、`job_poll`、`job_kill`

**交互式**：`tty_open`、`tty_write`、`tty_read`、`tty_close` —— 真 PTY，能 ssh 到第三台机器、能跑交互式安装程序

**文件**：`fs_ls`、`fs_read`、`fs_write`、`fs_edit`（改一处，不动整个文件）、`fs_stat`、`fs_find`、`fs_grep`（在目标机上搜，不用把树搬过来）、`fs_manage`（mkdir/rm/mv/cp/chmod/chown/symlink/truncate 合一个）、`fs_pull`、`fs_push`、`fs_tail`、`fs_hash`

**系统**：`proc_list`、`proc_kill`、`svc`（systemctl/openrc/sysv 自动认）、`net`（网卡/监听端口/连通性探测/DNS）、`pkg`（apt/dnf/pacman/zypper/apk 自动认）、`power`

`fs_pull` 值得单说一句。它把远端文件拉到本机磁盘然后返回本地路径，Agent 拿自己的文件工具去读。二进制、图片、几十兆的日志都走这条，比 base64 塞进上下文强太多。

---

## 几个设计上的取舍

**为什么不用 HTTP。** 试过。HTTP 那套要么长轮询要么 SSE，为了在一条连接上多路复用要引入一堆语义，而且"连接正常但会话失效"这个状态天然存在。裸 TCP 上自己划帧反而简单，错了就是连接断了，重连就完事。

**为什么不直接 SSH。** SSH 在，但 Agent 用 SSH 有几个实际问题：密码/密钥管理、每次 exec 都要新建会话（慢）、输出和退出码要自己拼、超时和进程组处理很烦。另外 Windows 上默认没有 ssh 客户端的情况也不少。这些都能解决，但解决完就是重写一遍我现在写的东西。

**加密。** 没上 TLS，因为不想为了自签证书引入 openssl 依赖。用的是 stdlib 里能拼出来的东西：HMAC-SHA256 计数器模式做密钥流，再加 8 字节截断 tag，encrypt-then-MAC。挡得住局域网里随手抓包看到路径和命令，挡不住有心人。真跨网请套 WireGuard 或者 Tailscale，别指望这个。

**帧顺序。** 这个坑值得记一下：seal 和 write 必须是一个原子操作。第一版拆开写，12 个并发请求就把计数器搞乱序了，对端直接报 `bad frame tag`。现在两边都是一把锁包住"加密+发送"。

---

## 实测

`python tests/e2e.py` 会真的拉起一个 agentd，然后用真客户端打 27 项，覆盖握手、错 key 拒绝、命令执行、退出码、超时转 job、PTY、文件全套、300KB 二进制往返、输出截断、`allow_root` 越权拦截、12 路并发、断线重连。

本机（Windows 自测，走 loopback）：

```
27/27 passed
```

外加 `tests/test_protocol.py` 18 项（帧编解码、CRC、密钥流、tag 篡改、计数器乱序、agent 与客户端两份协议实现逐字节比对）和 `tests/test_mcp.py` 13 项（JSON-RPC 握手、协议版本协商、tools/list、tools/call、错误映射）。

几个数字：`sys.ping` 往返 0.3ms 左右，文件读写 1~5ms，300KB 二进制推+拉 90ms。命令执行在 Linux 上基本就是命令本身的耗时，Windows 上每次要起一个 `cmd.exe`，会多 120ms 左右 —— 那是系统开销，不是协议开销。

---

## 权限，以及别干的事

这套东西等价于把副电脑的 shell 交出去。装的时候想清楚。

- **key 就是全部**。`/etc/crosswire/agent.key` 和主电脑 `~/.crosswire/` 里那份，泄露等于机器被接管
- 默认 `--allow-root /` 也就是全盘可读写。想收窄就 `--allow-root /home/you/project`，越界会直接返回 `denied`
- `--allow-sudo`、`--allow-pkg`、`--allow-power` 三个开关默认全关。`power` 还额外要求 `confirm` 参数跟动作名一字不差
- **不要做公网端口映射**。真需要跨网，WireGuard / Tailscale，再加 `--allow-cidr 10.0.0.0/24`
- 每条请求都会写审计日志（地址、方法、耗时、成败、参数摘要），在 `journalctl -u crosswire-agentd`

---

## 已知问题

- Windows 上跑 agentd 时 `tty` 是假的（管道模拟，不是 PTY），`proc_list` 也会退化。Windows 只是拿来测协议用的，正经用请装在 Linux 上
- `proc_list` 的 CPU% 是两次调用之间的差值，所以刚连上第一次调经常全是 0，第二次才准
- `fs_grep` 是纯 Python 逐文件扫，几万个小文件会慢。真要快还是得让 Agent 直接 `run "grep -r"`
- 没做压缩，文本传输是原样。局域网够快，懒得加
- 断线重连只在"下一次请求"时发生，没有主动心跳重连（有心跳包保活，但不自动重拨）

---

## 目录

```
crosswire/            客户端（MCP 服务 + CLI）
  protocol.py         帧格式、加解密、握手
  client.py           连接、多路复用、文件传输
  config.py           ~/.crosswire/hosts.json
  cli.py              命令行
  mcp/server.py       JSON-RPC stdio
  mcp/tools.py        30 个工具的定义和处理
agent/
  crosswire_agentd.py 单文件守护进程，纯标准库，直接读 /proc
  install-agent.sh    一键装
cw.py                 免安装启动器
docs/                 协议、部署、安全、给 Agent 的操作规范
tests/                58 项测试
```

agentd 是故意做成单文件的。拷一个 `.py` 过去就能跑，没有依赖，没有虚拟环境，没有 `pip install`。代价是协议那部分代码在客户端和 agentd 里各有一份，靠 `test_protocol.py` 里那个逐字节比对的测试盯着。

---

## 许可

MIT。

---

名字是随便起的。wire 指两台机器之间那根线，cross 就是跨过去。你要不喜欢，改个名就行，代码里没有硬编码的地方。
