# 安全模型

说直白点：**这套东西等价于把副电脑的 shell 交出去**。装之前想清楚，装完别忘记。

## 信任边界在哪

```
[ Agent ]──stdio──[ crosswire ]──TCP+密钥──[ agentd ]──root/sudo──[ 系统 ]
   ①                  ②              ③           ④
```

1. Agent 完全可信。它能调用任何工具，没有二次确认
2. 客户端持有密钥，能连任何配置过的目标
3. 这一段是唯一需要防的。局域网内有人抓包、有人扫端口
4. agentd 的进程权限就是它的能力上限

**第 3 段是唯一真正的边界。** 破了它，后面的策略都是摆设。

## 密钥

一把 32 字节的共享密钥，两边一样。它是全部凭据。

- 副电脑：`/etc/crosswire/agent.key`，600，只有 root 能读
- 主电脑：`~/.crosswire/hosts.json` 里的 `key` 字段，或者 `~/.crosswire/key`，600
- 环境变量 `CROSSWIRE_KEY` 优先级更高，适合 CI

泄露 = 那台机器被完全接管。所以：

- 别提交进 git（`.gitignore` 里已经有了）
- 别贴在聊天记录里
- 别用同一把 key 给多台机器（虽然能跑，但泄露影响面变大）
- 换 key：副电脑重新 `--keygen`，主电脑 `crosswire add` 重来一遍。没有热更新，得重启 agentd

## 传输

握手用 HMAC 挑战应答，双向验证：

- 客户端证明自己知道 key（`client_proof`）
- 服务端也证明（`server_proof`）—— 所以假冒的服务器骗不到客户端
- 每次连接新 nonce，旧握手不能重放

握手之后所有载荷加密：HMAC-SHA256 计数器模式密钥流 + 8 字节截断 tag，encrypt-then-MAC。

**能做到什么**：局域网里随手抓包，看不到你执行了什么命令、读写了什么路径、传了什么内容。改了任何一个字节都会被 tag 检测出来。

**做不到什么**：
- 不是 TLS。没有前向保密。拿到 key 的人可以解密历史流量（如果他也录了握手）
- 8 字节 tag 比标准 16 字节短，理论上碰撞概率更高（实践中 2^-64 已经够用）
- 没有抗重放的时间窗。nonce 是随机的，服务端不记录历史 nonce，所以理论上可以重放整个连接——但重放一个完整的 TCP 会话需要能劫持连接，那时候已经没意义了

**真要安全**：套 WireGuard / Tailscale，让它跑在隧道里。这也是跨网络的唯一推荐做法。

## agentd 的策略开关

默认全关，显式打开：

| 开关 | 打开后能做什么 | 建议 |
|---|---|---|
| （无） | 读写整个文件系统、跑任意命令、看进程、管服务 | 至少配 `--allow-root` 收窄 |
| `--allow-sudo` | `run(sudo=true)` 提权 | 只在真需要时装包/改系统时开 |
| `--allow-pkg` | 装/卸软件包 | 同上 |
| `--allow-power` | 重启、关机、挂起 | 需要 `confirm` 二次确认，但仍然危险 |

`--allow-root` 可以给多个，取并集。路径先 `realpath` 再比对，所以 `../` 穿越和符号链接都绕不过去：

```
--allow-root /home/deploy/app
→ fs_read("/home/deploy/app/../../../etc/shadow")  →  denied
```

`--allow-cidr` 是网络层白名单，在 accept 之后立刻检查，不在范围内的连接直接关掉，连握手都不给。

## 审计

每条请求都记一行：

```
2026-10-25 03:02:13 [audit] 192.168.1.20 exec.run 190ms ok=True | {"command": "systemctl restart nginx"}
```

含来源 IP、方法、耗时、成败、参数摘要（每个值截断 120 字符）。写到 stderr，systemd 下就是 journald：

```bash
journalctl -u crosswire-agentd | grep audit
```

参数摘要是摘要，不是全文——`fs_write` 的内容不会进日志。要审计内容自己配 `--log` 再做日志轮转。

## 不该做的事

- **公网端口映射。** 一次都不要。这个协议没为公网设计，被扫到就是被接管
- 把 key 写进 Dockerfile / 镜像 / 公开的 compose 文件
- 在多人共用的机器上跑 agentd 而不配 `--allow-cidr`
- 用 `--no-crypto` 图省事。它只是关掉加密，性能差异在局域网上测不出来

## 出事了怎么办

```bash
sudo systemctl stop crosswire-agentd
sudo systemctl disable crosswire-agentd
```

然后按普通入侵流程走：看 journald、看 `last`、看有没有多出来的 crontab 和 systemd unit。

只换 key 不够——攻击者已经在里面了，换 key 只是关门，人还在屋里。
