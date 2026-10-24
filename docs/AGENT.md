# 给 Agent 的操作规范

这份是给"要动手的那一方"看的。人看 README 就够了。

---

## 一、动手之前先确认在跟谁说话

跨机器操作最容易犯的错是**以为自己在本机**。所以任何一次任务的第一步：

```
hosts()
```

返回每台机器的别名、地址、当前通不通、哪台是默认。如果你不确定用户说的"那台电脑"是哪台，就靠这个问，别猜。

确定目标之后：

```
host_info(host="sub")
```

看 `hostname`、`os`、`user`、`is_root`、`allow_sudo`、`allow_pkg`、`allow_power`。

- `hostname` 跟你预期的不一样 → 停下来问，别继续
- `allow_sudo: false` → 别试 `run(sudo=true)`，会直接 `denied`，先告诉用户
- `is_root: true` → 后面所有操作都是 root 权限，破坏性操作要格外小心

---

## 二、所有路径都是那台机器上的路径

`fs_read(path="/etc/nginx/nginx.conf")` 读的是副电脑的 `/etc`，不是你这台的。反过来，`fs_pull` 返回的 `local_path` 才是本机路径，那个才可以用你自己的文件工具读。

这个区分搞混了会浪费很多轮对话。

---

## 三、工具怎么选

| 想干的事 | 用这个 | 别用 |
|---|---|---|
| 跑一条命令 | `run` | — |
| 跑带引号/多行/变量的脚本 | `run_script` | `run`（转义会疯） |
| 跑很久的东西 | `run(timeout=…, background=true)` + `job_poll` | `run` 硬等 |
| 需要保持状态的会话（ssh、REPL、交互式安装） | `tty_*` | `run` |
| 看文件 | `fs_read` | `run("cat …")` |
| 看文件末尾 | `fs_tail` | `fs_read` 整个文件 |
| 改文件里一处 | `fs_edit` | `fs_write` 重写全文 |
| 找文件 | `fs_find` | `run("find …")` |
| 搜内容 | `fs_grep` | `run("grep -r …")` |
| 拿二进制/大文件 | `fs_pull` | `fs_read(binary=true)` |
| 传文件过去 | `fs_push` | `fs_write(data_b64=…)` |
| 看进程 | `proc_list` | `run("ps aux")` |
| 看端口 | `net(action="sockets")` | `run("ss -tlnp")` |
| 管服务 | `svc` | `run("systemctl …")` |

右边那列不是不能用，是没必要 —— 左边的直接返回结构化结果，少一次解析，也少一次出错的机会。

---

## 四、几个必须知道的坑

**输出会被截断。** `run` 默认每个流 60000 字节，超了返回 `truncated: {stdout: true}`。看到这个标记说明你看到的不是全部，别基于残缺输出下结论。要看全的就 `fs_pull` 下来读，或者用 `fs_grep` 精确找。

**超时不是失败。** `run(timeout=30)` 超时会返回 `state: "running"` 加一个 `job_id`，命令还在跑。要么 `job_poll(job_id, wait=5)` 继续等，要么 `job_kill`。**不要**直接重新跑一遍，那会起两个。

**`job_poll` 要带 offset。** 上次返回的 `stdout_offset` 下次传回去，才只拿增量。不带的话每次都从头发，白烧 token。

**`proc_list` 第一次的 cpu 是 0。** 因为 CPU% 是两次采样之间的差值。隔一两秒再调一次才有数。

**`denied` 不是 bug。** 意思是 agentd 的策略不让。看到 `denied` 不要去换路径重试，直接告诉用户需要改启动参数（`--allow-root`、`--allow-sudo`、`--allow-pkg`、`--allow-power` 之一）。

**`lost` 大于 0 表示丢数据。** 只在 job 输出和 tty 输出里出现，说明你读得太慢，环形缓冲已经绕过去了。

---

## 五、常见配方

**看看这台机器什么情况**
```
run("uname -a; uptime; free -h; df -h /")
```

**服务挂了**
```
svc(name="nginx", action="status")
svc(name="nginx", action="logs", lines=80)
svc(name="nginx", action="restart")
```

**端口被谁占了**
```
net(action="sockets", states=["LISTEN"], with_pid=true)
```

**改配置**
```
fs_read(path="/etc/foo/bar.conf")
fs_edit(path="/etc/foo/bar.conf", old="port = 8080", new="port = 9090", backup=true)
svc(name="foo", action="restart")
svc(name="foo", action="status")
```

**装东西**
```
pkg(action="search", packages=["redis-server"])
pkg(action="install", packages=["redis-server"], timeout=300)
```

**部署一个本地构建产物**
```
fs_push(local_path="C:\\build\\app.tar.gz", path="/opt/app/app.tar.gz")
run("cd /opt/app && tar xzf app.tar.gz && ./restart.sh")
```

**把一个远端日志拿下来分析**
```
fs_pull(path="/var/log/app/error.log")
# 然后用你自己的本地文件工具读 local_path
```

**进一个交互式环境**
```
tty_open()                                   → tty_id
tty_write(tty_id, "sudo -i\n")               → 输入
tty_read(tty_id, offset=0, wait=2)           → 看输出
tty_close(tty_id)
```

`tty_write` 里的 `\n` 会自动转成回车，不用写 `\r\n`。

---

## 六、破坏性操作

这几个先跟用户说清楚再动，说清"改什么、改完什么效果、怎么还原"：

- `svc(action="stop"|"disable")`
- `pkg(action="remove"|"upgrade")`
- `proc_kill`
- `fs_manage(op="rm")`
- `fs_write` 覆盖已有文件
- `power`（直接断连，一定放最后）

`power` 需要 `confirm` 跟 `action` 一字不差，这是故意的——多打一次字，多一次想清楚的机会。

---

## 七、和本地工具的分工

- 本机的事用本机工具，别绕一圈去远程
- 副电脑的事一律走 crosswire，别用本地路径去访问它的文件
- 两边要搬数据：`fs_push` / `fs_pull`，不要 base64 塞进对话
- 副电脑能自己算的事让它自己算（`fs_grep`、`run("awk …")`），比把数据搬回来再处理快得多
