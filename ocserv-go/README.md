# ocserv-go

用 Go 重写 Cisco AnyConnect / OpenConnect 服务端的 **CSTP 隧道部分**，把内核 TUN 换成
**用户态 TCP/IP 栈**（gVisor netstack），因此：

- ❌ 不需要 `/dev/net/tun`
- ❌ 不需要 `CAP_NET_ADMIN` / `--privileged`
- ❌ 不需要 `iptables` / `MASQUERADE` / `ip_forward`

只要有端口转发权限，就能在**无特权 LXC / Docker** 里跑。客户端照旧用
Cisco AnyConnect、OpenConnect、或任何兼容客户端（对端协议不变）。

> 状态：实验性分支 `ocserv-go`，只实现了 IPv4 + TCP/UDP 代理，暂无 DTLS/压缩/分流量路由。

## 工作原理

```
AnyConnect 客户端
   │  TLS + AnyConnect 认证（XML）
   │  CONNECT /CSTP → 8 字节帧 + IP 包
   ▼
ocserv-go
   ├─ cstp     : 帧编解码
   ├─ acxml    : 认证握手 XML
   ├─ auth     : 用户库（bcrypt）
   ├─ ippool   : 客户端地址分配
   └─ usrnet   : gVisor 用户态 TCP/IP 栈
          ├─ 收到 IP 包 → 注入栈
          ├─ 栈里每条 TCP 连接 → 进程内 net.Dial 到真实目标 → 双向转发
          └─ 每条 UDP 流同理（DNS/QUIC 可用）
   ▼
宿主网络（普通 socket 出网）
```

每个客户端连接独享一个用户态栈，互不影响；地址池按连接分配。

## 编译

```bash
cd ocserv-go
go build -o bin/ocserv-go .
```

依赖：`gvisor.dev/gvisor`（已 pin 到 Tailscale 验证过的版本）、`golang.org/x/crypto`、`golang.org/x/net`。
纯 Go，`CGO_ENABLED=0` 可静态编译。

## 用法

```bash
# 1) 生成用户（bcrypt）
./bin/ocserv-go hash '你的密码'
# → $2a$10$...
echo 'alice:$2a$10$...' > users.txt

# 2) 起服务
sudo ./bin/ocserv-go \
  -addr :443 \
  -cert /etc/ssl/securev/vpn.example.com/fullchain.pem \
  -key  /etc/ssl/securev/vpn.example.com/privkey.pem \
  -users users.txt \
  -net 10.66.66.0/24 -ip 10.66.66.1 \
  -dns 1.1.1.1
```

联调时可以不给证书，用 `-self-signed` 自动生成（客户端会提示不受信任）。

### 两种登录风格

`-style` 决定 webvpn 认证流程：

- **`asa`（默认）**：复刻 Cisco ASA。按抓包对比 `Cisco ASA` 实现：

  | 请求 | 真机行为 | 本实现 |
  |---|---|---|
  | `POST /`（XML init） | 404 | 404 |
  | `GET /` | AnyConnect UA → 302 `/+webvpn+/index.html` + `tg=` cookie；浏览器 → 带 JS 跳转的 HTML | 同 |
  | `GET /+webvpn+/index.html` | `text/xml`，`X-Transcend-Version: 1`，裸 `<auth id="main">` | 同（不含组选择） |
  | `GET /+CSCOE+/logon.html` | 浏览器登录页（table 布局、`unicorn_form`、csrf_token、USERNAME/PASSWORD） | 同 |
  | 静态资源 | `/+CSCOE+/logon_custom.css`、`/+CSCOU+/portal.css`、`/+CSCOU+/csco_logo.gif`、`/+CSCOU+/login-header-*.jpg` | 均返回 200，内容是自绘占位 |
  | 提交分流 | AnyConnect 客户端（`X-Transcend-Version` / UA）拿 XML；浏览器拿 HTML + 302 到门户 | 同 |
  | `POST /+webvpn+/index.html` | 表单 `group_list/username/password`；失败插 `<error id="15" param1="" param2="">Login failed.</error>`；成功 `id="success"` + `webvpn` cookie | 同 |
  | `CONNECT /CSTP` | 带 `webvpn` cookie（可在新连接上） | 支持 cookie 或同连接会话 |

  > 真机的登录页带 `group_list`（权限组下拉）。本实现**不做组选择**：
  > 组名属于各站点的私有配置，不内置也不照搬。
  >
  > 页面的 HTML/XML 骨架（元素 id、name、隐藏字段、表单 action、错误码）按真机对齐，
  > 但**样式与图片是自绘的占位**，不随包分发 Cisco 的商标/资源。
  > 目的：让扫描器看到一个"像 ASA"的表面；认证成功之后的隧道逻辑仍走本实现。

- **`ocserv`**：标准 ocserv 的 XML 流程（`POST /` → `auth-request`，`POST /auth` → `auth-reply`）。

```bash
# 用 ASA 风格（默认）
./bin/ocserv-go -addr :443 -users users.txt -cert c.pem -key k.pem -style asa
```

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-addr` | `:443` | 监听地址 |
| `-cert` / `-key` | — | TLS 证书/私钥；缺省时需 `-self-signed` |
| `-users` | 必填 | `用户名:bcrypt哈希` 每行一条 |
| `-net` | `10.66.66.0/24` | 客户端地址池 |
| `-ip` | `10.66.66.1` | 隧道内服务端地址（必须是池内地址） |
| `-dns` | `1.1.1.1` | 下发给客户端的 DNS（最多 2 个） |
| `-mtu` | `1400` | 隧道 MTU |
| `-dpd` | `30` | 保活间隔（秒），0 关闭 |
| `-socks` | — | 出网走 SOCKS5（`host:port`，UDP 仍直连） |
| `-style` | `asa` | 登录风格：`asa`（模拟 Cisco ASA）或 `ocserv` |
| `-http` | false | **仅预览**：明文 HTTP 启动，用浏览器看登录页（真实客户端必须 TLS） |
| `-self-signed` | false | 没证书时生成自签 |
| `-domain` | `ocserv-go.local` | 自签证书 CN / 下发默认域 |

## 浏览器预览（看页面效果）

```bash
./bin/ocserv-go hash 'test123' > /tmp/u.txt      # 生成一行 alice:$2a$...
printf 'alice:%s\n' "$(./bin/ocserv-go hash 'test123')" > /tmp/users.txt
./bin/ocserv-go -http -addr :8080 -users /tmp/users.txt
```

打开 <http://localhost:8080/>：会像真机一样 JS 跳到 `/+CSCOE+/logon.html` 登录页，
输错密码显示 `Login failed.`，登录成功跳到 `/+CSCOE+/portal.html`。

> `-http` 只用于预览页面；AnyConnect 客户端必须走 TLS（去掉 `-http` 并提供证书）。

页面路由（ASA 风格）：

| 路径 | 用途 |
|---|---|
| `/+CSCOE+/logon.html` | 浏览器登录页（表单 post 到自己） |
| `/+CSCOE+/portal.html` | 登录后门户（需要 webvpn cookie） |
| `/+webvpn+/index.html` | 客户端用的 XML 接口（`text/xml`） |

## 无特权 Docker

```bash
docker build -t ocserv-go:dev ocserv-go
docker run -d --name ocserv-go \
  -p 443:443 \
  -v "$PWD/users.txt:/data/users.txt:ro" \
  -v "$PWD/certs:/certs:ro" \
  ocserv-go:dev \
  -addr :443 -users /data/users.txt \
  -cert /certs/fullchain.pem -key /certs/privkey.pem
```

注意**没有** `--privileged`、没有 `--device /dev/net/tun`、没有 `--cap-add`。

## 已验证

`go test ./...`：

- `internal/acxml`：init / auth-reply 解析、四种响应报文
- `internal/cstp`：帧往返、非法 STF、超长拒绝
- `internal/ippool`：分配/释放/耗尽/非法配置
- 根包 `TestTunnelTCP`：ocserv 风格完整链路——TLS 认证 → CONNECT → CSTP 帧 → 客户端 gVisor 栈
  → 服务端用户态栈 → 从宿主机拨到本地 HTTP 服务 → 内容回传
- 根包 `TestASAStyle`：ASA 风格完整链路——`GET /` 302 → 登录 XML → 错误密码得
  `error id="15"` → 正确密码得 `id="success"` + `webvpn` cookie → **新连接带 cookie** CONNECT
  → 隧道内 UDP 往返

另有一个手工端到端脚本（Python）验证 UDP 转发（DNS 场景）：

```
1) init      -> 200
2) username  -> Please enter your password
3) password  -> success
4) CONNECT   -> 200 CONNECTED  X-CSTP-Address: 10.66.66.2
5) 收到回包  192.168.50.158:15353 -> 10.66.66.2:40000  负载=b'echo:hello-through-tunnel'
```

## DTLS

默认启用（`-dtls=false` 关闭），UDP 端口与 `-addr` 相同（可用 `-dtls-port` 指定）。

Cisco 的 DTLS 不是普通握手：客户端在 `CONNECT` 里用 `X-DTLS-Master-Secret` 给出 48 字节主密钥，
双方据此做「恢复握手」。实现方式：

1. 读 `X-DTLS-Master-Secret`（96 个 hex）
2. 生成 32 字节会话 ID，用 `X-DTLS-Session-ID` 下发
3. 把这个主密钥按其会话 ID 预置进 pion/dtls 的 `SessionStore`（`dtls.Session{ID, Secret, CipherSuiteID}`）
4. 客户端带该会话 ID 发起 DTLS，pion 走恢复流程，握手后数据面切到 UDP
5. 数据帧在 DTLS 上用 **`[1 字节类型][负载]`**（不是 8 字节 CSTP 头）；控制帧仍走 TCP

协商头（与真机一致）：

```
X-DTLS-Session-ID: <64 hex>
X-DTLS-Port: 443
X-DTLS-12: 1
X-DTLS-DPD: 30
X-DTLS-MTU: 1400
X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384
```

> 需要 **RSA 证书**（Cisco 用 ECDHE-RSA 套件）；ECDSA 证书时 DTLS 自动禁用并打日志。

**已验证**（openconnect 9.12 作为客户端）：

```
Established DTLS connection (using GnuTLS). Ciphersuite (DTLS1.2)-(ECDHE-RSA)-(AES-256-GCM).
Configured as 10.66.66.2, with SSL connected and DTLS connected
```

连接持续 20 秒无重连、无 "Unrecoverable I/O error"；服务端日志 `DTLS 数据面已建立`。
MTU 探针（类型 3）会按原长度回 `type=4`。

**CSTP 头格式**（TCP，8 字节，与 openconnect 的 cstp.c 一致）：

```
'S' 'T' 'F' 0x01 | 长度(大端,4-5) | 类型(6) | 0(7) | 负载
```

类型：0=数据 3=DPD 4=DPD 应答 5=断开 7=保活 8=压缩 9=踢下线。

## 已知限制

- **仅 IPv4**；IPv6 包直接丢弃
- **无 DTLS**：只走 TLS/TCP 传输，客户端会自动降级（性能略差）
- **无压缩**（CSTP 压缩帧未实现）
- **路由固定为全局**：不下发 split-include/exclude
- **ICMP 只回应隧道内地址**（ping 10.66.66.1），不代理到外网
- 出网源地址是运行 ocserv-go 的机器，上游看到的是宿主 IP
- 用户态栈有额外开销，单核吞吐通常在几百 Mbps 量级（取决于包大小）
- 认证状态按 TLS 连接维护，没有会话超时/重新认证策略

## 与主套件的关系

这个分支只替换 **ocserv 的 CSTP 数据面**。面板、证书、用户管理仍在主分支的
`ocserv-deploy-kit` 里；后续若稳定，可以把 ocserv-go 作为面板的一种「运行模式」接入
（不需要 tun 的部署方式）。
