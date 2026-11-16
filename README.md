# ocserv-go

用 Go 重写的 **Cisco AnyConnect / ASA 兼容 VPN 服务端**：协议层照旧（客户端不用改），
数据面换成 **gVisor 用户态 TCP/IP 栈** —— 所以**不需要 `/dev/net/tun`、不需要 `NET_ADMIN`、
不需要 `iptables` / `ip_forward`**，无特权 LXC / Docker / PaaS 里都能跑。

> 当前版本 **1.1.0**。本仓库只包含 Go 版服务端与管理面板；
> C 版 ocserv 部署套件在另一个仓库：[ocserv-deploy-kit](https://github.com/hakureiyuyuko/ocserv-deploy-kit)。

## 仓库结构

```
ocserv-go/          # Go 服务端源码（main.go、internal/、install.sh、Dockerfile）
ocserv-go/panel/    # 内置管理面板（Go API + 前端构建产物 webdist/，go:embed 进二进制）
web/                # 面板前端源码（Vue 3 + Vite）
.github/            # CI：推 v* tag 自动出双架构包并发布 Release
```

> 服务端与面板现在是**同一个二进制**：`ocserv-go` 负责 VPN，`ocserv-go panel`
> 子命令负责管理面板。运行时不需要 Node.js（Node 只在构建前端时用到）。

---

## 它解决什么问题

传统 ocserv 依赖内核 TUN 设备把隧道里的 IP 包接进来，再靠 iptables 做 NAT 出网。这在
受限容器里直接用不了：要么拿不到 `/dev/net/tun`，要么没有 `NET_ADMIN`。

ocserv-go 把这两步都搬进进程：

```
AnyConnect 客户端
   │  TLS（控制） + DTLS（数据，可选）
   │  ASA 风格 webvpn 认证（HTML 表单 / XML）+ CSTP 帧
   ▼
ocserv-go
   ├─ 认证：bcrypt 或 ocpasswd 的 $5$/$6$ crypt
   ├─ CSTP：8 字节帧（"STF"+0x01 + 长度 + 类型）
   ├─ DTLS：Cisco 的「预共享主密钥恢复握手」
   └─ gVisor 用户态 TCP/IP 栈
        ├─ 客户端发来的 IP 包注入栈
        ├─ 栈里每条 TCP 连接 → 进程内 net.Dial 到真实目标 → 双向转发
        └─ 每条 UDP 流同理（DNS/QUIC 可用）
   ▼
宿主网络（普通 socket 出网，无需任何特权）
```

每个客户端连接独享一个用户态栈，地址按连接从池里分配。

## 和其它实现的关系

| | 本分支 `ocserv-go` | `main` 分支 |
|---|---|---|
| 服务端 | Go 重写（`ocserv-go/`） | C 版 ocserv（发行版包） |
| 数据面 | gVisor 用户态栈，进程内出网 | 内核 TUN + iptables NAT |
| 权限 | **无要求**（能监听端口即可） | 需要 tun / `NET_ADMIN` |
| 面板 | 可切换后端（`backend=go`） | 原生后端 |
| 协议 | AnyConnect / ASA（CSTP + DTLS） | 同（另有标准 OpenConnect 协议） |

---

## 快速开始

### 0. 用发行包安装（推荐）

从 [Releases](https://github.com/hakureiyuyuko/ocserv-deploy-kit/releases) 下载对应架构：

```
ocserv-go-1.1.0-linux-amd64.tar.gz     # x86_64
ocserv-go-1.1.0-linux-arm64.tar.gz     # aarch64
```

```bash
tar xzf ocserv-go-1.1.0-linux-amd64.tar.gz
cd ocserv-go-1.1.0-linux-amd64
sudo ./install.sh --domain vpn.example.com --user alice
```

`install.sh` 会自己判断环境：

- 按 `uname -m` 校验包内二进制能否执行（架构不符会直接报错，不会装错）
- 识别 **systemd**（Debian/Ubuntu）或 **OpenRC**（Alpine），写对应服务单元并开机自启
- 没有证书时生成自签 **RSA**（DTLS 需要）；`/etc/ocserv/ocpasswd` 为空时创建 `admin` 并打印密码
- 缺 `openssl` 时会尝试用 `apk/apt/dnf` 自动补装
- 支持 `--uninstall` 卸载（保留配置/证书/用户）

常用参数：`--domain` `--port` `--cert` `--key` `--users` `--net` `--ip` `--dns`
`--user` `--password` `--prefix` `--no-start`。

> 已在**无特权 LXC** 里实测：Alpine 3.24（OpenRC）与 Debian 13（systemd）都能一键装好、
> 开机自启、TCP+UDP 监听并完成认证。



### 1. 编译

```bash
cd ocserv-go
go build -o bin/ocserv-go .
# 纯 Go，可静态：CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ocserv-go .
```

### 2. 准备用户

```bash
./bin/ocserv-go hash '你的密码'          # 输出 $2a$… 一行
echo 'alice:$2a$10$…' > users.txt
```

也**直接兼容 ocserv 的 `ocpasswd`**（`user:*:$5$…` 或 `user:*:$6$…`），所以可以让面板
继续用 `/etc/ocserv/ocpasswd` 管理用户。

### 3. 证书

三种来源，任选：

```bash
# a) 已有证书
-cert /etc/ssl/securev/vpn.example.com/fullchain.pem -key …/privkey.pem

# b) 内置 Let's Encrypt（DNS-01，见下文）
ocserv-go -acme-once -acme-domain vpn.example.com -acme-dns cloudflare …

# c) 联调用自签
-self-signed -domain vpn.example.com
```

### 4. 运行

```bash
./bin/ocserv-go \
  -addr :443 -users users.txt \
  -cert fullchain.pem -key privkey.pem \
  -net 10.66.66.0/24 -ip 10.66.66.1 \
  -dns 1.1.1.1,8.8.8.8 \
  -mtu 1400 -dpd 30
```

### 5. 无特权 Docker

```bash
docker build -t ocserv-go:dev ocserv-go
docker run -d --name ocserv-go -p 443:443 -p 443:443/udp \
  -v "$PWD/users.txt:/data/users.txt:ro" \
  -v "$PWD/certs:/certs:ro" \
  ocserv-go:dev -addr :443 -users /data/users.txt \
  -cert /certs/fullchain.pem -key /certs/privkey.pem
```

注意：**没有** `--privileged`、**没有** `--device /dev/net/tun`、**没有** `--cap-add`。

### 6. 浏览器预览（只看页面）

```bash
./bin/ocserv-go -http -addr :8080 -users users.txt
```

打开 <http://localhost:8080/> 会像真机一样跳到 `/+CSCOE+/logon.html` 登录页，登录后进
`/+CSCOE+/portal.html`。`-http` 仅用于预览，真实客户端必须走 TLS。

---

## 命令行参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-addr` | `:443` | 监听地址（TCP） |
| `-cert` / `-key` | — | TLS 证书 / 私钥 |
| `-users` | 必填 | 用户文件（`user:hash` 或 ocpasswd 的 `user:group:hash`） |
| `-net` | `10.66.66.0/24` | 客户端地址池 |
| `-ip` | `10.66.66.1` | 隧道内服务端地址（必须在池内） |
| `-dns` | `1.1.1.1` | 下发给客户端的 DNS（逗号分隔，最多 2 个） |
| `-mtu` | `1400` | 隧道 MTU |
| `-dpd` | `30` | 保活间隔（秒），0 关闭 |
| `-socks` | — | 出网走 SOCKS5（TCP；UDP 直连） |
| `-self-signed` | false | 无证书时生成自签 |
| `-domain` | `ocserv-go.local` | 自签证书 CN / 下发默认域 |
| `-style` | `asa` | 登录风格：`asa`（模拟 Cisco ASA）或 `ocserv`（标准 XML） |
| `-dtls` | true | 启用 DTLS 数据面 |
| `-dtls-port` | 同 `-addr` | DTLS 端口 |
| `-assets` | `/etc/ocserv-go/assets` | 用户上传的 Cisco 登录页资源目录（图片/CSS/logon.html） |
| `-icmp-echo` | true | 客户端 ping 由服务端本地应答（echo reply，延迟 = 客户端到网关 RTT）；`false` 则不代答 |
| `-http` | false | 明文 HTTP 预览模式（仅看页面） |
| `-v` | false | 详细日志 |
| `-version` | — | 显示版本 |
| `-acme-once` | false | 申请/续期证书后退出 |
| `-acme-domain` / `-acme-email` | — | ACME 域名 / 账号邮箱 |
| `-acme-dns` | — | `cloudflare` / `alidns` / `tencentcloud` / `dnspod` |
| `-acme-cache` | `/etc/ocserv-go/acme` | ACME 账号与缓存目录 |
| `-acme-env` | `/etc/ocserv-go/acme.env` | 凭据文件（`KEY=VALUE`） |
| `-acme-staging` | false | 用 LE staging |
| `-acme-key-type` | `rsa2048` | 证书密钥类型（`ec256` 亦可，但 DTLS 需 RSA） |
| `-acme-auto` | true | 自动续期：按 `-acme-state` 检查，剩余 ≤30 天用内置 lego 续期 |
| `-acme-state` | `/etc/ocserv-go/acme.json` | 自动续期配置（域名/服务商/邮箱/凭据路径，面板签发时写入） |

---

## 两种登录风格

### `asa`（默认）：模拟 Cisco ASA

按照对真实 ASA 的抓包实现，路径与响应都对齐：

| 请求 | 行为 |
|---|---|
| `POST /`（XML init） | 404（真机就是不接受） |
| `GET /` | AnyConnect UA → 302 `/+webvpn+/index.html` + `tg=` cookie；浏览器 → JS 跳 `/+CSCOE+/logon.html` |
| `GET /+webvpn+/index.html` | `text/xml`、`X-Transcend-Version: 1`、裸 `<auth id="main">` |
| `POST /+webvpn+/index.html` | 表单提交；失败插 `<error id="15" param1="" param2="">Login failed.</error>`；成功 `id="success"` + `webvpn` cookie |
| `GET /+CSCOE+/logon.html` | 浏览器登录页（`unicorn_form`、csrf_token、USERNAME/PASSWORD、#858A91 边框） |
| 静态资源 | `logon_custom.css` / `portal.css` / `win.js` / `csco_logo.gif` / `login-header-*.jpg` 均 200 |
| `CONNECT /CSTP`（或 `/CSCOSSLC/tunnel`） | 200 CONNECTED + `X-CSTP-*` / `X-DTLS-*`，之后是 CSTP 二进制流 |

页面骨架与真机一致，但**样式和图片是自绘占位**，不随包分发 Cisco 的商标或资源；
也不内置任何具体站点的权限组名。

### `ocserv`：标准 XML 流程

`POST /` → `auth-request`，`POST /auth` → `auth-reply`（`<auth id="success"/>`）。

---

## DTLS

Cisco 的 DTLS 不是普通握手：客户端在 `CONNECT` 里用 `X-DTLS-Master-Secret` 给出
48 字节主密钥，双方据此做**恢复握手**。

实现方式：

1. 读 `X-DTLS-Master-Secret`（96 hex）
2. 生成 32 字节会话 ID，用 `X-DTLS-Session-ID` 下发
3. 把主密钥按会话 ID 预置进 pion/dtls 的 `SessionStore`，握手走恢复流程
4. 数据面切到 UDP：DTLS 上帧格式是 **`[1 字节类型][负载]`**（不是 8 字节 CSTP 头）
5. 控制帧（DPD/保活）仍走 TCP；MTU 探针按原长度回 `type=4`

协商头：

```
X-DTLS-Session-ID: <64 hex>
X-DTLS-Port: 443
X-DTLS-12: 1
X-DTLS-DPD: 30
X-DTLS-MTU: 1400
X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384
```

> **需要 RSA 证书**（Cisco 用 ECDHE-RSA 套件）。ECDSA 证书时自动禁用 DTLS 并打日志；
> 面板在 `backend=go` 时会用 RSA（ACME 2048 / 自签 rsa:2048）。

## ICMP 应答（ping 延迟）

有些应用（游戏、测速、连通性探针）会先 ping 一个外部地址来判断链路质量。隧道内的
ping 如果被丢掉、或者绕到真实目的地，测出来的数字要么超时、要么包含整段公网 RTT。

`-icmp-echo`（默认开启）让服务端**本地代答**：客户端发出的 ICMP echo request
（目标地址任意，含外部地址）直接由服务端生成 echo reply，源地址就是被 ping 的地址，
原样回显 identifier / sequence / 负载。

效果：

- ping 任何地址都有应答，不依赖目标主机是否响应；
- 测到的延迟就是**客户端 ↔ 网关**的真实 RTT（不含公网绕行），正好是这类应用
  “到网关延迟”的口径；
- 除链路本身丢包外，丢包率为 0。

关闭：`-icmp-echo=false`，此时 echo request 按普通数据包处理（送进网络栈，
通常因无法路由而被丢弃）。

---

## CSTP 头格式（TCP）

```
'S' 'T' 'F' 0x01 | 长度(大端, 字节 4-5) | 类型(字节 6) | 0(字节 7) | 负载
```

类型：`0` 数据、`3` DPD 请求、`4` DPD 应答、`5` 断开、`7` 保活、`8` 压缩、`9` 踢下线。

---

## 内置 Let's Encrypt（DNS-01）

用 [lego](https://github.com/go-acme/lego) 在进程内签发，**不需要 acme.sh、不需要 80 端口**。

```bash
cat > /etc/ocserv-go/acme.env <<'EOF'
CF_DNS_API_TOKEN=xxxxx
EOF
chmod 600 /etc/ocserv-go/acme.env

ocserv-go -acme-once -acme-domain vpn.example.com -acme-dns cloudflare \
  -acme-env /etc/ocserv-go/acme.env -acme-cache /etc/ocserv-go/acme \
  -cert /etc/ssl/securev/vpn.example.com/fullchain.pem \
  -key  /etc/ssl/securev/vpn.example.com/privkey.pem
```

| 服务商 | `-acme-dns` | 环境变量 |
|---|---|---|
| Cloudflare | `cloudflare` | `CF_DNS_API_TOKEN`（或 `CLOUDFLARE_DNS_API_TOKEN`） |
| 阿里云 DNS | `alidns` | `ALICLOUD_ACCESS_KEY` + `ALICLOUD_SECRET_KEY` |
| 腾讯云 DNSPod（API 密钥） | `tencentcloud` | `TENCENTCLOUD_SECRET_ID` + `TENCENTCLOUD_SECRET_KEY` |
| DNSPod Token | `dnspod` | `DNSPOD_API_KEY`（`ID,Token`） |

账号密钥与注册信息缓存在 `-acme-cache`，重复运行复用同一账号；`-acme-staging` 可打测试环境。
默认签发 **RSA 2048**（DTLS 需要）。

---

## 证书自动续期（免维护）

只要证书是由**面板的「内置 Let's Encrypt」**签发的，续期就是全自动的：

- 面板签发成功后会写入 `/etc/ocserv-go/acme.json`（域名/服务商/邮箱/凭据路径）和
  `/etc/ocserv-go/acme.env`（凭据，0600）；
- 守护进程启动时检查一次，之后每 **6 小时**检查一次；剩余 **≤30 天**就用内置 lego 自动续期；
- 续期结果**原子写入**证书文件，TLS/DTLS 都是每次握手取当前证书，所以**不需要重启、不会断线**；
- 面板「证书」页会显示「自动续期：已启用 · 服务商 · 剩余 ≤30 天自动续」。

相关参数：`-acme-auto`（默认开）、`-acme-state`（默认 `/etc/ocserv-go/acme.json`）。

手动触发一次检查：重启服务即可（启动即检查）。

> 从 acme.sh 迁移过来时要注意：acme.sh 会自己续期并在续期后重启服务。两者同时开会导致重复签发，
> 建议把 acme.sh 的 cron 停掉（`crontab -l | grep -v acme.sh | crontab -`），由 ocserv-go 接管。

---

## 内置管理面板

面板和 VPN 是同一个二进制，运行时不需要 Node：

```bash
sudo ocserv-go panel -config /etc/ocserv-go/panel.json     # 默认 :19999
```

安装脚本会自动完成这些事：生成 `/etc/ocserv-go/panel.json`、建一个 `admin` 账号并打印随机密码、
写 `ocserv-go-panel.service` 并开机自启。

命令行参数：

| 参数 | 说明 |
|---|---|
| `-config` | 配置文件（默认 `/etc/ocserv-go/panel.json`） |
| `-listen` | 监听地址，覆盖配置 |
| `-init` | 只生成/保存配置后退出（安装脚本用） |
| `-set-password user:pw` | 重置面板账号密码 |
| `-import <旧配置>` | 从旧 Node 面板的 `config.json` 迁移端口/账号/证书路径（旧面板密码是 scrypt，本面板会兼容校验，无需重设） |

面板功能：

- **概览**：服务状态、证书剩余天数、用户数、当前监听
- **VPN 用户**：增删用户、重置密码（写 `ocpasswd`，**改完立即生效**，靠文件热加载）
- **证书**：查看当前证书、自签、上传 PEM、内置 Let's Encrypt（DNS-01）
- **服务配置**：域名/端口/网段/MTU/DNS → 重写 systemd 单元并可一键重启
- **日志**：`journalctl -u ocserv-go`（可自动刷新）
- **面板设置**：改面板密码、查看路径

配置文件示例（`/etc/ocserv-go/panel.json`，0600）：

```json
{
  "title": "ocserv-go 管理面板",
  "listen": ":19999",
  "service": "ocserv-go",
  "bin": "/usr/local/bin/ocserv-go",
  "usersFile": "/etc/ocserv/ocpasswd",
  "certFile": "/etc/ssl/securev/vpn.example.com/fullchain.pem",
  "keyFile": "/etc/ssl/securev/vpn.example.com/privkey.pem",
  "domain": "vpn.example.com",
  "vpnPort": 443,
  "vpnNet": "10.66.66.0/24",
  "vpnMtu": 1400,
  "vpnDns": ["1.1.1.1"]
}
```

### 登录页外观（素材由用户自己提供）

套件**不自带**任何 Cisco 图片 / CSS（厂商素材，不随仓库分发）。想还原手上设备的外观，
可以自己从设备抓取后打包上传：

```bash
# 在与你设备同网段的一台 Linux/macOS 上执行，BASE 换成设备地址
BASE=https://192.168.1.1
for p in /+CSCOE+/logon.html /+CSCOE+/logon_custom.css /+CSCOE+/win.js \
         /+CSCOU+/csco_logo.gif /+CSCOU+/login-header-icon.jpg \
         /+CSCOU+/login-header-middle.jpg /+CSCOU+/login-header-end.jpg; do
  mkdir -p ".$(dirname "$p")"
  curl -sk "$BASE$p" -o ".$p" || true
done
# 抬头蓝色 Banner 的背景图（缺了它 Banner 是空白的）
curl -sk "$BASE/+CSCOU+/gradient.gif?r=255&g=255&b=255" -o ".+CSCOU+/gradient.gif" || true
tar czf cisco-assets.tar.gz +CSCOE+ +CSCOU+
```

然后在面板「登录页外观」页上传这个包（或 `POST /api/assets`，multipart 字段名 `file`）。

服务端行为：

- 先查 `/etc/ocserv-go/assets/<路径>`（即 `-assets` 目录），命中就直接回文件（自动按扩展名给
  Content-Type、带 1 小时缓存）；
- 没命中就回内置占位（1×1 像素图、最小 CSS）；
- 登录页抬头 Banner 靠 `+CSCOU+/login-header-*.jpg` + `+CSCOU+/gradient.gif`（真机页面里写作
  `gradient.gif?r=255&g=255&b=255`，抓取要带 query，存成 `gradient.gif` 即可）；
- 如果包里有 `+CSCOE+/logon.html`，**整页替换**登录页（表单字段仍需 `username` / `password`，
  POST 到 `/+webvpn+/index.html`，与本套件兼容）；
- 只接受 `+CSCOT+` / `+CSCOU+` / `+CSCOE+` 下的路径；拒绝绝对路径、`..`、软链、设备文件；
  总量 ≤ 32MB、单文件 ≤ 8MB、文件数 ≤ 500；包里多带的 README/`.DS_Store` 会被忽略；
- **自动脱敏**：`+CSCOE+/*.html` 里的**连接组名会被替换成固定的 `HetraVPN_Group`**
  （删除原有的 `<option>`、`group_list` 隐藏域，并在全文其它位置清理掉原组名），
  避免把你（或对方）设备的连接组名公开到登录页上。

面板接口：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/assets` | 列出已导入文件、是否含 logon.html、限额 |
| POST | `/api/assets` | 上传 `.tar.gz`（字段 `file`）并解包 |
| DELETE | `/api/assets` | 清空，恢复内置占位页 |

### 前端开发

前端源码在 `web/`（Vue 3 + Vite）：

```bash
cd web && npm install
npm run dev      # 开发：热更新，API 转发到 127.0.0.1:19999
npm run build    # 产物输出到 ocserv-go/panel/webdist/（已入库，go build 不需要 Node）
```

构建产物提交进仓库，所以**用发行版的人完全不用装 Node**；只有改前端时才需要 `npm`。

---

## 验证过什么

`go test ./...`：

- `internal/cstp`：TCP 帧往返、非法魔数、超长拒绝
- `internal/acxml` / `internal/asa`：认证 XML 解析、登录页/错误码/成功响应
- `internal/ippool`：分配/释放/耗尽/非法配置
- `internal/auth`：bcrypt、ocpasswd 的 `user:*:$5$…`、错误密码拒绝
- 根包 `TestTunnelTCP`：ocserv 风格完整链路（TLS 认证 → CONNECT → CSTP → 客户端 gVisor 栈
  → 服务端用户态栈 → 访问宿主 HTTP 服务 → 内容回传）
- 根包 `TestASAStyle`：ASA 风格完整链路（302 → 登录 XML → 错误 → 成功 → 带 cookie 的
  CONNECT → 隧道 UDP 往返）

真客户端（openconnect 9.12）实测：

```
Established DTLS connection (using GnuTLS). Ciphersuite (DTLS1.2)-(ECDHE-RSA)-(AES-256-GCM).
Configured as 10.66.66.2, with SSL connected and DTLS connected
```

连接持续 20 秒无重连；以 `nobody` 用户启动也能正常服务（验证无特权）。

## 已知限制

- **仅 IPv4**；IPv6 包丢弃
- **只实现 AnyConnect/ASA 协议**（标准 OpenConnect 协议不在范围内）
- 无压缩（CSTP 压缩帧未实现）
- 路由固定全局，不下发 split include/exclude
- ICMP 由服务端本地代答（ping 任意地址都回，延迟=到网关 RTT；`-icmp-echo=false` 关闭）
- 出网源地址是运行本进程的机器（上游看到宿主 IP）
- 认证状态按连接维护，没有会话超时/重新认证策略
- 无带宽限制、无多用户审计
- DTLS 需要 RSA 证书

## 目录结构

```
ocserv-go/
├── main.go              # 入口：TLS + HTTP(webvpn) + CSTP/DTLS 隧道
├── internal/
│   ├── asa/             # Cisco ASA 风格页面与 XML
│   ├── acxml/           # ocserv 风格 XML 认证
│   ├── auth/            # 用户库（bcrypt / crypt）
│   ├── cstp/            # CSTP 帧 + DTLS 数据报
│   ├── dtlsx/           # pion/dtls 封装 + 会话预置
│   ├── usrnet/          # gVisor 用户态栈 + TCP/UDP 代理
│   ├── ippool/          # 客户端地址池
│   └── acme/            # 内置 Let's Encrypt（lego）
├── Dockerfile           # 无特权镜像
└── README.md            # 包级说明（指向本文件）
```

## 路线图

- [ ] 面板里给 `-icmp-echo` 加开关（目前是命令行参数）
- [ ] IPv6 隧道
- [ ] CSTP 压缩
- [ ] split 路由（按用户/组）
- [ ] 带宽限制与在线审计
- [ ] 多架构镜像与 CI（构建 + `go test`）
- [ ] 面板里显示内置 ACME 的账号/到期信息

## 许可

[AGPL-3.0-or-later](LICENSE)（与主仓库一致）。
