# ocserv-go（包级说明）

完整文档在仓库根目录的 [`README.md`](../README.md)（分支首页）。这里只留开发时需要的速查。

## 编译与自测

```bash
go build -o bin/ocserv-go .
go test ./...
```

## 容器镜像

```bash
docker build -t ocserv-go .            # Alpine 多阶段构建，约 25MB
docker run --rm ocserv-go -version
```

容器里没有 systemd，入口脚本用 `ocserv-go panel -supervise` 托管 VPN 子进程（面板里能
启动/停止/重启、看日志）。详见仓库根 README 的「Docker」一节。

## 包职责

| 包 | 内容 |
|---|---|
| `main` | 入口：TLS + HTTP(webvpn) + CSTP/DTLS 隧道、用户态栈挂载 |
| `internal/asa` | Cisco ASA 风格的登录页 HTML 与 `<auth>` XML、CSRF/令牌 |
| `internal/acxml` | ocserv 风格 `config-auth` XML |
| `internal/auth` | 用户库：bcrypt 与 ocpasswd 的 `$5$/$6$/$1$` crypt |
| `internal/cstp` | CSTP 帧（TCP）与 DTLS 数据报编解码 |
| `internal/dtlsx` | pion/dtls 封装；用 `SessionStore` 预置 Cisco 的预共享主密钥 |
| `internal/usrnet` | gVisor netstack：注入 IP 包、TCP/UDP 转发（进程内出网） |
| `internal/ippool` | 客户端地址池 |
| `internal/acme` | 内置 Let's Encrypt DNS-01（lego：cloudflare/alidns/tencentcloud/dnspod） |
| `panel` | 管理面板 API + 内嵌前端；`supervisor.go` 是容器模式下的 VPN 进程托管器 |

## 几个容易踩的点

- **CSTP 头**：`'S','T','F',0x01 | 长度(4-5) | 类型(6) | 0(7)`，类型不是字节 3
- **DTLS 帧**：`[1 字节类型][负载]`，没有 8 字节头
- **DTLS 握手**：Cisco 用 `X-DTLS-Master-Secret` 预共享主密钥做恢复握手，头名必须是
  `X-DTLS12-CipherSuite`（带 12）才会按 DTLS 1.2 处理；需要 RSA 证书
- **`channel.Endpoint.Read()` 是非阻塞的**：读栈出口要用 `ReadContext`
- **gVisor 版本**：pin 在 Tailscale 用过的伪版本；最新版曾因测试文件包名不一致无法构建

## 运行示例

```bash
./bin/ocserv-go hash 'pw'            # 生成用户行
./bin/ocserv-go -users users.txt -self-signed -addr :8443 -v
./bin/ocserv-go -http -addr :8080 -users users.txt   # 只看网页
```
