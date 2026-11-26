// ocserv-go：用 Go 重写 AnyConnect/OpenConnect 服务端，走用户态网络栈，
// 不需要 tun 设备、iptables、ip_forward 或任何内核参数 —— 无特权 LXC / Docker 可用。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/hakureiyuyuko/ocserv-go/internal/acme"
	"github.com/hakureiyuyuko/ocserv-go/internal/acxml"
	"github.com/hakureiyuyuko/ocserv-go/internal/asa"
	"github.com/hakureiyuyuko/ocserv-go/internal/assets"
	"github.com/hakureiyuyuko/ocserv-go/internal/auth"
	"github.com/hakureiyuyuko/ocserv-go/internal/connlog"
	"github.com/hakureiyuyuko/ocserv-go/internal/cstp"
	"github.com/hakureiyuyuko/ocserv-go/internal/dtlsx"
	"github.com/hakureiyuyuko/ocserv-go/internal/ippool"
	"github.com/hakureiyuyuko/ocserv-go/internal/usrnet"
)

const version = "1.1.3"

var (
	addr        = flag.String("addr", ":443", "监听地址")
	certFile    = flag.String("cert", "", "TLS 证书（PEM）")
	keyFile     = flag.String("key", "", "TLS 私钥（PEM）")
	usersFile   = flag.String("users", "", "用户文件（每行 用户名:bcrypt 哈希）")
	serverIP    = flag.String("ip", "10.66.66.1", "隧道内服务端地址")
	clientNet   = flag.String("net", "10.66.66.0/24", "客户端地址池网段")
	dnsStr      = flag.String("dns", "1.1.1.1", "下发给客户端的 DNS（逗号分隔，最多 2 个）")
	mtu         = flag.Int("mtu", 1400, "隧道 MTU")
	dpd         = flag.Int("dpd", 30, "保活间隔（秒）：2×dpd 没收到包就发 DPD，3×dpd 没收到 TCP 包就断开")
	mobileDPD   = flag.Int("mobile-dpd", 30, "移动端 DPD 间隔（秒；0 = 同 -dpd）")
	idleTimeout = flag.Int("idle-timeout", 0, "无用户数据多久断开（秒；0 = 不限制）")
	mobileIdle  = flag.Int("mobile-idle-timeout", 0, "移动端无数据多久断开（秒；0 = 用 -idle-timeout）")
	switchTCP   = flag.Int("switch-to-tcp-timeout", 25, "DTLS 静默多少秒后数据改走 TCP（0 = 不切换）")
	socksAddr   = flag.String("socks", "", "出网走 SOCKS5（host:port，可选；UDP 仍直连）")
	selfSigned  = flag.Bool("self-signed", false, "没有证书时自动生成自签证书（联调用）")
	domain      = flag.String("domain", "ocserv-go.local", "自签证书/默认域使用的域名")
	style       = flag.String("style", "asa", "登录协议风格: asa（模拟 Cisco ASA）或 ocserv")
	httpOnly    = flag.Bool("http", false, "仅用于预览 Web 页面：用明文 HTTP 启动（真实客户端必须用 TLS）")
	dtlsOn      = flag.Bool("dtls", true, "启用 DTLS（UDP 数据面，与 TCP 同端口）")
	dtlsPort    = flag.Int("dtls-port", 0, "DTLS 端口（默认与 -addr 相同）")
	showVer     = flag.Bool("version", false, "显示版本后退出")
	assetsDir   = flag.String("assets", "/etc/ocserv-go/assets", "用户上传的 Cisco 登录页资源目录（图片/CSS/logon.html）")
	connLogPath = flag.String("conn-log", "/etc/ocserv-go/connections.jsonl", "连接日志（JSONL，只记成功连接；空=不记录）")
	acmeAuto    = flag.Bool("acme-auto", true, "按 -acme-state 自动续期证书（面板签发时写入该文件）")
	acmeState   = flag.String("acme-state", "/etc/ocserv-go/acme.json", "自动续期配置（域名/服务商/邮箱/凭据路径）")
	icmpEcho    = flag.Bool("icmp-echo", true, "本地应答客户端的 ICMP ping（返回客户端到网关的延迟；false 则透传/丢弃）")
	acmeOnce    = flag.Bool("acme-once", false, "申请/续期证书后退出（DNS-01，内置 lego）")
	acmeDomain  = flag.String("acme-domain", "", "ACME 域名（-acme-once 时必填）")
	acmeEmail   = flag.String("acme-email", "", "ACME 账号邮箱（可空）")
	acmeDNS     = flag.String("acme-dns", "", "DNS 服务商: cloudflare / alidns / tencentcloud / dnspod")
	acmeCache   = flag.String("acme-cache", "/etc/ocserv-go/acme", "ACME 账号与缓存目录")
	acmeEnv     = flag.String("acme-env", "/etc/ocserv-go/acme.env", "凭据环境变量文件（KEY=VALUE）")
	acmeStage   = flag.Bool("acme-staging", false, "用 Let's Encrypt staging 环境")
	acmeKeyTyp  = flag.String("acme-key-type", "rsa2048", "证书密钥类型: rsa2048 / ec256")
	verbose     = flag.Bool("v", false, "详细日志")
)

type ctxKey struct{}

// session 是一条 TLS 连接上的认证状态。
type session struct {
	mu      sync.Mutex
	user    string
	gotUser bool
	authed  bool
}

func sessionOf(ctx context.Context) *session {
	s, _ := ctx.Value(ctxKey{}).(*session)
	return s
}

// withSession 给每条 TLS 连接挂一个 session（认证状态供后续 CSTP 使用）。
func withSession(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ctxKey{}, &session{})
}

type server struct {
	users      *auth.Users
	certStore  *certStore
	connLog    *connlog.Log
	assetsDir  string
	icmpEcho   bool
	pendMu     sync.Mutex
	pend       map[string]pendEntry
	pool       *ippool.Pool
	dials      usrnet.DialFunc
	mtu        int
	dpd        time.Duration
	mobileDPD  time.Duration
	idle       time.Duration
	mobileIdle time.Duration
	switchTCP  time.Duration
	dns        []string
	prefix     int
	serverIP   net.IP
	domain     string
	style      string
	secure     bool // 是否 TLS（决定 cookie 是否带 Secure）
	start      time.Time

	tokensMu sync.Mutex
	tokens   map[string]string // webvpn cookie → 用户名

	dtlsWant bool
	dtlsLn   *dtlsx.Listener
	dtlsPort int
	tunMu    sync.Mutex
	tunnels  map[string]*tunnel // 客户端 IP → 隧道
}

// tunnel 是一条已建立的 CSTP 隧道（TCP 控制 + 可选 DTLS 数据面）。
type tunnel struct {
	id     string
	dtlsCh chan net.Conn
}

// serverConfig 是 newServer 的入参（便于测试直接构造）。
type serverConfig struct {
	Users             *auth.Users
	ClientNet         string
	ServerIP          string
	MTU               int
	DPD               int
	MobileDPD         int
	IdleTimeout       int
	MobileIdleTimeout int
	SwitchToTCP       int
	DNS               []string
	Domain            string
	Style             string
	Addr              string
	DTLS              bool
	DTLSPort          int
	CertStore         *certStore
	ConnLog           *connlog.Log
	AssetsDir         string
	ICMPEcho          bool
	Dial              usrnet.DialFunc
}

func newServer(c serverConfig) (*server, error) {
	pool, err := ippool.New(c.ClientNet, c.ServerIP)
	if err != nil {
		return nil, err
	}
	_, ipnet, _ := net.ParseCIDR(c.ClientNet)
	ones, _ := ipnet.Mask.Size()
	if c.MTU <= 0 {
		c.MTU = 1400
	}
	s := &server{
		users:      c.Users,
		pool:       pool,
		mtu:        c.MTU,
		dpd:        time.Duration(c.DPD) * time.Second,
		mobileDPD:  time.Duration(c.MobileDPD) * time.Second,
		idle:       time.Duration(c.IdleTimeout) * time.Second,
		mobileIdle: time.Duration(c.MobileIdleTimeout) * time.Second,
		switchTCP:  time.Duration(c.SwitchToTCP) * time.Second,
		dns:        c.DNS,
		prefix:     ones,
		certStore:  c.CertStore,
		connLog:    c.ConnLog,
		assetsDir:  c.AssetsDir,
		icmpEcho:   c.ICMPEcho,
		serverIP:   net.ParseIP(c.ServerIP),
		domain:     c.Domain,
		style:      c.Style,
		start:      time.Now(),
		tokens:     make(map[string]string),
		tunnels:    make(map[string]*tunnel),
		dtlsWant:   c.DTLS,
		dtlsPort:   c.DTLSPort,
	}
	if s.dtlsPort == 0 {
		if _, ps, err := net.SplitHostPort(c.Addr); err == nil {
			s.dtlsPort, _ = strconv.Atoi(ps)
		}
	}
	if c.Dial == nil {
		d := &net.Dialer{}
		s.dials = func(network, addr string) (net.Conn, error) { return d.Dial(network, addr) }
	} else {
		s.dials = c.Dial
	}
	return s, nil
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	if *acmeOnce {
		os.Exit(runACMEOnce())
	}

	// 子命令：内置管理面板
	if flag.Arg(0) == "panel" {
		os.Exit(runPanel())
	}

	// 子命令：生成自签证书（容器首次启动用）
	if flag.Arg(0) == "self-signed" {
		os.Exit(runSelfSigned())
	}

	// 子命令：哈希
	if flag.Arg(0) == "hash" {
		pw := flag.Arg(1)
		if pw == "" {
			fmt.Fprintln(os.Stderr, "用法: ocserv-go hash <密码>")
			os.Exit(2)
		}
		h, err := auth.Hash(pw)
		if err != nil {
			log.Fatalf("生成哈希失败: %v", err)
		}
		fmt.Println(h)
		return
	}

	if *usersFile == "" {
		log.Fatal("必须指定 -users（每行 用户名:bcrypt 哈希；用 `ocserv-go hash` 生成）")
	}
	users, err := auth.Load(*usersFile)
	if err != nil {
		log.Fatalf("读取用户文件失败: %v", err)
	}
	if users.Len() == 0 {
		log.Printf("警告: %s 里没有任何用户，所有登录都会被拒绝（到面板「用户管理」添加）", *usersFile)
	}

	// 证书热加载：磁盘上的证书被续期/替换后，下一次握手自动用新的
	store, err := newCertStore(*certFile, *keyFile, *domain, *selfSigned || *certFile == "" || *keyFile == "")
	if err != nil {
		log.Fatalf("加载证书失败: %v", err)
	}
	if *selfSigned || *certFile == "" || *keyFile == "" {
		log.Printf("使用自签证书（CN=%s），客户端会提示不受信任", *domain)
	}

	s, err := newServer(serverConfig{
		Users:             users,
		ClientNet:         *clientNet,
		ServerIP:          *serverIP,
		MTU:               *mtu,
		DPD:               *dpd,
		MobileDPD:         *mobileDPD,
		IdleTimeout:       *idleTimeout,
		MobileIdleTimeout: *mobileIdle,
		SwitchToTCP:       *switchTCP,
		DNS:               splitCSV(*dnsStr),
		Domain:            *domain,
		Style:             *style,
		Addr:              *addr,
		DTLS:              *dtlsOn && !*httpOnly,
		DTLSPort:          *dtlsPort,
		CertStore:         store,
		ConnLog:           connlog.Open(*connLogPath),
		AssetsDir:         *assetsDir,
		ICMPEcho:          *icmpEcho,
		Dial:              buildDialer(*socksAddr),
	})
	if err != nil {
		log.Fatalf("启动配置错误: %v", err)
	}

	var tlsCfg *tls.Config
	if !*httpOnly {
		tlsCfg, err = tlsConfig(store)
		if err != nil {
			log.Fatalf("TLS 配置失败: %v", err)
		}
	}

	// DTLS 监听（与 TCP 同端口，UDP）。
	// Cisco 的 DTLS 用 ECDHE-RSA 套件，证书必须是 RSA（真机也是）。
	if s.dtlsEnabled() {
		if !store.IsRSA() {
			log.Printf("!! 当前证书不是 RSA，Cisco 风格 DTLS 需要 RSA 证书，DTLS 已禁用")
		} else {
			ln, derr := dtlsx.ListenFunc(fmt.Sprintf(":%d", s.dtlsPort), func() (tls.Certificate, error) {
				c, err := store.Get()
				if err != nil {
					return tls.Certificate{}, err
				}
				return *c, nil
			}, s.mtu, dtlsx.NewStore())
			if derr != nil {
				log.Printf("!! DTLS 启动失败（将只用 TCP）: %v", derr)
			} else {
				s.dtlsLn = ln
				go s.dtlsAcceptLoop()
				log.Printf("DTLS 监听: udp :%d", s.dtlsPort)
			}
		}
	}

	if *acmeAuto && !*httpOnly {
		go runAutoRenew(context.Background(), *acmeState, store, log.Printf)
	}

	hs := &http.Server{
		Addr:        *addr,
		Handler:     s,
		TLSConfig:   tlsCfg,
		ConnContext: withSession,
		ErrorLog:    log.New(io.Discard, "", 0), // 客户端乱发数据时不刷屏
	}

	s.secure = !*httpOnly
	log.Printf("ocserv-go 启动: %s  用户 %v  网段 %s  服务端 %s  MTU %d",
		*addr, users.Names(), *clientNet, *serverIP, *mtu)
	log.Printf("用户态网络栈：不需要 tun / iptables / ip_forward")
	if *httpOnly {
		log.Printf("!! 预览模式：明文 HTTP，仅供浏览器查看页面；真实客户端请用 TLS")
		if err := hs.ListenAndServe(); err != nil {
			log.Fatalf("监听失败: %v", err)
		}
		return
	}
	if err := hs.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("监听失败: %v", err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ocserv-go — 用户态 AnyConnect 服务端

用法:
  ocserv-go -users users.txt -addr :443 [-cert cert.pem -key key.pem] [选项]
  ocserv-go hash <密码>          # 生成用户文件里用的 bcrypt 哈希
  ocserv-go panel [选项]         # 内置管理面板（-supervise 为容器托管模式）
  ocserv-go self-signed -domain vpn.example.com [-cert ... -key ...]

选项:
`)
	flag.PrintDefaults()
}

func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func buildDialer(socks string) usrnet.DialFunc {
	if socks == "" {
		d := &net.Dialer{}
		return func(network, addr string) (net.Conn, error) { return d.Dial(network, addr) }
	}
	sd, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("SOCKS5 配置失败: %v", err)
	}
	d := &net.Dialer{}
	log.Printf("出网经 SOCKS5: %s（UDP 仍直连）", socks)
	return func(network, addr string) (net.Conn, error) {
		if network == "tcp" {
			return sd.Dial(network, addr)
		}
		return d.Dial(network, addr)
	}
}

func tlsConfig(store *certStore) (*tls.Config, error) {
	return &tls.Config{
		// 每次握手都取当前证书：磁盘上的证书被续期/替换后会立即生效
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return store.Get()
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}, nil
}

func makeSelfSigned(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isACMClient(r) {
		rec := &acmRecorder{ResponseWriter: w}
		defer func() {
			log.Printf("AC 请求: %s %s UA=%q agg=%q → %d (%d 字节)",
				r.Method, r.URL.Path, r.UserAgent(), r.Header.Get("X-Aggregate-Auth"), rec.code, rec.n)
		}()
		s.commonHeaders(rec)
		s.route(rec, r)
		return
	}
	s.commonHeaders(w)
	s.route(w, r)
}

// acmRecorder 记录响应码/字节数，并把 Hijack 透传下去（CSTP 需要直接接管连接）。
type acmRecorder struct {
	http.ResponseWriter
	code int
	n    int64
}

func (a *acmRecorder) WriteHeader(c int) {
	if a.code == 0 {
		a.code = c
	}
	a.ResponseWriter.WriteHeader(c)
}

func (a *acmRecorder) Write(b []byte) (int, error) {
	if a.code == 0 {
		a.code = http.StatusOK
	}
	n, err := a.ResponseWriter.Write(b)
	a.n += int64(n)
	return n, err
}

func (a *acmRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := a.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack unsupported")
	}
	return hj.Hijack()
}

func (s *server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	p := path.Clean(r.URL.Path)
	switch {
	case p == "/" || p == ".":
		if r.Method == http.MethodGet {
			if s.style == "ocserv" {
				writeXML(w, acxml.RequestUsername())
				return
			}
			s.handleRootGET(w, r)
			return
		}
		// 任意风格的 POST /：真 AnyConnect 的聚合认证首包就是 POST / + <config-auth type="init">，
		// 回 ocserv 同款的两步式表单（先要用户名），真机客户端才认。
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.handleInit(w, r, body)
	case p == "/+CSCOE+/logon.html":
		if r.Method == http.MethodGet {
			if s.serveAsset(w, r, p, "no-cache") {
				return
			}
			s.handleLogonPage(w, r, "")
			return
		}
		s.handleLogonSubmit(w, r)
	case p == "/+CSCOE+/portal.html":
		s.handlePortal(w, r)
	case p == "/+webvpn+/index.html":
		if r.Method == http.MethodGet {
			s.handleASALoginPage(w, r)
			return
		}
		s.handleASASubmit(w, r)
	case p == "/auth":
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s.handleAuth(w, r, body)
	case p == "/CSTP":
		s.handleConnect(w, r)
	default:
		if s.serveASAStatic(w, r, p) {
			return
		}
		if *verbose {
			log.Printf("%s %s（忽略）", r.Method, r.URL.Path)
		}
		http.NotFound(w, r)
	}
}

// serveAsset 优先返回用户上传的登录页资源。
// 用 assets.Open 打开（内部 os.Root），不把用户给的路径直接交给 ServeFile。
func (s *server) serveAsset(w http.ResponseWriter, r *http.Request, p, cache string) bool {
	f, name, ok := assets.Open(s.assetsDir, p)
	if !ok {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return false
	}
	w.Header().Set("Content-Type", assets.ContentType(name))
	if cache != "" {
		w.Header().Set("Cache-Control", cache)
	}
	http.ServeContent(w, r, name, st.ModTime(), f)
	return true
}

// serveASAStatic 复刻真机会被扫描器探测的静态资源路径（内容是自绘的占位）。
func (s *server) serveASAStatic(w http.ResponseWriter, r *http.Request, p string) bool {
	// 用户自己上传的 Cisco 资源优先（我们不自带厂商素材）
	if r.Method == http.MethodGet {
		if s.serveAsset(w, r, p, "public, max-age=3600") {
			return true
		}
	}
	// 真 ocserv 对这些路径回 200 + 一个小 XML（worker-http-handlers.c get_string_handler），
	// 回 404 会让真 AnyConnect 客户端在隧道建立后立刻重连。
	xmlVpn := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n"
	switch p {
	case "/+CSCOT+/translation-table", "/+CSCOT+/oem-customization", "/VPNManifest.xml", "/1/VPNManifest.xml":
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(xmlVpn))
		return true
	case "/1/binaries/update.txt":
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte("0,0,0000\n"))
		return true
	case "/1/index.html", "/1/Linux", "/1/Linux_64", "/1/Windows", "/1/Windows_ARM64", "/1/Darwin_i386":
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>\n"))
		return true
	case "/+CSCOE+/logon_custom.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(asa.LogonCSS())
		return true
	case "/+CSCOU+/portal.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(asa.PortalCSS())
		return true
	case "/+CSCOE+/win.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(asa.WinJS())
		return true
	case "/+CSCOE+/blank.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html></html>"))
		return true
	case "/+CSCOU+/csco_logo.gif":
		b, ct := asa.TinyImage("gif")
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
		return true
	case "/+CSCOU+/login-header-icon.jpg", "/+CSCOU+/login-header-middle.jpg", "/+CSCOU+/login-header-end.jpg":
		b, ct := asa.TinyImage("jpeg")
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
		return true
	}
	return false
}

// isACMClient 判断请求来自 AnyConnect 客户端（要 XML）还是浏览器（要 HTML）。
func isACMClient(r *http.Request) bool {
	if r.Header.Get("X-Transcend-Version") != "" || r.Header.Get("X-Aggregate-Auth") != "" {
		return true
	}
	return strings.Contains(strings.ToLower(r.UserAgent()), "anyconnect")
}

// commonHeaders 复刻 Cisco ASA 的常见安全头。
func (s *server) commonHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-XSS-Protection", "1")
	h.Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors 'self'; base-uri 'self'; block-all-mixed-content")
	h.Set("Cross-Origin-Opener-Policy", "same-origin-allow-popups")
}

func (s *server) expiredCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", Secure: s.secure,
		Expires: time.Unix(0, 0),
	})
}

// handleRootGET: GET / 的行为与真机一致 —— AnyConnect 客户端拿 302，
// 浏览器拿一页带 JS 跳转的 HTML。
func (s *server) handleRootGET(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(strings.ToLower(r.UserAgent()), "anyconnect") {
		s.expiredCookie(w, "tg")
		w.Header().Set("Location", "/+webvpn+/index.html")
		w.WriteHeader(http.StatusFound)
		return
	}
	for _, n := range []string{"webvpn", "webvpnc", "webvpn_portal", "webvpn_as", "webvpnSharePoint"} {
		s.expiredCookie(w, n)
	}
	http.SetCookie(w, &http.Cookie{Name: "webvpnlogin", Value: "1", Path: "/", HttpOnly: true, Secure: s.secure})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asa.HTMLRedirect())
}

// handleASALoginPage: GET /+webvpn+/index.html
func (s *server) handleASALoginPage(w http.ResponseWriter, r *http.Request) {
	for _, n := range []string{"webvpn", "webvpn_as", "webvpnc"} {
		s.expiredCookie(w, n)
	}
	http.SetCookie(w, &http.Cookie{Name: "webvpnlogin", Value: "1", Path: "/", HttpOnly: true, Secure: s.secure})
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-Transcend-Version", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asa.LoginPage())
}

// handleASASubmit: POST /+webvpn+/index.html（表单或聚合认证 XML，都可能落到这里）
func (s *server) handleASASubmit(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if b := bytes.TrimSpace(body); len(b) > 0 && b[0] == '<' {
		s.handleAuth(w, r, body)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	s.doLogin(w, r)
}

// maskPass 把 XML 里的密码打码，其余原样（排障日志用）。
// 注意：打完码后 <password> 标签仍在，必须从打码位置之后继续找，否则死循环。
func maskPass(b []byte) string {
	s := string(b)
	if len(s) > 1200 {
		s = s[:1200] + "…"
	}
	low := strings.ToLower(s)
	off := 0
	for {
		i := strings.Index(low[off:], "<password>")
		if i < 0 {
			break
		}
		i += off
		j := strings.Index(low[i:], "</password>")
		if j < 0 {
			break
		}
		j += i
		s = s[:i+len("<password>")] + "***" + s[j:]
		low = strings.ToLower(s)
		off = i + len("<password>") + 3
	}
	// 表单编码（application/x-www-form-urlencoded）也要打码
	if i := strings.Index(low, "password="); i >= 0 {
		st := i + len("password=")
		en := strings.IndexByte(s[st:], '&')
		if en < 0 {
			en = len(s) - st
		}
		s = s[:st] + "***" + s[st+en:]
	}
	return s
}

// handleLogonPage 渲染浏览器登录页。
func (s *server) handleLogonPage(w http.ResponseWriter, r *http.Request, errMsg string) {
	csrf := asa.NewCSRF()
	http.SetCookie(w, &http.Cookie{Name: "CSRFtoken", Value: csrf, Path: "/", Secure: s.secure})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asa.LogonPage(csrf, errMsg))
}

// handleLogonSubmit 处理浏览器表单提交（同一套用户库）。
func (s *server) handleLogonSubmit(w http.ResponseWriter, r *http.Request) {
	s.doLogin(w, r)
}

// doLogin 是统一的登录处理：客户端拿 XML，浏览器拿 HTML/跳转。
func (s *server) doLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	user := strings.TrimSpace(r.PostFormValue("username"))
	pass := r.PostFormValue("password")
	client := isACMClient(r)

	if user == "" || !s.users.Verify(user, pass) {
		if user != "" {
			log.Printf("认证失败: %s", user)
		}
		if client {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			w.Header().Set("X-Transcend-Version", "1")
			_, _ = w.Write(asa.LoginFailed("Login failed."))
			return
		}
		s.handleLogonPage(w, r, "Login failed.")
		return
	}

	tok := asa.NewToken()
	s.tokensMu.Lock()
	s.tokens[tok] = user
	s.tokensMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: tok, Path: "/", Secure: s.secure, HttpOnly: true})
	if sess := sessionOf(r.Context()); sess != nil {
		sess.mu.Lock()
		sess.user, sess.authed = user, true
		sess.mu.Unlock()
	}
	log.Printf("认证成功: %s", user)
	if client {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.Header().Set("X-Transcend-Version", "1")
		_, _ = w.Write(asa.Success())
		return
	}
	http.Redirect(w, r, "/+CSCOE+/portal.html", http.StatusFound)
}

// handlePortal 是需要登录的门户页。
func (s *server) handlePortal(w http.ResponseWriter, r *http.Request) {
	user := ""
	if c, err := r.Cookie("webvpn"); err == nil {
		if u, ok := s.tokenUser(c.Value); ok {
			user = u
		}
	}
	if user == "" {
		http.Redirect(w, r, "/+CSCOE+/logon.html", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(asa.PortalPage(user))
}

// tokenUser 通过 webvpn cookie 找用户（CSTP 可能在新连接上发起）。
func (s *server) tokenUser(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()
	u, ok := s.tokens[tok]
	return u, ok
}

func writeXML(w http.ResponseWriter, body []byte) {
	// 与真 ocserv 一致：text/xml + X-Transcend-Version（真 AnyConnect 认这个组合）
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("X-Transcend-Version", "1")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *server) handleInit(w http.ResponseWriter, r *http.Request, body []byte) {
	ca, err := acxml.Parse(body)
	if err != nil {
		if *verbose {
			log.Printf("init XML 解析失败: %v", err)
		}
	} else if *verbose {
		log.Printf("init: client=%s type=%s", ca.Client, ca.Type)
	}
	writeXML(w, acxml.RequestUsername())
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request, body []byte) {
	sess := sessionOf(r.Context())
	ck := ""
	if c, cerr := r.Cookie("webvpncontext"); cerr == nil {
		ck = c.Value
	}
	log.Printf("AC /auth: ctype=%q ctxCookie=%q len=%d body=%s",
		r.Header.Get("Content-Type"), ck, len(body), maskPass(body))

	// 真 AnyConnect（Android）第二步是把它当普通 HTML 表单提交的：
	// application/x-www-form-urlencoded，body 里只有 username=xxx / password=xxx，
	// 不是 config-auth XML —— 两种都要认。
	var user, pass string
	if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		r.Body = io.NopCloser(bytes.NewReader(body))
		_ = r.ParseForm()
		user, pass = strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	} else {
		ca, err := acxml.Parse(body)
		if err != nil {
			log.Printf("AC /auth: XML 解析失败: %v", err)
			writeXML(w, acxml.RequestUsername())
			return
		}
		user, pass = ca.Credentials()
	}

	// 真 ocserv / 真 AnyConnect 是两步式：先发用户名，再只发密码；
	// 用户名靠 webvpncontext cookie 记住（客户端可能在新连接上发第二步）。
	tok := ""
	if c, cerr := r.Cookie("webvpncontext"); cerr == nil {
		tok = c.Value
	}
	if user == "" && tok != "" {
		user = s.pendUser(tok)
	}
	if user == "" {
		writeXML(w, acxml.RequestUsername())
		return
	}
	if tok == "" {
		tok = asa.NewToken()
	}
	http.SetCookie(w, &http.Cookie{Name: "webvpncontext", Value: tok, Path: "/", Secure: s.secure, HttpOnly: true})
	s.pendSet(tok, user)
	if sess != nil {
		sess.mu.Lock()
		sess.user, sess.gotUser = user, true
		sess.mu.Unlock()
	}

	// 还没给密码 → 继续要密码
	if pass == "" {
		writeXML(w, acxml.RequestPassword())
		return
	}

	// 记下客户端提交的凭据（密码打码），排障用
	log.Printf("AC 认证: user=%q passLen=%d body=%s", user, len(pass), maskPass(body))
	if !s.users.Verify(user, pass) {
		log.Printf("认证失败: %s", user)
		writeXML(w, acxml.RequestPassword()) // 与真机一致：重发密码表单
		return
	}
	token := asa.NewToken()
	s.tokensMu.Lock()
	s.tokens[token] = user
	s.tokensMu.Unlock()
	if sess != nil {
		sess.mu.Lock()
		sess.authed = true
		sess.mu.Unlock()
	}
	log.Printf("认证成功: %s", user)
	s.writeSuccess(w, tok, token)
}

// writeSuccess 按 ocserv 的字节回认证成功：
//
//	type="complete" + <version who="sg"> + <auth id="success"><title>SSL VPN Service</title>
//	以及 webvpn / webvpncontext / webvpnc(bu:/&p:t&iu:1/&sh:<证书SHA1>) 三个 cookie。
//
// 真 AnyConnect 客户端靠 webvpnc 里的 &sh: 定位隧道并校验证书，
// 缺了它认证通过后不会继续发 CONNECT。
func (s *server) writeSuccess(w http.ResponseWriter, ctxTok, token string) {
	body := acxml.SuccessComplete()
	certHash := ""
	if s.certStore != nil {
		certHash = s.certStore.Hash()
	}
	h := w.Header()
	h.Set("Content-Type", "text/xml; charset=utf-8")
	h.Set("X-Transcend-Version", "1")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: token, Path: "/", Secure: s.secure, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "webvpnc", Value: "bu:/&p:t&iu:1/&sh:" + certHash, Path: "/", Secure: s.secure, HttpOnly: true})
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// ---- 两步式认证的待定用户名（按 webvpncontext cookie 存，5 分钟过期）----

type pendEntry struct {
	user string
	exp  time.Time
}

func (s *server) pendSet(tok, user string) {
	if tok == "" {
		return
	}
	now := time.Now()
	s.pendMu.Lock()
	if s.pend == nil {
		s.pend = make(map[string]pendEntry)
	}
	for k, v := range s.pend {
		if v.exp.Before(now) {
			delete(s.pend, k)
		}
	}
	s.pend[tok] = pendEntry{user: user, exp: now.Add(5 * time.Minute)}
	s.pendMu.Unlock()
}

func (s *server) pendUser(tok string) string {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	e, ok := s.pend[tok]
	if !ok || e.exp.Before(time.Now()) {
		return ""
	}
	return e.user
}

func (s *server) handleConnect(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r.Context())
	var hs []string
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-cstp") || strings.HasPrefix(lk, "x-dtls") || lk == "cookie" || lk == "user-agent" || lk == "host" {
			hs = append(hs, k+"="+strings.Join(v, ","))
		}
	}
	log.Printf("CONNECT %s 请求头: %s", r.URL.Path, strings.Join(hs, " | "))
	if sess == nil {
		http.Error(w, "no session", http.StatusBadRequest)
		return
	}
	sess.mu.Lock()
	authed, user := sess.authed, sess.user
	sess.mu.Unlock()
	if !authed {
		// ASA 风格：客户端可能带着 webvpn cookie 在新连接上发 CONNECT
		if c, err := r.Cookie("webvpn"); err == nil {
			if u, ok := s.tokenUser(c.Value); ok {
				authed, user = true, u
			}
		}
	}
	if !authed {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	ip := s.pool.Alloc()
	if ip == nil {
		http.Error(w, "address pool exhausted", http.StatusServiceUnavailable)
		return
	}
	defer s.pool.Free(ip)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// DTLS：客户端在 CONNECT 里用 X-DTLS-Master-Secret 给出 48 字节主密钥，
	// 双方据此做「恢复握手」。没有该头就只走 TCP。
	var tun *tunnel
	if s.dtlsEnabled() && s.dtlsLn != nil {
		secret, derr := hex.DecodeString(strings.TrimSpace(r.Header.Get("X-DTLS-Master-Secret")))
		if derr == nil && len(secret) == 48 {
			idRaw := make([]byte, 32)
			if _, err := rand.Read(idRaw); err == nil {
				if serr := s.dtlsLn.Seed(idRaw, secret, dtlsx.SuiteRSA); serr != nil {
					log.Printf("DTLS 会话预置失败: %v", serr)
				} else {
					tun = &tunnel{id: hex.EncodeToString(idRaw), dtlsCh: make(chan net.Conn, 1)}
				}
			}
		} else if *verbose {
			log.Printf("CONNECT 未带有效的 X-DTLS-Master-Secret，不启用 DTLS")
		}
		if tun != nil {
			if peer, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				pip := peer.IP.String()
				s.tunMu.Lock()
				s.tunnels[pip] = tun
				s.tunMu.Unlock()
				defer func() {
					s.tunMu.Lock()
					if s.tunnels[pip] == tun {
						delete(s.tunnels, pip)
					}
					s.tunMu.Unlock()
				}()
			}
		}
	}

	// MTU 协商与真 ocserv 一致：link_mtu = min(1500, 客户端 Base-Mtu)，
	// 数据 MTU = link - 28（无 DTLS 时）。客户端自报 1460 而我们回 1500 时，
	// 真 AnyConnect 会认为配置不自洽并立刻重连。
	linkMTU := 1500
	if v := r.Header.Get("X-Cstp-Base-Mtu"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 800 && n < linkMTU {
			linkMTU = n
		}
	}
	dataMTU := s.mtu
	if maxData := linkMTU - 28; dataMTU > maxData {
		dataMTU = maxData
	}

	// 保活参数：移动端可以单独配 mobile-dpd / mobile-idle-timeout
	lc := liveCfg{dpd: s.dpd, idle: s.idle, switchTCP: s.switchTCP}
	if isMobileRequest(r) {
		if s.mobileDPD > 0 {
			lc.dpd = s.mobileDPD
		}
		if s.mobileIdle > 0 {
			lc.idle = s.mobileIdle
		}
	}

	// 兜底：把底层 TCP 的 keepalive 调短（内核默认 7200 秒，死链要挂两小时）
	if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
		if tc, ok := nc.NetConn().(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(120 * time.Second)
		}
	} else if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(120 * time.Second)
	}

	// 建隧道：直接回裸 HTTP 响应，之后是 CSTP 二进制流。
	// 字段与取值逐项照「能用的」那台 ocserv（dpd=90 / keepalive=32400 /
	// rekey-time=172800+ssl / mtu=1420 / 无 session-timeout 即 none）：
	//   · 发 new-tunnel 或 Session-Timeout-Remaining: 0 会让真客户端立刻
	//     发 DISCONNECT「Reconnecting the VPN tunnel.」并循环重连。
	fmt.Fprintf(conn, "HTTP/1.1 200 CONNECTED\r\n")
	fmt.Fprintf(conn, "X-CSTP-Version: 1\r\n")
	fmt.Fprintf(conn, "X-CSTP-Server-Name: OpenConnect VPN Server\r\n")
	if lc.dpd > 0 {
		fmt.Fprintf(conn, "X-CSTP-DPD: %d\r\n", int(lc.dpd.Seconds()))
	}
	fmt.Fprintf(conn, "X-CSTP-Address: %s\r\n", ip.String())
	fmt.Fprintf(conn, "X-CSTP-Netmask: %s\r\n", s.netmask())
	for i, d := range s.dns {
		if i > 1 {
			break
		}
		fmt.Fprintf(conn, "X-CSTP-DNS: %s\r\n", d)
	}
	fmt.Fprintf(conn, "X-CSTP-Tunnel-All-DNS: true\r\n")
	fmt.Fprintf(conn, "X-CSTP-Client-Bypass-Protocol: false\r\n")
	fmt.Fprintf(conn, "X-CSTP-Keepalive: 32400\r\n")
	if lc.idle > 0 {
		fmt.Fprintf(conn, "X-CSTP-Idle-Timeout: %d\r\n", int(lc.idle.Seconds()))
	} else {
		fmt.Fprintf(conn, "X-CSTP-Idle-Timeout: none\r\n")
	}
	fmt.Fprintf(conn, "X-CSTP-Smartcard-Removal-Disconnect: true\r\n")
	fmt.Fprintf(conn, "X-CSTP-Rekey-Time: 172800\r\n")
	fmt.Fprintf(conn, "X-CSTP-Rekey-Method: ssl\r\n")
	fmt.Fprintf(conn, "X-CSTP-Session-Timeout: none\r\n")
	fmt.Fprintf(conn, "X-CSTP-Disconnected-Timeout: none\r\n")
	fmt.Fprintf(conn, "X-CSTP-Keep: true\r\n")
	fmt.Fprintf(conn, "X-CSTP-TCP-Keepalive: true\r\n")
	fmt.Fprintf(conn, "X-CSTP-License: accept\r\n")
	if tun != nil {
		fmt.Fprintf(conn, "X-DTLS-Session-ID: %s\r\n", tun.id)
		fmt.Fprintf(conn, "X-DTLS-Port: %d\r\n", s.dtlsPort)
		fmt.Fprintf(conn, "X-DTLS-12: 1\r\n")
		if lc.dpd > 0 {
			fmt.Fprintf(conn, "X-DTLS-DPD: %d\r\n", int(lc.dpd.Seconds()))
		}
		fmt.Fprintf(conn, "X-DTLS-MTU: %d\r\n", dataMTU)
		fmt.Fprintf(conn, "X-DTLS12-CipherSuite: %s\r\n", dtlsx.SuiteNameRSA)
	}
	fmt.Fprintf(conn, "X-CSTP-Base-MTU: %d\r\n", linkMTU)
	fmt.Fprintf(conn, "X-CSTP-MTU: %d\r\n", dataMTU)
	fmt.Fprintf(conn, "\r\n")

	log.Printf("隧道建立: 用户=%s 客户端 IP=%s", user, ip)
	if s.connLog != nil {
		peer := ""
		if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			peer = a.IP.String()
		}
		go s.connLog.Record(user, peer)
	}
	defer log.Printf("隧道断开: 用户=%s 客户端 IP=%s", user, ip)

	s.tunnel(r.Context(), conn, brw.Reader, user, ip, tun, dataMTU, lc)
}

func (s *server) dtlsEnabled() bool { return s.dtlsWant }

// isMobileRequest 判断是不是移动端：
// ocserv 看 X-CSTP-Device-Platform（android / apple-ios），AnyConnect 移动版还会发
// X-CSTP-License: mobile，UA 里也带 Android/iPhone/iPad。
func isMobileRequest(r *http.Request) bool {
	if p := strings.ToLower(r.Header.Get("X-CSTP-Device-Platform")); p != "" {
		if strings.Contains(p, "android") || strings.Contains(p, "ios") {
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-CSTP-License")), "mobile") {
		return true
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	return strings.Contains(ua, "android") || strings.Contains(ua, "iphone") ||
		strings.Contains(ua, "ipad") || strings.Contains(ua, "ios")
}

// certIsRSA 判断证书公钥是不是 RSA（Cisco 风格 DTLS 用 ECDHE-RSA 套件）。
func certIsRSA(c tls.Certificate) bool {
	if c.Leaf != nil {
		return c.Leaf.PublicKeyAlgorithm == x509.RSA
	}
	if len(c.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	return err == nil && leaf.PublicKeyAlgorithm == x509.RSA
}

// dtlsAcceptLoop 接受 DTLS 连接，并按客户端 IP 挂到对应隧道上。
func (s *server) dtlsAcceptLoop() {
	for {
		c, err := s.dtlsLn.Accept()
		if err != nil {
			return
		}
		ip := ""
		if a, ok := c.RemoteAddr().(*net.UDPAddr); ok {
			ip = a.IP.String()
		}
		s.attachDTLS(ip, c)
	}
}

func (s *server) attachDTLS(ip string, c net.Conn) {
	s.tunMu.Lock()
	t := s.tunnels[ip]
	s.tunMu.Unlock()
	if t == nil {
		log.Printf("DTLS 连接没有对应隧道（%s），关闭", ip)
		_ = c.Close()
		return
	}
	select {
	case t.dtlsCh <- c:
	default:
		_ = c.Close()
	}
}

func (s *server) netmask() string {
	ones := s.prefix
	var m uint32
	if ones > 0 {
		m = ^uint32(0) << (32 - uint(ones))
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(m>>24), byte(m>>16), byte(m>>8), byte(m))
}

type frame struct {
	typ     cstp.Type
	payload []byte
	viaDTLS bool // 是否强制走 DTLS（DPD 需在同一传输上回）
}

func (s *server) tunnel(ctx context.Context, conn net.Conn, br *bufio.Reader, user string, ip net.IP, tun *tunnel, dataMTU int, lc liveCfg) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	st, err := usrnet.New(ctx, usrnet.Options{
		MTU:           s.mtu,
		ServerIP:      s.serverIP,
		PrefixLen:     s.prefix,
		Dial:          s.dials,
		ICMPEchoReply: s.icmpEcho,
	})
	if err != nil {
		log.Printf("网络栈启动失败: %v", err)
		return
	}
	defer st.Close()

	// 收到的帧（TCP 与 DTLS 两个来源汇到同一个 channel）
	type inFrame struct {
		typ     cstp.Type
		payload []byte
		viaDTLS bool
	}
	in := make(chan inFrame, 256)

	// 保活/死链检测用的时间戳（UnixNano，0 表示还没发生）
	nowNs := func() int64 { return time.Now().UnixNano() }
	var lastTCP, lastUDP, lastData, probeTCP, probeUDP atomic.Int64
	lastTCP.Store(nowNs())
	lastUDP.Store(nowNs())
	lastData.Store(nowNs())
	var dtlsWarned atomic.Bool

	// TCP 控制通道
	go func() {
		for {
			typ, payload, err := cstp.ReadFrame(br)
			if err != nil {
				if *verbose {
					log.Printf("CSTP 读取结束: %v", err)
				}
				cancel()
				return
			}
			lastTCP.Store(nowNs())
			select {
			case in <- inFrame{typ, payload, false}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// DTLS 数据面：一个隧道可能经历多次 DTLS 握手（换网/熄屏恢复后客户端会重新握手）。
	// 这里循环等待新的 DTLS 连接，出错只回落到 TCP，不退出整个隧道。
	var dtlsMu sync.Mutex
	var dtlsConn net.Conn
	defer func() {
		dtlsMu.Lock()
		if dtlsConn != nil {
			_ = dtlsConn.Close()
			dtlsConn = nil
		}
		dtlsMu.Unlock()
	}()
	if tun != nil {
		go func() {
			dbuf := make([]byte, 65536)
			for {
				var c net.Conn
				select {
				case c = <-tun.dtlsCh:
				case <-ctx.Done():
					return
				}
				dtlsMu.Lock()
				dtlsConn = c
				dtlsMu.Unlock()
				lastUDP.Store(nowNs())
				dtlsWarned.Store(false)
				log.Printf("DTLS 数据面已建立: 用户=%s 客户端=%s", user, ip)

				for {
					n, rerr := c.Read(dbuf)
					if rerr != nil {
						dtlsMu.Lock()
						if dtlsConn == c {
							dtlsConn = nil
						}
						dtlsMu.Unlock()
						_ = c.Close()
						log.Printf("DTLS 连接结束（回落到 TCP）: %v", rerr)
						break // 等下一次 DTLS 握手
					}
					if n > 0 {
						lastUDP.Store(nowNs())
						dtlsWarned.Store(false)
					}
					var typ cstp.Type
					var payload []byte
					if n > 0 {
						if t, pl, perr := cstp.ParseDTLS(dbuf[:n]); perr == nil {
							typ, payload = t, append([]byte(nil), pl...)
						}
						if *verbose {
							log.Printf("DTLS 收到: 类型=%d 长度=%d", typ, n-1)
						}
					}
					select {
					case in <- inFrame{typ, payload, true}:
					case <-ctx.Done():
						_ = c.Close()
						return
					}
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}()
	}

	// 所有写操作串行化；DATA 优先走 DTLS，其余（控制帧）走 TCP
	writes := make(chan frame, 512)
	go func() {
		for f := range writes {
			now := time.Now()
			target := conn
			wantDTLS := f.viaDTLS || f.typ == cstp.TypeData
			if wantDTLS {
				dtlsMu.Lock()
				dc := dtlsConn
				dtlsMu.Unlock()
				// 数据帧：DTLS 静默太久就先走 TCP（等价 ocserv 的 switch-to-tcp-timeout）；
				// 客户端再发 UDP 包时 lastUDP 更新，会自动切回 DTLS。
				if dc != nil && (f.viaDTLS || dtlsEgressOK(now, time.Unix(0, lastUDP.Load()), lc)) {
					target = dc
				}
			}
			if *verbose {
				log.Printf("CSTP 发送: 类型=%s(%d) 长度=%d viaDTLS=%v", f.typ, int(f.typ), len(f.payload), target != conn)
			}
			var werr error
			if target != conn {
				if *verbose {
					log.Printf("DTLS 发送: 类型=%d 长度=%d", f.typ, len(f.payload))
				}
				werr = cstp.WriteDTLS(target, f.typ, f.payload)
			} else {
				werr = cstp.WriteFrame(target, f.typ, f.payload)
			}
			if err := werr; err != nil {
				if target != conn {
					// DTLS 写失败：丢弃这帧并回落到 TCP
					dtlsMu.Lock()
					if dtlsConn == target {
						_ = dtlsConn.Close()
						dtlsConn = nil
					}
					dtlsMu.Unlock()
					continue
				}
				cancel()
				return
			}
		}
	}()
	defer close(writes)

	// 栈 → 客户端
	go func() {
		for b := range st.Outbound() {
			select {
			case writes <- frame{cstp.TypeData, b, false}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 保活 / 死链检测：每秒检查一次（语义见 liveness.go 与 ocserv 的 periodic_check）
	go func() {
		if lc.dpd <= 0 && lc.idle <= 0 {
			return
		}
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				dtlsMu.Lock()
				dc := dtlsConn
				dtlsMu.Unlock()

				d := decideLiveness(now, liveClock{
					tcp:      time.Unix(0, lastTCP.Load()),
					udp:      time.Unix(0, lastUDP.Load()),
					data:     time.Unix(0, lastData.Load()),
					probeTCP: time.Unix(0, probeTCP.Load()),
					probeUDP: time.Unix(0, probeUDP.Load()),
				}, dc != nil, lc)

				if d.SendDPDTCP {
					probeTCP.Store(now.UnixNano())
					select {
					case writes <- frame{cstp.TypeDPDReq, nil, false}:
					case <-ctx.Done():
						return
					}
					if *verbose {
						log.Printf("保活: 发 TCP DPD（用户=%s）", user)
					}
				}
				if d.SendDPDUDP {
					probeUDP.Store(now.UnixNano())
					n := dataMTU - 1 // DTLS 上是 [1 字节类型][负载]，总长 ≈ 数据 MTU，兼做 PMTU 探测
					if n < 1 {
						n = 1200
					}
					select {
					case writes <- frame{cstp.TypeDPDReq, make([]byte, n), true}:
					case <-ctx.Done():
						return
					}
					if *verbose {
						log.Printf("保活: 发 DTLS DPD %d 字节（用户=%s）", n+1, user)
					}
				}
				if d.DropDTLS != "" && !dtlsWarned.Swap(true) {
					// 不立刻关 DTLS：保留 socket，客户端再发 UDP 包就能恢复；
					// 数据出口已经在静默超过 switch-to-tcp-timeout 后改走 TCP。
					log.Printf("%s（用户=%s 客户端=%s）", d.DropDTLS, user, ip)
				}
				if d.DropTunnel != "" {
					log.Printf("%s（用户=%s 客户端=%s）", d.DropTunnel, user, ip)
					cancel()
					return
				}
			}
		}
	}()

	for {
		select {
		case f := <-in:
			if *verbose {
				log.Printf("CSTP 收到: 类型=%s(%d) 长度=%d viaDTLS=%v", f.typ, int(f.typ), len(f.payload), f.viaDTLS)
			}
			switch f.typ {
			case cstp.TypeData:
				lastData.Store(nowNs())
				if err := st.Inject(f.payload); err != nil && *verbose {
					log.Printf("注入失败: %v", err)
				}
			case cstp.TypeDPDReq:
				// DTLS 上的 DPD 常用于 MTU 探测：必须回同样长度（type 4）
				var resp []byte
				if f.viaDTLS && len(f.payload) > 0 {
					resp = make([]byte, len(f.payload))
				}
				select {
				case writes <- frame{cstp.TypeDPDResp, resp, f.viaDTLS}:
				case <-ctx.Done():
					return
				}
			case cstp.TypeKeepalive:
				select {
				case writes <- frame{cstp.TypeKeepalive, nil, false}:
				case <-ctx.Done():
					return
				}
			case cstp.TypeDisconnect, cstp.TypeTerminate:
				reason := strings.TrimRight(string(f.payload), "\x00")
				if reason == "" {
					reason = "(无)"
				}
				log.Printf("客户端主动断开: %s  原因=%q", user, reason)
				return
			default:
				if *verbose {
					log.Printf("忽略帧类型 %s（%d 字节）", f.typ, len(f.payload))
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// loadEnvFile 读取 KEY=VALUE 形式的环境变量文件。
func loadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
		_ = os.Setenv(k, v)
	}
	return nil
}

// runACMEOnce 用内置 lego 做 DNS-01 签发，把证书写到 -cert / -key 指定的位置。
func runACMEOnce() int {
	if *acmeDomain == "" {
		log.Printf("X 需要 -acme-domain")
		return 2
	}
	if *acmeDNS == "" {
		log.Printf("X 需要 -acme-dns（%s）", strings.Join(acme.Supported(), " / "))
		return 2
	}
	if *acmeEnv != "" {
		if err := loadEnvFile(*acmeEnv); err != nil {
			log.Printf("! 读取凭据文件 %s 失败: %v（若凭据已在环境变量里可忽略）", *acmeEnv, err)
		}
	}
	certOut := *certFile
	keyOut := *keyFile
	if certOut == "" {
		certOut = "/etc/ssl/securev/" + *acmeDomain + "/fullchain.pem"
	}
	if keyOut == "" {
		keyOut = "/etc/ssl/securev/" + *acmeDomain + "/privkey.pem"
	}

	log.Printf("内置 ACME（DNS-01）: 域名=%s 提供商=%s 缓存=%s staging=%v", *acmeDomain, *acmeDNS, *acmeCache, *acmeStage)
	certPEM, keyPEM, err := acme.Obtain(context.Background(), acme.Config{
		Domain:   *acmeDomain,
		Email:    *acmeEmail,
		Provider: *acmeDNS,
		CacheDir: *acmeCache,
		Staging:  *acmeStage,
		KeyType:  *acmeKeyTyp,
	}, log.Printf)
	if err != nil {
		log.Printf("X 签发失败: %v", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(certOut), 0755); err != nil {
		log.Printf("X 创建证书目录失败: %v", err)
		return 1
	}
	if err := os.WriteFile(certOut, certPEM, 0644); err != nil {
		log.Printf("X 写证书失败: %v", err)
		return 1
	}
	if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
		log.Printf("X 写私钥失败: %v", err)
		return 1
	}
	log.Printf("v 证书已写入 %s / %s", certOut, keyOut)
	return 0
}
