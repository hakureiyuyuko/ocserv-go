// ocserv-go：用 Go 重写 AnyConnect/OpenConnect 服务端，走用户态网络栈，
// 不需要 tun 设备、iptables、ip_forward 或任何内核参数 —— 无特权 LXC / Docker 可用。
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/acxml"
	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/asa"
	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/auth"
	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/cstp"
	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/ippool"
	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/usrnet"
)

var (
	addr       = flag.String("addr", ":443", "监听地址")
	certFile   = flag.String("cert", "", "TLS 证书（PEM）")
	keyFile    = flag.String("key", "", "TLS 私钥（PEM）")
	usersFile  = flag.String("users", "", "用户文件（每行 用户名:bcrypt 哈希）")
	serverIP   = flag.String("ip", "10.66.66.1", "隧道内服务端地址")
	clientNet  = flag.String("net", "10.66.66.0/24", "客户端地址池网段")
	dnsStr     = flag.String("dns", "1.1.1.1", "下发给客户端的 DNS（逗号分隔，最多 2 个）")
	mtu        = flag.Int("mtu", 1400, "隧道 MTU")
	dpd        = flag.Int("dpd", 30, "保活间隔（秒）")
	socksAddr  = flag.String("socks", "", "出网走 SOCKS5（host:port，可选；UDP 仍直连）")
	selfSigned = flag.Bool("self-signed", false, "没有证书时自动生成自签证书（联调用）")
	domain     = flag.String("domain", "ocserv-go.local", "自签证书/默认域使用的域名")
	style      = flag.String("style", "asa", "登录协议风格: asa（模拟 Cisco ASA）或 ocserv")
	httpOnly   = flag.Bool("http", false, "仅用于预览 Web 页面：用明文 HTTP 启动（真实客户端必须用 TLS）")
	verbose    = flag.Bool("v", false, "详细日志")
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
	users    *auth.Users
	pool     *ippool.Pool
	dials    usrnet.DialFunc
	mtu      int
	dpd      time.Duration
	dns      []string
	prefix   int
	serverIP net.IP
	domain   string
	style    string
	secure   bool // 是否 TLS（决定 cookie 是否带 Secure）
	start    time.Time

	tokensMu sync.Mutex
	tokens   map[string]string // webvpn cookie → 用户名
}

// serverConfig 是 newServer 的入参（便于测试直接构造）。
type serverConfig struct {
	Users     *auth.Users
	ClientNet string
	ServerIP  string
	MTU       int
	DPD       int
	DNS       []string
	Domain    string
	Style     string
	Dial      usrnet.DialFunc
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
		users:    c.Users,
		pool:     pool,
		mtu:      c.MTU,
		dpd:      time.Duration(c.DPD) * time.Second,
		dns:      c.DNS,
		prefix:   ones,
		serverIP: net.ParseIP(c.ServerIP),
		domain:   c.Domain,
		style:    c.Style,
		start:    time.Now(),
		tokens:   make(map[string]string),
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

	s, err := newServer(serverConfig{
		Users:     users,
		ClientNet: *clientNet,
		ServerIP:  *serverIP,
		MTU:       *mtu,
		DPD:       *dpd,
		DNS:       splitCSV(*dnsStr),
		Domain:    *domain,
		Style:     *style,
		Dial:      buildDialer(*socksAddr),
	})
	if err != nil {
		log.Fatalf("启动配置错误: %v", err)
	}

	var tlsCfg *tls.Config
	if !*httpOnly {
		tlsCfg, err = tlsConfig()
		if err != nil {
			log.Fatalf("TLS 配置失败: %v", err)
		}
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

func tlsConfig() (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	switch {
	case *certFile != "" && *keyFile != "":
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return nil, err
		}
	case *selfSigned:
		cert, err = makeSelfSigned(*domain)
		if err != nil {
			return nil, err
		}
		log.Printf("使用自签证书（CN=%s），客户端会提示不受信任", *domain)
	default:
		return nil, fmt.Errorf("需要 -cert/-key，或加 -self-signed 联调")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
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
	s.commonHeaders(w)
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
		if s.style == "ocserv" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			s.handleInit(w, r, body)
			return
		}
		// ASA 对 POST / 返回 404（真机行为）
		http.NotFound(w, r)
	case p == "/+CSCOE+/logon.html":
		if r.Method == http.MethodGet {
			s.handleLogonPage(w, r, "")
			return
		}
		s.handleLogonSubmit(w, r)
	case p == "/+CSCOE+/portal.html":
		s.handlePortal(w, r)
	case p == "/+CSCOE+/logon_custom.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte("/* ocserv-go */\n"))
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

// serveASAStatic 复刻真机会被扫描器探测的静态资源路径（内容是自绘的占位）。
func (s *server) serveASAStatic(w http.ResponseWriter, r *http.Request, p string) bool {
	switch p {
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
	http.SetCookie(w, &http.Cookie{Name: "webvpnlogin", Value: "1", Path: "/", Secure: s.secure})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asa.HTMLRedirect())
}

// handleASALoginPage: GET /+webvpn+/index.html
func (s *server) handleASALoginPage(w http.ResponseWriter, r *http.Request) {
	for _, n := range []string{"webvpn", "webvpn_as", "webvpnc"} {
		s.expiredCookie(w, n)
	}
	http.SetCookie(w, &http.Cookie{Name: "webvpnlogin", Value: "1", Path: "/", Secure: s.secure})
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-Transcend-Version", "1")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(asa.LoginPage())
}

// handleASASubmit: POST /+webvpn+/index.html（表单，不是 XML）
func (s *server) handleASASubmit(w http.ResponseWriter, r *http.Request) {
	s.doLogin(w, r)
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
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
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
	if sess == nil {
		http.Error(w, "no session", http.StatusBadRequest)
		return
	}
	ca, err := acxml.Parse(body)
	if err != nil {
		writeXML(w, acxml.Failure("Login failed (bad request)."))
		return
	}
	user, pass := ca.Credentials()
	if user == "" {
		writeXML(w, acxml.Failure("Please enter your username."))
		return
	}
	sess.mu.Lock()
	sess.user = user
	sess.gotUser = true
	sess.mu.Unlock()

	// 还没给密码 → 继续要密码
	if pass == "" {
		writeXML(w, acxml.RequestPassword())
		return
	}

	if !s.users.Verify(user, pass) {
		log.Printf("认证失败: %s", user)
		writeXML(w, acxml.Failure("Login failed."))
		return
	}
	sess.mu.Lock()
	sess.authed = true
	sess.mu.Unlock()
	log.Printf("认证成功: %s", user)
	writeXML(w, acxml.Success())
}

func (s *server) handleConnect(w http.ResponseWriter, r *http.Request) {
	sess := sessionOf(r.Context())
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

	// 建隧道：直接回裸 HTTP 响应，之后是 CSTP 二进制流
	fmt.Fprintf(conn, "HTTP/1.1 200 CONNECTED\r\n")
	fmt.Fprintf(conn, "X-CSTP-Version: 1\r\n")
	fmt.Fprintf(conn, "X-CSTP-Address: %s\r\n", ip.String())
	fmt.Fprintf(conn, "X-CSTP-Netmask: %s\r\n", s.netmask())
	for i, d := range s.dns {
		if i > 1 {
			break
		}
		fmt.Fprintf(conn, "X-CSTP-DNS: %s\r\n", d)
	}
	fmt.Fprintf(conn, "X-CSTP-MTU: %d\r\n", s.mtu)
	fmt.Fprintf(conn, "X-CSTP-Base-MTU: 1500\r\n")
	fmt.Fprintf(conn, "X-CSTP-DPD: %d\r\n", int(s.dpd.Seconds()))
	fmt.Fprintf(conn, "X-CSTP-Keepalive: 30\r\n")
	fmt.Fprintf(conn, "X-CSTP-Tunnel-All-DNS: true\r\n")
	fmt.Fprintf(conn, "X-CSTP-Default-Domain: %s\r\n", s.domain)
	fmt.Fprintf(conn, "\r\n")

	log.Printf("隧道建立: 用户=%s 客户端 IP=%s", user, ip)
	defer log.Printf("隧道断开: 用户=%s 客户端 IP=%s", user, ip)

	s.tunnel(r.Context(), conn, brw.Reader, user, ip)
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
}

func (s *server) tunnel(ctx context.Context, conn net.Conn, br *bufio.Reader, user string, ip net.IP) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	st, err := usrnet.New(ctx, usrnet.Options{
		MTU:       s.mtu,
		ServerIP:  s.serverIP,
		PrefixLen: s.prefix,
		Dial:      s.dials,
	})
	if err != nil {
		log.Printf("网络栈启动失败: %v", err)
		return
	}
	defer st.Close()

	// 所有写操作串行化，避免帧交错
	writes := make(chan frame, 512)
	go func() {
		for f := range writes {
			if err := cstp.WriteFrame(conn, f.typ, f.payload); err != nil {
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
			case writes <- frame{cstp.TypeData, b}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 保活：定期发 DPD 请求
	go func() {
		if s.dpd <= 0 {
			return
		}
		t := time.NewTicker(s.dpd)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				select {
				case writes <- frame{cstp.TypeDPDReq, nil}:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		typ, payload, err := cstp.ReadFrame(br)
		if err != nil {
			if *verbose {
				log.Printf("CSTP 读取结束: %v", err)
			}
			return
		}
		switch typ {
		case cstp.TypeData:
			if err := st.Inject(payload); err != nil && *verbose {
				log.Printf("注入失败: %v", err)
			}
		case cstp.TypeDPDReq:
			select {
			case writes <- frame{cstp.TypeDPDResp, nil}:
			case <-ctx.Done():
				return
			}
		case cstp.TypeKeepalive:
			select {
			case writes <- frame{cstp.TypeKeepalive, nil}:
			case <-ctx.Done():
				return
			}
		case cstp.TypeDisconnect, cstp.TypeTerminate:
			log.Printf("客户端主动断开: %s", user)
			return
		default:
			if *verbose {
				log.Printf("忽略帧类型 %s（%d 字节）", typ, len(payload))
			}
		}
	}
}
