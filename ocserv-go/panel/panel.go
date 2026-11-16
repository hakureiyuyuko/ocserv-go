package panel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hakureiyuyuko/ocserv-go/internal/acme"
	"github.com/hakureiyuyuko/ocserv-go/internal/assets"
	"github.com/hakureiyuyuko/ocserv-go/internal/connlog"
)

// Panel 是管理面板（API + 内嵌前端）。
type Panel struct {
	cfg      *Config
	sessions *sessions
	version  string
	web      http.Handler
	sup      *Supervisor // 非 nil = 容器模式：面板自己托管 VPN 子进程
	init     InitKind    // systemd / openrc / none（构造时按环境探测）
}

// New 构造面板。version 会显示在页面上。
func New(cfg *Config, version string) *Panel {
	return &Panel{
		cfg:      cfg,
		sessions: newSessions(),
		version:  version,
		web:      newWebHandler(),
		init:     DetectInit(cfg.Service),
	}
}

// Supervise 让面板托管 VPN 子进程（容器/无 systemd 环境用）。
func (p *Panel) Supervise(s *Supervisor) { p.sup = s }

// Supervised 报告是否处于托管模式。
func (p *Panel) Supervised() bool { return p.sup != nil }

// SetInit 覆盖探测结果（测试或显式指定用）。
func (p *Panel) SetInit(k InitKind) { p.init = k }

// Config 返回当前配置（只读用）。
func (p *Panel) Config() *Config { return p.cfg }

// Handler 返回整个面板的 http.Handler。
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", p.handleLogin)
	mux.HandleFunc("POST /api/logout", p.withAuth(p.handleLogout))
	mux.HandleFunc("GET /api/me", p.withAuth(p.handleMe))

	mux.HandleFunc("GET /api/overview", p.withAuth(p.handleOverview))
	mux.HandleFunc("GET /api/users", p.withAuth(p.handleUsersList))
	mux.HandleFunc("POST /api/users", p.withAuth(p.handleUsersPost))
	mux.HandleFunc("POST /api/service", p.withAuth(p.handleService))
	mux.HandleFunc("GET /api/logs", p.withAuth(p.handleLogs))
	mux.HandleFunc("GET /api/connections", p.withAuth(p.handleConnections))
	mux.HandleFunc("GET /api/assets", p.withAuth(p.handleAssetsGet))
	mux.HandleFunc("POST /api/assets", p.withAuth(p.handleAssetsUpload))
	mux.HandleFunc("DELETE /api/assets", p.withAuth(p.handleAssetsClear))
	mux.HandleFunc("GET /api/cert", p.withAuth(p.handleCertInfo))
	mux.HandleFunc("GET /api/cert/providers", p.withAuth(p.handleCertProviders))
	mux.HandleFunc("POST /api/cert", p.withAuth(p.handleCertPost))
	mux.HandleFunc("GET /api/config", p.withAuth(p.handleConfigGet))
	mux.HandleFunc("POST /api/config", p.withAuth(p.handleConfigPost))
	mux.HandleFunc("POST /api/panel/password", p.withAuth(p.handlePanelPassword))
	mux.HandleFunc("GET /api/panel", p.withAuth(p.handlePanelInfo))

	mux.Handle("/", p.web)
	return mux
}

// ---- 基础工具 ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func sessionToken(r *http.Request) string {
	if c, err := r.Cookie("sid"); err == nil {
		return c.Value
	}
	return ""
}

func (p *Panel) withAuth(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-Panel") != "1" {
			fail(w, http.StatusForbidden, "缺少 X-Panel 头")
			return
		}
		user, ok := p.sessions.get(sessionToken(r))
		if !ok {
			fail(w, http.StatusUnauthorized, "未登录")
			return
		}
		h(w, r, user)
	}
}

// ---- 登录 ----

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Panel") != "1" {
		fail(w, http.StatusForbidden, "缺少 X-Panel 头")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cred, ok := p.cfg.PanelUsers[in.Username]
	if !ok || !VerifyPassword(in.Password, cred) {
		fail(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	tok := p.sessions.create(in.Username, 12*time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": in.Username})
}

func (p *Panel) handleLogout(w http.ResponseWriter, r *http.Request, _ string) {
	p.sessions.drop(sessionToken(r))
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) handleMe(w http.ResponseWriter, _ *http.Request, user string) {
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "version": p.version, "title": p.cfg.Title})
}

// ---- 概览 ----

func (p *Panel) handleOverview(w http.ResponseWriter, _ *http.Request, _ string) {
	active, enabled := p.ServiceState()
	users := ReadUsers(p.cfg.UsersFile)
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service": map[string]any{
			"name": p.cfg.Service, "active": active, "enabled": enabled,
			"port": p.cfg.VPNPort,
		},
		"cert":  p.CertInfo(),
		"users": map[string]any{"count": len(users), "names": names},
		"config": map[string]any{
			"domain": p.cfg.Domain, "vpnPort": p.cfg.VPNPort, "vpnNet": p.cfg.VPNNet,
			"vpnMtu": p.cfg.VPNMTU, "vpnDns": p.cfg.VPNDNS,
		},
		"version": p.version,
	})
}

// ---- 用户 ----

func (p *Panel) handleUsersList(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"users": ReadUsers(p.cfg.UsersFile)})
}

func (p *Panel) handleUsersPost(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct {
		Action   string `json:"action"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	var err error
	switch in.Action {
	case "add", "passwd":
		err = AddUser(p.cfg.UsersFile, in.Name, in.Password)
	case "del":
		err = DelUser(p.cfg.UsersFile, in.Name)
	default:
		fail(w, http.StatusBadRequest, "未知操作")
		return
	}
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	// ocserv-go 会按文件 mtime 自动热加载用户库，无需重启
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": ReadUsers(p.cfg.UsersFile)})
}

// ---- 服务控制 ----

func (p *Panel) handleService(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if err := p.ServiceAction(in.Action); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	time.Sleep(800 * time.Millisecond)
	active, enabled := p.ServiceState()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active": active, "enabled": enabled})
}

// handleConnections 返回连接日志（最近 N 条，时间倒序）。
func (p *Panel) handleConnections(w http.ResponseWriter, r *http.Request, _ string) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	recs, total, err := connlog.Read(p.cfg.ConnLog, limit, user, q)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records": recs, "count": len(recs), "total": total, "file": p.cfg.ConnLog,
	})
}

func (p *Panel) handleLogs(w http.ResponseWriter, r *http.Request, _ string) {
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	writeJSON(w, http.StatusOK, map[string]any{"text": p.Logs(n)})
}

// ---- 登录页外观（用户自己上传的 Cisco 资源）----

func (p *Panel) handleAssetsGet(w http.ResponseWriter, _ *http.Request, _ string) {
	files := assets.List(p.cfg.AssetsDir)
	if files == nil {
		files = []assets.File{} // 空时也要返回 []，否则前端拿到 null
	}
	hasLogon := false
	for _, f := range files {
		if strings.EqualFold(f.Path, "+CSCOE+/logon.html") {
			hasLogon = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dir": p.cfg.AssetsDir, "files": files, "count": len(files), "hasLogon": hasLogon,
		"limits": map[string]any{"maxTotalMB": assets.MaxTotalSize >> 20, "maxFileMB": assets.MaxFileSize >> 20, "maxFiles": assets.MaxFiles},
	})
}

func (p *Panel) handleAssetsUpload(w http.ResponseWriter, r *http.Request, _ string) {
	// 限制请求体，避免超大上传把内存/磁盘打满
	r.Body = http.MaxBytesReader(w, r.Body, assets.MaxTotalSize+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		fail(w, http.StatusBadRequest, "解析上传内容失败（需要 multipart/form-data，字段名 file）: "+err.Error())
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, http.StatusBadRequest, "没有收到文件（字段名应为 file）")
		return
	}
	defer f.Close()
	if !strings.HasSuffix(strings.ToLower(hdr.Filename), ".tar.gz") && !strings.HasSuffix(strings.ToLower(hdr.Filename), ".tgz") {
		fail(w, http.StatusBadRequest, "请上传 .tar.gz / .tgz 包")
		return
	}
	files, err := assets.Extract(f, p.cfg.AssetsDir)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "files": files, "count": len(files)})
}

func (p *Panel) handleAssetsClear(w http.ResponseWriter, _ *http.Request, _ string) {
	if err := assets.Clear(p.cfg.AssetsDir); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- 证书 ----

// acmeField 是某个 DNS 服务商需要的凭据字段（写进环境变量，与 lego 约定一致）。
type acmeField struct {
	K     string `json:"k"`
	Label string `json:"label"`
	Hint  string `json:"hint,omitempty"`
}

type acmeProvider struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Fields []acmeField `json:"fields"`
}

var acmeProviders = []acmeProvider{
	{"cloudflare", "Cloudflare", []acmeField{
		{"CF_DNS_API_TOKEN", "API Token", "Zone → DNS → Edit 权限即可，创建时只显示一次"},
	}},
	{"alidns", "阿里云 DNS", []acmeField{
		{"ALICLOUD_ACCESS_KEY", "AccessKey ID", ""},
		{"ALICLOUD_SECRET_KEY", "AccessKey Secret", ""},
	}},
	{"tencentcloud", "腾讯云 DNSPod", []acmeField{
		{"TENCENTCLOUD_SECRET_ID", "SecretId", ""},
		{"TENCENTCLOUD_SECRET_KEY", "SecretKey", ""},
	}},
	{"dnspod", "DNSPod Token", []acmeField{
		{"DNSPOD_API_KEY", "ID,Token", "形如 12345,abcdefg…"},
	}},
}

func (p *Panel) handleCertProviders(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": acmeProviders, "envFile": p.cfg.AcmeEnv})
}

func (p *Panel) handleCertInfo(w http.ResponseWriter, _ *http.Request, _ string) {
	ci := p.CertInfo()
	st, _ := acme.LoadState(p.cfg.AcmeState)
	auto := map[string]any{"enabled": st != nil, "stateFile": p.cfg.AcmeState, "thresholdDays": 30}
	if st != nil {
		auto["domain"] = st.Domain
		auto["provider"] = st.Provider
		auto["staging"] = st.Staging
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exists": ci.Exists, "subject": ci.Subject, "issuer": ci.Issuer,
		"notAfter": ci.NotAfter, "daysLeft": ci.DaysLeft, "san": ci.SAN, "isRsa": ci.IsRSA,
		"autoRenew": auto,
	})
}

func (p *Panel) handleCertPost(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct {
		Action   string            `json:"action"` // selfsigned | upload | acme
		Domain   string            `json:"domain"`
		Cert     string            `json:"cert"`
		Key      string            `json:"key"`
		Email    string            `json:"email"`
		Provider string            `json:"provider"`
		Staging  bool              `json:"staging"`
		Creds    map[string]string `json:"creds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	domain := strings.TrimSpace(in.Domain)
	if domain == "" {
		domain = p.cfg.Domain
	}
	if domain == "" {
		fail(w, http.StatusBadRequest, "请先填写域名")
		return
	}
	certDir := certDir(domain)
	certFile := certDir + "/fullchain.pem"
	keyFile := certDir + "/privkey.pem"

	switch in.Action {
	case "selfsigned":
		if err := osMkdirAll(certDir); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := SelfSigned(domain, certFile, keyFile); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	case "upload":
		if err := osMkdirAll(certDir); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !strings.Contains(in.Cert, "BEGIN CERTIFICATE") || !strings.Contains(in.Key, "PRIVATE KEY") {
			fail(w, http.StatusBadRequest, "证书或私钥不像 PEM")
			return
		}
		if err := osWrite(certFile, in.Cert, 0o644); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := osWrite(keyFile, in.Key, 0o600); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	case "acme":
		if in.Provider == "" {
			fail(w, http.StatusBadRequest, "请选择 DNS 服务商")
			return
		}
		var meta *acmeProvider
		for i := range acmeProviders {
			if acmeProviders[i].ID == in.Provider {
				meta = &acmeProviders[i]
				break
			}
		}
		if meta == nil {
			fail(w, http.StatusBadRequest, "不支持的 DNS 服务商")
			return
		}
		// 凭据缺失检查（给出具体字段名）
		var missing []string
		for _, f := range meta.Fields {
			if strings.TrimSpace(in.Creds[f.K]) == "" {
				missing = append(missing, f.K)
			}
		}
		if len(missing) > 0 {
			fail(w, http.StatusBadRequest, "请填写凭据："+strings.Join(missing, ", "))
			return
		}
		if err := osMkdirAll(certDir); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		certPEM, keyPEM, err := obtainWithCreds(ctx, p.cfg.AcmeEnv, acme.Config{
			Domain: domain, Email: in.Email, Provider: in.Provider,
			CacheDir: "/etc/ocserv-go/acme", Staging: in.Staging, KeyType: "rsa2048",
		}, in.Creds)
		if err != nil {
			fail(w, http.StatusBadGateway, "ACME 签发失败: "+err.Error())
			return
		}
		if err := osWrite(certFile, string(certPEM), 0o644); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := osWrite(keyFile, string(keyPEM), 0o600); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	default:
		fail(w, http.StatusBadRequest, "未知操作")
		return
	}

	// ACME 签发成功：把续期参数交给守护进程（它按这个文件自动续期）
	if in.Action == "acme" {
		_ = acme.SaveState(p.cfg.AcmeState, acme.State{
			Domain: domain, Provider: in.Provider, Email: in.Email,
			Staging: in.Staging, EnvFile: p.cfg.AcmeEnv, CacheDir: "/etc/ocserv-go/acme",
		})
	}

	p.cfg.Domain = domain
	p.cfg.CertFile = certFile
	p.cfg.KeyFile = keyFile
	if err := p.cfg.Save(); err != nil {
		fail(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert": certInfoOf(certFile)})
}

// ---- 配置（VPN 参数）----

func (p *Panel) handleConfigGet(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": p.cfg.Domain, "vpnPort": p.cfg.VPNPort, "vpnNet": p.cfg.VPNNet,
		"vpnMtu": p.cfg.VPNMTU, "vpnDns": p.cfg.VPNDNS,
		// 托管模式没有服务脚本（参数直接交给子进程），OpenRC/systemd 展示对应文本
		"unit": p.ServiceScript(), "mode": p.ModeName(),
	})
}

func (p *Panel) handleConfigPost(w http.ResponseWriter, r *http.Request, _ string) {
	var in struct {
		Domain  string   `json:"domain"`
		VPNPort int      `json:"vpnPort"`
		VPNNet  string   `json:"vpnNet"`
		VPNMTU  int      `json:"vpnMtu"`
		VPNDNS  []string `json:"vpnDns"`
		Apply   bool     `json:"apply"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if _, _, err := net.ParseCIDR(in.VPNNet); err != nil {
		fail(w, http.StatusBadRequest, "客户端网段不合法（形如 10.66.66.0/24）")
		return
	}
	if in.VPNPort < 1 || in.VPNPort > 65535 {
		fail(w, http.StatusBadRequest, "端口不合法")
		return
	}
	if in.VPNMTU < 576 || in.VPNMTU > 1500 {
		fail(w, http.StatusBadRequest, "MTU 应在 576~1500")
		return
	}
	if len(in.VPNDNS) == 0 {
		fail(w, http.StatusBadRequest, "至少填一个 DNS")
		return
	}
	p.cfg.Domain = strings.TrimSpace(in.Domain)
	p.cfg.VPNPort = in.VPNPort
	p.cfg.VPNNet = in.VPNNet
	p.cfg.VPNMTU = in.VPNMTU
	p.cfg.VPNDNS = in.VPNDNS
	if p.cfg.Domain != "" && p.cfg.CertFile == "" {
		p.cfg.CertFile = certDir(p.cfg.Domain) + "/fullchain.pem"
		p.cfg.KeyFile = certDir(p.cfg.Domain) + "/privkey.pem"
	}
	if err := p.cfg.Save(); err != nil {
		fail(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	if err := p.WriteService(); err != nil {
		fail(w, http.StatusInternalServerError, "写入服务脚本失败: "+err.Error())
		return
	}
	if in.Apply {
		if err := p.ServiceAction("restart"); err != nil {
			fail(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unit": p.ServiceScript(), "mode": p.ModeName()})
}

// ---- 面板自身 ----

func (p *Panel) handlePanelInfo(w http.ResponseWriter, _ *http.Request, user string) {
	names := make([]string, 0, len(p.cfg.PanelUsers))
	for n := range p.cfg.PanelUsers {
		names = append(names, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": p.version, "title": p.cfg.Title, "listen": p.cfg.Listen,
		"users": names, "me": user,
		"usersFile": p.cfg.UsersFile, "certFile": p.cfg.CertFile, "keyFile": p.cfg.KeyFile,
	})
}

func (p *Panel) handlePanelPassword(w http.ResponseWriter, r *http.Request, user string) {
	var in struct {
		Old string `json:"oldPassword"`
		New string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	cred, ok := p.cfg.PanelUsers[user]
	if !ok || !VerifyPassword(in.Old, cred) {
		fail(w, http.StatusBadRequest, "当前密码不正确")
		return
	}
	if len(in.New) < 6 {
		fail(w, http.StatusBadRequest, "新密码至少 6 位")
		return
	}
	p.cfg.PanelUsers[user] = HashPassword(in.New)
	if err := p.cfg.Save(); err != nil {
		fail(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- 自签证书 ----

// SelfSigned 生成自签 RSA 证书（Cisco DTLS 要求 RSA）并写盘。
func SelfSigned(domain, certFile, keyFile string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := osWrite(certFile, string(certPEM), 0o644); err != nil {
		return err
	}
	return osWrite(keyFile, string(keyPEM), 0o600)
}

func osWrite(path, body string, mode os.FileMode) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body), mode)
}

func osMkdirAll(dir string) error { return os.MkdirAll(dir, 0o755) }

func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "."
	}
	return p[:i]
}

// acmeEnvMu 保护临时设置的环境变量（lego 的服务商从环境变量读凭据）。
var acmeEnvMu sync.Mutex

// obtainWithCreds 把凭据注入环境变量后调用 acme.Obtain，结束后恢复，
// 并把凭据写入 0600 的 env 文件（供命令行 -acme-once / 续期复用）。
func obtainWithCreds(ctx context.Context, envFile string, cfg acme.Config, creds map[string]string) ([]byte, []byte, error) {
	acmeEnvMu.Lock()
	defer acmeEnvMu.Unlock()

	type saved struct {
		v   string
		had bool
	}
	old := map[string]saved{}
	for k, v := range creds {
		if !validEnvKey(k) {
			return nil, nil, fmt.Errorf("非法环境变量名: %q", k)
		}
		prev, had := os.LookupEnv(k)
		old[k] = saved{prev, had}
		_ = os.Setenv(k, strings.TrimSpace(v))
	}
	defer func() {
		for k, s := range old {
			if s.had {
				_ = os.Setenv(k, s.v)
			} else {
				_ = os.Unsetenv(k)
			}
		}
	}()

	if envFile != "" {
		var b strings.Builder
		b.WriteString("# 由面板「证书」页写入；权限 600，勿提交到版本库\n")
		keys := make([]string, 0, len(creds))
		for k := range creds {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(k + "=" + strings.TrimSpace(creds[k]) + "\n")
		}
		if err := os.MkdirAll(dirOf(envFile), 0o755); err == nil {
			_ = os.WriteFile(envFile, []byte(b.String()), 0o600)
		}
	}

	return acme.Obtain(ctx, cfg, func(string, ...any) {})
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
