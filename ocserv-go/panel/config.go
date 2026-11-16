// Package panel 是 ocserv-go 内置的管理面板：HTTP API + 内嵌的 Vue 前端。
//
// 设计目标：整个服务端只有**一个二进制**，运行时不依赖 Node。
// 前端构建产物放在 webdist/ 下，用 go:embed 打进二进制。
package panel

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Credential 是面板账号的加盐 SHA-256 摘要（与旧 Node 面板格式一致，可直接迁移）。
type Credential struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

// Config 是面板配置，持久化为 JSON。
type Config struct {
	Title         string                `json:"title"`
	Listen        string                `json:"listen"`
	Service       string                `json:"service"`
	Bin           string                `json:"bin"`
	UsersFile     string                `json:"usersFile"`
	AssetsDir     string                `json:"assetsDir"`
	AcmeEnv       string                `json:"acmeEnv"`
	CertFile      string                `json:"certFile"`
	KeyFile       string                `json:"keyFile"`
	Domain        string                `json:"domain"`
	VPNPort       int                   `json:"vpnPort"`
	VPNNet        string                `json:"vpnNet"`
	VPNMTU        int                   `json:"vpnMtu"`
	VPNDNS        []string              `json:"vpnDns"`
	SessionSecret string                `json:"sessionSecret"`
	PanelUsers    map[string]Credential `json:"panelUsers"`

	path string
}

// DefaultConfig 返回一份可直接用的默认配置。
func DefaultConfig() *Config {
	return &Config{
		Title:      "ocserv-go 管理面板",
		Listen:     ":19999",
		Service:    "ocserv-go",
		Bin:        "/usr/local/bin/ocserv-go",
		UsersFile:  "/etc/ocserv/ocpasswd",
		AssetsDir:  "/etc/ocserv-go/assets",
		AcmeEnv:    "/etc/ocserv-go/acme.env",
		VPNPort:    443,
		VPNNet:     "10.66.66.0/24",
		VPNMTU:     1400,
		VPNDNS:     []string{"1.1.1.1"},
		PanelUsers: map[string]Credential{},
	}
}

// LoadConfig 读取配置；文件不存在时返回默认配置（并记住路径，首次 Save 时落盘）。
func LoadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	c.path = path
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("配置文件不是合法 JSON: %v", err)
	}
	c.path = path
	c.normalize()
	return c, nil
}

// ImportNodePanel 从旧 Node 面板的 config.json 迁移常用字段（端口/标题/账号/证书路径）。
func (c *Config) ImportNodePanel(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var old struct {
		Title      string                `json:"title"`
		Port       int                   `json:"port"`
		Host       string                `json:"host"`
		Users      map[string]Credential `json:"users"`
		CertFile   string                `json:"certFile"`
		KeyFile    string                `json:"keyFile"`
		Ocpasswd   string                `json:"ocpasswd"`
		AcmeDomain string                `json:"acmeDomain"`
		GoPort     int                   `json:"goPort"`
		GoMTU      int                   `json:"goMTU"`
		GoNet      string                `json:"goNet"`
		GoDNS      string                `json:"goDNS"`
		Backend    string                `json:"backend"`
		Secret     string                `json:"sessionSecret"`
	}
	if err := json.Unmarshal(b, &old); err != nil {
		return fmt.Errorf("旧配置解析失败: %v", err)
	}
	if old.Title != "" {
		c.Title = old.Title
	}
	if old.Port > 0 {
		host := old.Host
		if host == "" {
			host = "0.0.0.0"
		}
		c.Listen = fmt.Sprintf("%s:%d", host, old.Port)
	}
	if len(old.Users) > 0 {
		c.PanelUsers = old.Users
	}
	if old.CertFile != "" {
		c.CertFile = old.CertFile
	}
	if old.KeyFile != "" {
		c.KeyFile = old.KeyFile
	}
	if old.Ocpasswd != "" {
		c.UsersFile = old.Ocpasswd
	}
	if old.AcmeDomain != "" {
		c.Domain = old.AcmeDomain
	}
	if old.GoPort > 0 {
		c.VPNPort = old.GoPort
	}
	if old.GoMTU > 0 {
		c.VPNMTU = old.GoMTU
	}
	if old.GoNet != "" {
		c.VPNNet = old.GoNet
	}
	if old.Secret != "" {
		c.SessionSecret = old.Secret
	}
	if strings.TrimSpace(old.GoDNS) != "" {
		c.VPNDNS = splitCSV(old.GoDNS)
	}
	c.normalize()
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) normalize() {
	d := DefaultConfig()
	if c.Title == "" {
		c.Title = d.Title
	}
	if c.Listen == "" {
		c.Listen = d.Listen
	}
	if c.Service == "" {
		c.Service = d.Service
	}
	if c.Bin == "" {
		c.Bin = d.Bin
	}
	if c.UsersFile == "" {
		c.UsersFile = d.UsersFile
	}
	if c.AssetsDir == "" {
		c.AssetsDir = d.AssetsDir
	}
	if c.AcmeEnv == "" {
		c.AcmeEnv = d.AcmeEnv
	}
	if c.VPNPort == 0 {
		c.VPNPort = d.VPNPort
	}
	if c.VPNNet == "" {
		c.VPNNet = d.VPNNet
	}
	if c.VPNMTU == 0 {
		c.VPNMTU = d.VPNMTU
	}
	if len(c.VPNDNS) == 0 {
		c.VPNDNS = d.VPNDNS
	}
	if c.PanelUsers == nil {
		c.PanelUsers = map[string]Credential{}
	}
	if c.CertFile == "" && c.Domain != "" {
		c.CertFile = filepath.Join(certDir(c.Domain), "fullchain.pem")
	}
	if c.KeyFile == "" && c.Domain != "" {
		c.KeyFile = filepath.Join(certDir(c.Domain), "privkey.pem")
	}
	if c.SessionSecret == "" {
		c.SessionSecret = randomHex(32)
	}
}

// certDir 是套件约定的证书目录。
func certDir(domain string) string { return filepath.Join("/etc/ssl/securev", domain) }

// Save 原子写回配置文件（0600）。
func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("配置没有路径")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 极端情况下退回时间戳，保证不 panic
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// HashPassword 生成 Credential（加盐 SHA-256，与旧面板一致）。
func HashPassword(pw string) Credential {
	salt := randomHex(16)
	sum := sha256.Sum256([]byte(salt + pw))
	return Credential{Salt: salt, Hash: hex.EncodeToString(sum[:])}
}

// VerifyPassword 校验密码（常数时间比较）。
//
// 兼容两种摘要：
//   - 本面板：加盐 SHA-256（64 个 hex 字符）
//   - 旧 Node 面板：crypto.scryptSync(pw, salt, 64)（128 个 hex 字符，N=16384,r=8,p=1）
//
// 这样从旧面板迁移过来的账号不用重设密码。
func VerifyPassword(pw string, c Credential) bool {
	if c.Hash == "" || c.Salt == "" {
		return false
	}
	var got string
	switch len(c.Hash) {
	case 128:
		k, err := scrypt.Key([]byte(pw), []byte(c.Salt), 16384, 8, 1, 64)
		if err != nil {
			return false
		}
		got = hex.EncodeToString(k)
	default:
		sum := sha256.Sum256([]byte(c.Salt + pw))
		got = hex.EncodeToString(sum[:])
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.Hash)) == 1
}

// IsLegacyScrypt 判断这条凭据是否来自旧 Node 面板（scrypt）。
func (c Credential) IsLegacyScrypt() bool { return len(c.Hash) == 128 }

// PanelUsersNames 返回面板账号名（排序后），用于日志展示。
func (c *Config) PanelUsersNames() []string {
	names := make([]string, 0, len(c.PanelUsers))
	for n := range c.PanelUsers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ---- 会话 ----

type session struct {
	User string
	Exp  time.Time
}

type sessions struct {
	mu sync.Mutex
	m  map[string]session
}

func newSessions() *sessions { return &sessions{m: map[string]session{}} }

func (s *sessions) create(user string, ttl time.Duration) string {
	tok := randomHex(24)
	s.mu.Lock()
	s.m[tok] = session{User: user, Exp: time.Now().Add(ttl)}
	s.mu.Unlock()
	return tok
}

func (s *sessions) get(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[tok]
	if !ok || time.Now().After(sess.Exp) {
		delete(s.m, tok)
		return "", false
	}
	return sess.User, true
}

func (s *sessions) drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}
