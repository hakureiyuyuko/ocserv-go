// Package acme 用 lego 在进程内完成 Let's Encrypt DNS-01 签发。
//
// 支持 Cloudflare / 阿里云 / 腾讯云（Tencent Cloud DNS）/ DNSPod。
// 各家凭据走环境变量（与 lego 的约定一致），由调用方从 env 文件注入：
//
//	cloudflare   CF_DNS_API_TOKEN（或 CLOUDFLARE_DNS_API_TOKEN / CLOUDFLARE_EMAIL+CLOUDFLARE_API_KEY）
//	alidns       ALICLOUD_ACCESS_KEY, ALICLOUD_SECRET_KEY
//	tencentcloud TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY
//	dnspod       DNSPOD_API_KEY   （ID,Token 形式）
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"

	"github.com/go-acme/lego/v4/challenge"
)

// Supported 返回支持的 DNS 服务商名字。
func Supported() []string { return []string{"cloudflare", "alidns", "tencentcloud", "dnspod"} }

// Config 是一次签发所需参数。
type Config struct {
	Domain   string
	Email    string
	Provider string
	CacheDir string
	Staging  bool
	// KeyType: "rsa2048"（默认，Cisco DTLS 需要）或 "ec256"
	KeyType string
}

type user struct {
	Email        string                 `json:"email"`
	KeyPEM       []byte                 `json:"key_pem"`
	Registration *registration.Resource `json:"registration,omitempty"`

	key crypto.PrivateKey
}

func (u *user) GetEmail() string                        { return u.Email }
func (u *user) GetRegistration() *registration.Resource { return u.Registration }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

func loadOrCreateUser(cacheDir, email string) (*user, error) {
	path := filepath.Join(cacheDir, "user.json")
	if b, err := os.ReadFile(path); err == nil {
		var u user
		if err := json.Unmarshal(b, &u); err == nil {
			if k, err := parseKey(u.KeyPEM); err == nil {
				u.key = k
				if u.Email == "" {
					u.Email = email
				}
				return &u, nil
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	u := &user{Email: email, KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), key: key}
	return u, nil
}

func (u *user) save(cacheDir string) error {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, "user.json"), b, 0600)
}

func parseKey(pemBytes []byte) (crypto.PrivateKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, fmt.Errorf("私钥 PEM 解析失败")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

func provider(name string) (challenge.Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cloudflare", "cf":
		return cloudflare.NewDNSProvider()
	case "alidns", "aliyun", "ali":
		return alidns.NewDNSProvider()
	case "tencentcloud", "tencent", "dnspod-cloud":
		return tencentcloud.NewDNSProvider()
	case "dnspod", "dp":
		return dnspod.NewDNSProvider()
	default:
		return nil, fmt.Errorf("不支持的 DNS 服务商 %q（支持: %s）", name, strings.Join(Supported(), ", "))
	}
}

// Obtain 申请（或续期）证书，返回证书链与私钥的 PEM。
func Obtain(ctx context.Context, cfg Config, logf func(string, ...interface{})) (certPEM, keyPEM []byte, err error) {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	if cfg.Domain == "" {
		return nil, nil, fmt.Errorf("缺少域名")
	}
	prov, err := provider(cfg.Provider)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, nil, err
	}
	u, err := loadOrCreateUser(cfg.CacheDir, cfg.Email)
	if err != nil {
		return nil, nil, err
	}

	conf := lego.NewConfig(u)
	if cfg.Staging {
		conf.CADirURL = lego.LEDirectoryStaging
	}
	switch strings.ToLower(cfg.KeyType) {
	case "ec256", "ecdsa":
		conf.Certificate.KeyType = certcrypto.EC256
	default:
		conf.Certificate.KeyType = certcrypto.RSA2048 // Cisco 风格 DTLS 需要 RSA
	}
	client, err := lego.NewClient(conf)
	if err != nil {
		return nil, nil, fmt.Errorf("初始化 ACME 客户端失败: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(prov); err != nil {
		return nil, nil, fmt.Errorf("设置 DNS-01 提供商失败: %w", err)
	}
	logf("DNS-01 提供商: %s，域名: %s", cfg.Provider, cfg.Domain)

	// 用同一把账号密钥重复注册是幂等的（会拿回同一个账号）
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("注册 ACME 账号失败: %w", err)
	}
	u.Registration = reg
	_ = u.save(cfg.CacheDir)

	req := certificate.ObtainRequest{Domains: []string{cfg.Domain}, Bundle: true}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return nil, nil, fmt.Errorf("签发失败: %w", err)
	}
	_ = u.save(cfg.CacheDir)
	logf("签发成功，证书到期: %s", res.Certificate)
	return res.Certificate, res.PrivateKey, nil
}

// NewTestKey 生成一个 ECDSA 账号密钥（仅测试用）。
func NewTestKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
