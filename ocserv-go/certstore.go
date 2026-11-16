package main

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// certStore 负责证书的热加载。
//
// TLS/DTLS 握手时按需从磁盘读取证书；文件被改写（ACME 续期、面板上传）
// 后，下一次握手就会用新证书 —— 不需要重启服务、不会断线。
type certStore struct {
	certFile   string
	keyFile    string
	domain     string
	selfSigned bool

	mu    sync.Mutex
	cert  *tls.Certificate
	hash  string // leaf DER 的 SHA1（大写 hex），webvpnc cookie 的 &sh:
	mtime time.Time
}

func newCertStore(certFile, keyFile, domain string, selfSigned bool) (*certStore, error) {
	c := &certStore{certFile: certFile, keyFile: keyFile, domain: domain, selfSigned: selfSigned}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *certStore) reload() error {
	var cert tls.Certificate
	var err error
	if c.selfSigned || c.certFile == "" || c.keyFile == "" {
		cert, err = makeSelfSigned(c.domain)
	} else {
		cert, err = tls.LoadX509KeyPair(c.certFile, c.keyFile)
	}
	if err != nil {
		return err
	}
	hash := ""
	if len(cert.Certificate) > 0 {
		sum := sha1.Sum(cert.Certificate[0])
		hash = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	c.mu.Lock()
	c.cert, c.hash = &cert, hash
	if !c.selfSigned && c.certFile != "" {
		c.mtime = fileMtime(c.certFile, c.keyFile)
	}
	c.mu.Unlock()
	return nil
}

func fileMtime(paths ...string) time.Time {
	var t time.Time
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

// Get 返回当前证书；发现文件更新会先热加载（失败则继续用旧证书）。
func (c *certStore) Get() (*tls.Certificate, error) {
	if !c.selfSigned && c.certFile != "" {
		c.mu.Lock()
		cur := c.mtime
		c.mu.Unlock()
		if m := fileMtime(c.certFile, c.keyFile); m.After(cur) {
			if err := c.reload(); err != nil {
				log.Printf("! 证书热加载失败（继续用旧证书）: %v", err)
				return c.current(), nil
			}
			log.Printf("证书已热加载: %s（%d 天后到期）", c.certFile, c.DaysLeft())
		}
	}
	return c.current(), nil
}

func (c *certStore) current() *tls.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert
}

// Hash 返回当前证书的 SHA1（大写 hex）。
func (c *certStore) Hash() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hash
}

// DaysLeft 返回证书剩余天数；解析失败返回 -1。
func (c *certStore) DaysLeft() int {
	cert := c.current()
	if cert == nil || len(cert.Certificate) == 0 {
		return -1
	}
	crt, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return -1
	}
	return int(time.Until(crt.NotAfter).Hours() / 24)
}

// IsRSA 判断当前证书是否为 RSA（Cisco 风格 DTLS 需要）。
func (c *certStore) IsRSA() bool {
	cert := c.current()
	if cert == nil {
		return false
	}
	return certIsRSA(*cert)
}
