package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hakureiyuyuko/ocserv-go/internal/acme"
)

func TestShouldRenew(t *testing.T) {
	cases := []struct {
		days, threshold int
		want            bool
	}{
		{89, 30, false},
		{31, 30, false},
		{30, 30, true},
		{7, 30, true},
		{0, 30, true},
		{-1, 30, false}, // 读不到证书时不动
	}
	for _, c := range cases {
		if got := shouldRenew(c.days, c.threshold); got != c.want {
			t.Fatalf("shouldRenew(%d,%d)=%v want %v", c.days, c.threshold, got, c.want)
		}
	}
}

// writeSelfSigned 生成一个指定有效期的自签证书对。
func writeSelfSigned(t *testing.T, dir, cn string, days int) (certPath, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "fullchain.pem")
	keyPath = filepath.Join(dir, "privkey.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	return
}

// 证书文件被改写后，Get() 应自动加载新证书（哈希/剩余天数变化）。
func TestCertStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSigned(t, dir, "a.example.com", 90)
	store, err := newCertStore(certPath, keyPath, "", false)
	if err != nil {
		t.Fatal(err)
	}
	oldHash := store.Hash()
	if oldHash == "" {
		t.Fatal("初始证书哈希为空")
	}
	if d := store.DaysLeft(); d < 80 || d > 95 {
		t.Fatalf("初始证书剩余天数异常: %d", d)
	}
	if !store.IsRSA() {
		t.Fatal("自签 RSA 证书应被识别为 RSA")
	}

	// 换成另一张证书（模拟续期写入）
	time.Sleep(1100 * time.Millisecond) // 让 mtime 一定变化
	newCert, newKey := writeSelfSigned(t, dir, "b.example.com", 30)
	if err := os.Rename(newCert, certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newKey, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(); err != nil {
		t.Fatal(err)
	}
	if store.Hash() == oldHash {
		t.Fatal("证书文件变化后应热加载出新证书")
	}
	if d := store.DaysLeft(); d > 40 {
		t.Fatalf("热加载后剩余天数应约为 30，得到 %d", d)
	}
}

func TestAcmeStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "acme.json")
	if st, err := acme.LoadState(p); err != nil || st != nil {
		t.Fatalf("不存在时应返回 nil: %v %v", st, err)
	}
	in := acme.State{Domain: "vpn.example.com", Provider: "cloudflare", Email: "a@b.c"}
	if err := acme.SaveState(p, in); err != nil {
		t.Fatal(err)
	}
	st, err := acme.LoadState(p)
	if err != nil || st == nil {
		t.Fatalf("读取失败: %v", err)
	}
	if st.Domain != in.Domain || st.Provider != in.Provider {
		t.Fatalf("内容不符: %+v", st)
	}
	if st.EnvFile == "" || st.CacheDir == "" {
		t.Fatalf("默认路径未填充: %+v", st)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("配置权限应为 0600，得到 %v", fi.Mode().Perm())
	}
}
