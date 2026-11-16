package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOcpasswdFormat(t *testing.T) {
	h, err := Hash("pw123456")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "ocpasswd")
	// ocpasswd 实际格式：user:*:bcrypt
	if err := os.WriteFile(f, []byte("alice:*:"+h+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	u, err := Load(f)
	if err != nil {
		t.Fatalf("加载 ocpasswd 失败: %v", err)
	}
	if !u.Verify("alice", "pw123456") || u.Verify("alice", "wrong") {
		t.Fatal("ocpasswd 格式校验不正确")
	}
}

func TestLoadOcpasswdSHA256(t *testing.T) {
	// 面板用 ocpasswd 默认的 $5$（SHA-256 crypt）
	dir := t.TempDir()
	f := filepath.Join(dir, "ocpasswd")
	// openssl passwd -5 -salt abcdefgh pw123456 的结果
	const hash = "$5$abcdefgh$4tql4SiJxo3vICFOdxINrIAixirnhiIcTsN7ih.G2E1"
	if err := os.WriteFile(f, []byte("kyaru:*:"+hash+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	u, err := Load(f)
	if err != nil {
		t.Fatalf("加载 $5$ 失败: %v", err)
	}
	if !u.Verify("kyaru", "pw123456") {
		t.Fatal("$5$ 校验失败")
	}
	if u.Verify("kyaru", "bad") {
		t.Fatal("错误密码不应通过")
	}
}
