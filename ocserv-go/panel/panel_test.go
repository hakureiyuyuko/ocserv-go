package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashVerify(t *testing.T) {
	c := HashPassword("s3cret!")
	if !VerifyPassword("s3cret!", c) {
		t.Fatal("正确密码应通过")
	}
	if VerifyPassword("wrong", c) {
		t.Fatal("错误密码不应通过")
	}
	if c.Salt == "" || len(c.Hash) != 64 {
		t.Fatalf("摘要格式不对: %+v", c)
	}
}

func TestRenderUnit(t *testing.T) {
	c := DefaultConfig()
	c.Domain = "vpn.example.com"
	c.CertFile = "/etc/ssl/securev/vpn.example.com/fullchain.pem"
	c.KeyFile = "/etc/ssl/securev/vpn.example.com/privkey.pem"
	c.VPNPort = 4443
	c.VPNNet = "192.168.100.0/24"
	c.VPNDNS = []string{"192.168.50.1", "8.8.8.8"}
	u := c.RenderUnit()
	for _, want := range []string{
		"ExecStart=/usr/local/bin/ocserv-go",
		"-addr :4443",
		"-users /etc/ocserv/ocpasswd",
		"-net 192.168.100.0/24",
		"-ip 192.168.100.1", // 网段第一个地址
		"-dns 192.168.50.1,8.8.8.8",
		"-domain vpn.example.com",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Fatalf("单元里缺少 %q\n%s", want, u)
		}
	}
}

func TestUsersAddDel(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ocpasswd")
	if err := AddUser(f, "alice", "pw123456"); err != nil {
		t.Fatal(err)
	}
	users := ReadUsers(f)
	if len(users) != 1 || users[0].Name != "alice" || !users[0].HasHash {
		t.Fatalf("写入后应为 1 个用户: %+v", users)
	}
	// 重置密码应覆盖而不是新增
	if err := AddUser(f, "alice", "newpw123"); err != nil {
		t.Fatal(err)
	}
	if n := len(ReadUsers(f)); n != 1 {
		t.Fatalf("重置密码后仍应 1 个用户，得到 %d", n)
	}
	if err := DelUser(f, "alice"); err != nil {
		t.Fatal(err)
	}
	if n := len(ReadUsers(f)); n != 0 {
		t.Fatalf("删除后应为 0 个用户，得到 %d", n)
	}
	if err := DelUser(f, "alice"); err == nil {
		t.Fatal("删除不存在的用户应报错")
	}
}

func TestUsersValidation(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ocpasswd")
	if err := AddUser(f, "bad name", "pw123456"); err == nil {
		t.Fatal("非法用户名应拒绝")
	}
	if err := AddUser(f, "bob", "123"); err == nil {
		t.Fatal("短密码应拒绝")
	}
}

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "panel.json")
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":19999" || c.VPNPort != 443 {
		t.Fatalf("默认值不对: %+v", c)
	}
	c.PanelUsers["admin"] = HashPassword("admin123")
	c.Domain = "vpn.example.com"
	c.CertFile = certDir("vpn.example.com") + "/fullchain.pem"
	c.KeyFile = certDir("vpn.example.com") + "/privkey.pem"
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	// 权限必须是 0600（里面有面板密码摘要）
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("配置文件权限应为 0600，得到 %v", st.Mode().Perm())
	}
	again, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("admin123", again.PanelUsers["admin"]) {
		t.Fatal("重新加载后面板密码失效")
	}
	if again.SessionSecret == "" {
		t.Fatal("会话密钥应持久化")
	}
}

func TestCertInfoOf(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "fullchain.pem")
	key := filepath.Join(dir, "privkey.pem")
	if err := selfSigned("vpn.example.com", cert, key); err != nil {
		t.Fatal(err)
	}
	ci := certInfoOf(cert)
	if !ci.Exists || ci.Subject != "vpn.example.com" {
		t.Fatalf("解析证书失败: %+v", ci)
	}
	if !ci.IsRSA {
		t.Fatal("自签证书应为 RSA（DTLS 需要）")
	}
	if ci.DaysLeft < 300 {
		t.Fatalf("自签证书有效期应为 ~365 天，剩 %d", ci.DaysLeft)
	}
}
