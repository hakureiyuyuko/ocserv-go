package panel

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
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
	if err := SelfSigned("vpn.example.com", cert, key); err != nil {
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

// 旧 Node 面板用 scrypt 存密码，迁移后必须还能验证。
func TestVerifyLegacyScrypt(t *testing.T) {
	pw := "svw817899"
	salt := "0123456789abcdef"
	k, err := scrypt.Key([]byte(pw), []byte(salt), 16384, 8, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	cred := Credential{Salt: salt, Hash: hex.EncodeToString(k)}
	if !cred.IsLegacyScrypt() {
		t.Fatal("应识别为 legacy scrypt")
	}
	if !VerifyPassword(pw, cred) {
		t.Fatal("scrypt 摘要应能通过校验")
	}
	if VerifyPassword("wrong", cred) {
		t.Fatal("错误密码不应通过")
	}
	// 本面板新写入的仍是 sha256，且必须能验证
	nc := HashPassword("newpw123")
	if nc.IsLegacyScrypt() || !VerifyPassword("newpw123", nc) {
		t.Fatal("新格式校验失败")
	}
}

func TestVPNArgsMatchesUnit(t *testing.T) {
	c := DefaultConfig()
	c.Domain = "vpn.example.com"
	c.CertFile = "/etc/ssl/securev/vpn.example.com/fullchain.pem"
	c.KeyFile = "/etc/ssl/securev/vpn.example.com/privkey.pem"
	args := strings.Join(VPNArgs(c), " ")
	unit := c.RenderUnit()
	for _, want := range []string{
		"-addr :443", "-users /etc/ocserv/ocpasswd", "-net 10.66.66.0/24",
		"-ip 10.66.66.1", "-domain vpn.example.com", "-assets /etc/ocserv-go/assets",
		"-conn-log /etc/ocserv-go/connections.jsonl",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("VPNArgs 缺少 %q: %s", want, args)
		}
		if !strings.Contains(unit, want) {
			t.Fatalf("单元文件缺少 %q（RenderUnit 应与 VPNArgs 一致）", want)
		}
	}
}

func TestLogRing(t *testing.T) {
	r := newLogRing(3)
	for _, s := range []string{"a", "b", "c", "d"} {
		r.add(s)
	}
	got := r.tail(2)
	if !strings.Contains(got, "c") || !strings.Contains(got, "d") || strings.Contains(got, "b") {
		t.Fatalf("环形缓冲只该留最近几行: %q", got)
	}
	if r.cap() != 3 {
		t.Fatalf("容量应为 3: %d", r.cap())
	}
}

func TestSupervisorLifecycle(t *testing.T) {
	sup := NewSupervisor("sh", []string{"-c", "echo ocserv-go-test-line; sleep 30"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.Run(ctx)

	waitFor := func(active bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			a, _ := sup.State()
			if (a == "active") == active {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatalf("等不到子进程状态 active=%v", active)
	}

	waitFor(true)
	time.Sleep(200 * time.Millisecond)
	if logs := sup.Logs(50); !strings.Contains(logs, "ocserv-go-test-line") {
		t.Fatalf("日志里应有子进程输出: %q", logs)
	}
	if err := sup.Do("stop"); err != nil {
		t.Fatalf("停止失败: %v", err)
	}
	waitFor(false)
	if err := sup.Do("start"); err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	waitFor(true)
	if err := sup.Do("restart"); err != nil {
		t.Fatalf("重启失败: %v", err)
	}
	waitFor(true)
	if err := sup.Do("bogus"); err == nil {
		t.Fatal("未知动作应报错")
	}

	cancel()
	select {
	case <-sup.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("Run 没在 ctx 取消后退出")
	}
	waitFor(false)
}

func TestClassifyInit(t *testing.T) {
	cases := []struct {
		name                string
		systemd, rc, rcUnit bool
		want                InitKind
	}{
		{"systemd 优先", true, true, true, InitSystemd},
		{"OpenRC", false, true, true, InitOpenRC},
		{"有 rc-service 但没有服务脚本", false, true, false, InitNone},
		{"精简容器（都没有）", false, false, false, InitNone},
	}
	for _, c := range cases {
		if got := classifyInit(c.systemd, c.rc, c.rcUnit); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestRenderOpenRC(t *testing.T) {
	c := DefaultConfig()
	c.Domain = "vpn.example.com"
	c.CertFile = "/etc/ssl/securev/vpn.example.com/fullchain.pem"
	c.KeyFile = "/etc/ssl/securev/vpn.example.com/privkey.pem"
	s := c.RenderOpenRC()
	for _, want := range []string{
		"#!/sbin/openrc-run",
		`command="/usr/local/bin/ocserv-go"`,
		"-addr :443",
		"-domain vpn.example.com",
		"command_background=true",
		`pidfile="/run/ocserv-go.pid"`,
		`output_log="/var/log/ocserv-go.log"`,
		"need net",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("OpenRC 脚本缺少 %q:\n%s", want, s)
		}
	}
}

// Fake rc-service / rc-update：验证面板在 Alpine（OpenRC）上会调用正确的命令，
// 不会再去找 systemctl。
func TestOpenRCServiceControl(t *testing.T) {
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls.log")
	mkScript := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mkScript("rc-service", `
if [ "$2" = "status" ]; then echo " * status: started"; exit 0; fi
echo "rc-service $1 $2" >> "$FAKE_CALLS"
exit 0
`)
	mkScript("rc-update", `echo "rc-update $*" >> "$FAKE_CALLS"`)

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("FAKE_CALLS", calls)

	cfg := DefaultConfig()
	p := New(cfg, "test")
	p.SetInit(InitOpenRC)
	if p.ModeName() != "openrc" {
		t.Fatalf("mode 应为 openrc: %s", p.ModeName())
	}
	if !strings.Contains(p.ServiceScript(), "openrc-run") {
		t.Fatal("ServiceScript 应是 OpenRC 脚本")
	}

	active, _ := p.ServiceState()
	if active != "active" {
		t.Fatalf("rc-service status 含 started 时应为 active: %s", active)
	}
	if err := p.ServiceAction("restart"); err != nil {
		t.Fatalf("OpenRC 重启失败: %v", err)
	}
	body, _ := os.ReadFile(calls)
	if !strings.Contains(string(body), "rc-service ocserv-go restart") {
		t.Fatalf("没有调用 rc-service restart: %s", body)
	}
}

func TestTailLines(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x.log")
	if err := os.WriteFile(f, []byte("a\nb\nc\nd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := tailLines(f, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != "c\nd\n" {
		t.Fatalf("末尾 2 行不对: %q", got)
	}
	if _, err := tailLines(filepath.Join(t.TempDir(), "nope"), 5); err == nil {
		t.Fatal("文件不存在应报错")
	}
}
