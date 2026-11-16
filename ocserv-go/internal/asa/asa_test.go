package asa

import (
	"strings"
	"testing"
)

func TestLoginPage(t *testing.T) {
	s := string(LoginPage())
	for _, want := range []string{
		`<auth id="main">`, "SSL VPN Service", "Please enter your username and password.",
		`action="/+webvpn+/index.html"`, `name="username"`, `name="password"`,
		`value="Login"`, `value="Clear"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("登录 XML 缺少 %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "<config-auth") {
		t.Fatal("ASA 风格不应是 config-auth")
	}
}

func TestLoginFailed(t *testing.T) {
	s := string(LoginFailed("Login failed."))
	if !strings.Contains(s, `<error id="15"`) || !strings.Contains(s, "Login failed.") {
		t.Fatalf("失败 XML 不对:\n%s", s)
	}
	if strings.Index(s, "<error") > strings.Index(s, "<form") {
		t.Fatal("error 应在 form 之前")
	}
}

func TestSuccess(t *testing.T) {
	s := string(Success())
	if !strings.Contains(s, `id="success"`) {
		t.Fatalf("成功 XML 不对: %s", s)
	}
}

func TestToken(t *testing.T) {
	a, b := NewToken(), NewToken()
	if len(a) != 32 || a == b {
		t.Fatalf("令牌不对: %q %q", a, b)
	}
}
