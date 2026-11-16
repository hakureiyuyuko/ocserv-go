package acxml

import (
	"strings"
	"testing"
)

func TestParseAuthReply(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply">
  <version who="vpn">4.10.04071</version>
  <auth><username>alice</username><password>s3cret</password></auth>
</config-auth>`)
	ca, err := Parse(body)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ca.Type != "auth-reply" {
		t.Fatalf("type 不对: %q", ca.Type)
	}
	u, p := ca.Credentials()
	if u != "alice" || p != "s3cret" {
		t.Fatalf("凭据解析错误: %q/%q", u, p)
	}
}

func TestParseInit(t *testing.T) {
	body := []byte(`<config-auth client="vpn" type="init"><version who="vpn">4.10.04071</version>
<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities></config-auth>`)
	ca, err := Parse(body)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ca.Type != "init" || ca.Client != "vpn" {
		t.Fatalf("字段不对: %+v", ca)
	}
	if ca.Capabilities == nil || len(ca.Capabilities.AuthMethods) != 1 {
		t.Fatalf("capabilities 解析失败")
	}
}

func TestResponses(t *testing.T) {
	cases := map[string]struct {
		body []byte
		want []string
	}{
		"username": {RequestUsername(), []string{`type="auth-request"`, `id="main"`, "username", "password"}},
		"password": {RequestPassword(), []string{`type="auth-reply"`, "Please enter your password."}},
		"success":  {Success(), []string{`id="success"`}},
		"failure":  {Failure("nope"), []string{"nope"}},
	}
	for name, c := range cases {
		s := string(c.body)
		if !strings.HasPrefix(s, xmlHeader) {
			t.Fatalf("%s: 缺少 XML 头", name)
		}
		for _, w := range c.want {
			if !strings.Contains(s, w) {
				t.Fatalf("%s: 缺少 %q\n%s", name, w, s)
			}
		}
	}
}

func TestParseRejectsOtherRoot(t *testing.T) {
	if _, err := Parse([]byte(`<foo/>`)); err == nil {
		t.Fatal("非 config-auth 应该报错")
	}
}
