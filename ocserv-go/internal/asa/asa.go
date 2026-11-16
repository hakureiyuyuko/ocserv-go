// Package asa 复刻 Cisco ASA（AnyConnect）的 webvpn 登录流程。
//
// 与 ocserv 的差别（抓包对比 Cisco ASA）：
//   - 客户端先 GET / → 302 到 /+webvpn+/index.html（非 AnyConnect UA 则返回带 JS 跳转的 HTML）
//   - 登录页是 text/xml，根节点直接是 <auth id="main">，不是 <config-auth>
//   - 提交用 application/x-www-form-urlencoded（group_list/username/password），不是 XML
//   - 失败时在 auth 里插入 <error id="15" param1="" param2="">Login failed.</error>
//   - 响应带一组 Cisco 风格的 cookie 与安全头，X-Transcend-Version: 1
package asa

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

const (
	msgPrompt = "Please enter your username and password."
	formAct   = "/+webvpn+/index.html"
)

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// build 按真机的元素顺序手工拼接（xml 包不允许同名字段，且真机是自闭合 input）。
func build(id, message, errID, errText string) []byte {
	var b strings.Builder
	b.WriteString(xmlHeader)
	fmt.Fprintf(&b, `<auth id="%s">`, esc(id))
	b.WriteString("<title>SSL VPN Service</title>")
	b.WriteString("<banner></banner>")
	fmt.Fprintf(&b, "<message>%s</message>", esc(message))
	if errID != "" {
		fmt.Fprintf(&b, `<error id="%s" param1="" param2="">%s</error>`, esc(errID), esc(errText))
	}
	if id != "success" {
		b.WriteString(`<form method="post" action="` + formAct + `">`)
		b.WriteString(`<input type="text" name="username" label="Username:" />`)
		b.WriteString(`<input type="password" name="password" label="Password:" />`)
		b.WriteString(`<input type="submit" name="Login" value="Login" />`)
		b.WriteString(`<input type="reset" name="Clear" value="Clear" />`)
		b.WriteString(`</form>`)
	}
	b.WriteString("</auth>")
	return []byte(b.String())
}

// LoginPage 是 GET /+webvpn+/index.html 的响应（登录表单）。
func LoginPage() []byte { return build("main", msgPrompt, "", "") }

// LoginFailed 带上 error id=15（与真机一致）。
func LoginFailed(msg string) []byte {
	if msg == "" {
		msg = "Login failed."
	}
	return build("main", msgPrompt, "15", msg)
}

// Success 是登录成功响应（客户端随后会用 cookie 去 POST /CSTP）。
func Success() []byte { return []byte(xmlHeader + `<auth id="success"></auth>` + "\n") }

// HTMLRedirect 给非 AnyConnect UA（浏览器）看的跳转页，行为与真机一致。
func HTMLRedirect() []byte {
	return []byte(`<!DOCTYPE html>
<html style="height:100%;width:100%;">
<head><title>SSL VPN Service</title></head>
<body>
<script>
document.cookie = "webvpnlogin=1; path=/; secure";
document.location.replace("/+CSCOE+/logon.html");
</script>
</body>
</html>`)
}

// NewToken 生成 webvpn 会话令牌。
func NewToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// LogonPage 是给浏览器看的登录页（真机同款路径 /+CSCOE+/logon.html）。
// 样式自绘，不复用 Cisco 的图片/样式资源。
func LogonPage(errMsg string) []byte {
	var errHTML string
	if errMsg != "" {
		errHTML = `<div class="err">` + esc(errMsg) + `</div>`
	}
	return []byte(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSL VPN Service</title>
<style>
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
         background:#eef2f6; color:#333; }
  .top { background:#1f5c98; color:#fff; padding:14px 24px; font-size:18px; font-weight:600;
         letter-spacing:.3px; }
  .wrap { max-width:420px; margin:48px auto; background:#fff; border:1px solid #d7dee6;
          border-radius:6px; box-shadow:0 6px 20px rgba(31,92,152,.12); overflow:hidden; }
  .hd { padding:18px 24px 0; font-size:16px; color:#1f5c98; font-weight:600; }
  .sub { padding:6px 24px 0; color:#7b8794; font-size:13px; }
  form { padding:16px 24px 24px; }
  .row { margin-top:14px; }
  .lbl { display:block; font-size:12px; color:#5b6b7b; margin-bottom:4px; }
  .inp { width:100%; padding:9px 10px; border:1px solid #c7d2dd; border-radius:4px; font-size:14px; }
  .inp:focus { outline:none; border-color:#1f5c98; box-shadow:0 0 0 2px rgba(31,92,152,.15); }
  .btn { margin-top:20px; width:100%; padding:10px; background:#1f5c98; color:#fff; border:0;
         border-radius:4px; font-size:15px; cursor:pointer; }
  .btn:hover { background:#17497a; }
  .err { margin:0 24px; padding:10px 12px; background:#fdecea; border:1px solid #f5c6c2;
         color:#a12a20; border-radius:4px; font-size:13px; }
  .ft { padding:12px 24px 18px; color:#9aa7b4; font-size:12px; text-align:center; }
</style></head>
<body>
<div class="top">SSL VPN Service</div>
<div class="wrap">
  <div class="hd">Sign in</div>
  <div class="sub">Please enter your username and password.</div>
  ` + errHTML + `
  <form method="post" action="/+CSCOE+/logon.html">
    <div class="row"><label class="lbl" for="username">Username</label>
      <input id="username" name="username" class="inp" type="text" autocomplete="username" autofocus></div>
    <div class="row"><label class="lbl" for="password">Password</label>
      <input id="password" name="password" class="inp" type="password" autocomplete="current-password"></div>
    <button class="btn" type="submit" name="Login" value="Login">Login</button>
  </form>
  <div class="ft">ocserv-go · ASA 风格演示</div>
</div>
</body></html>`)
}

// PortalPage 是登录成功后的简单门户页。
func PortalPage(user string) []byte {
	return []byte(`<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>SSL VPN Service</title>
<style>body{font-family:-apple-system,"Segoe UI",Roboto,sans-serif;background:#eef2f6;margin:0;color:#333}
.top{background:#1f5c98;color:#fff;padding:14px 24px;font-size:18px;font-weight:600}
.wrap{max-width:520px;margin:48px auto;background:#fff;border:1px solid #d7dee6;border-radius:6px;padding:24px}
.ok{color:#1a7f37;font-weight:600;margin-bottom:8px}.muted{color:#7b8794;font-size:13px}
code{background:#f3f6f9;padding:2px 6px;border-radius:4px}</style></head>
<body><div class="top">SSL VPN Service</div>
<div class="wrap">
  <div class="ok">✓ 登录成功：` + esc(user) + `</div>
  <div class="muted">这是 ocserv-go 的 ASA 风格门户页（演示用）。</div>
  <p class="muted">AnyConnect 客户端此时会带 <code>webvpn</code> cookie 去 <code>POST /CSTP</code> 建隧道。</p>
</div></body></html>`)
}
