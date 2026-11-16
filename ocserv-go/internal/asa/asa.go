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
	"image"
	"image/color/palette"
	"image/gif"
	"image/jpeg"
	"image/png"
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

// LogonPage 复刻真机登录页的骨架（table 布局、元素 id/name、隐藏字段、CSRF cookie），
// 样式为自绘等价实现，不使用 Cisco 的图片与样式表资源。
func LogonPage(csrf, errMsg string) []byte {
	msg := "Please enter your username and password."
	if errMsg != "" {
		msg = errMsg
	}
	return []byte(`<!DOCTYPE html>
<html style="height:100%;width:100%;">
<head>
<meta charset="utf-8">
<meta name="HandheldFriendly" content="true" />
<meta name="viewport" content="width=500,user-scalable=no" />
<title>SSL VPN Service</title>
<style>
  html,body{height:100%;margin:0;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#000;background:#fff;}
  #logon_wrap{width:350px;margin:40px auto;}
  #form_title{width:100%;border-collapse:collapse;}
  #form_title .hd{background:#f2f4f6;border:1px solid #858A91;border-bottom:0;height:40px;}
  #form_title .hd span{color:#7d8184;font-weight:bold;display:block;text-align:center;line-height:40px;}
  #logon_message_text{padding:15px 15px 5px;border-left:1px solid #858A91;border-right:1px solid #858A91;}
  .box{border:1px solid #858A91;border-top:0;padding:0 20px 10px;}
  table.form{border-collapse:collapse;width:100%;}
  table.form td{padding:4px 0;}
  input[type=text],input[type=password]{border:1px solid gray;padding:2px;width:180px;}
  input[type=submit]{font-weight:bold;cursor:pointer;padding:2px 14px;}
  .err{color:#b00;}
</style>
</head>
<body>
<div id="logon_wrap">
<form id="unicorn_form" method="POST" onsubmit="return formSubmit();" autocomplete="off" action="/+webvpn+/index.html">
<input name="tgroup" type="hidden" value="">
<input name="next" type="hidden" value="">
<input name="tgcookieset" type="hidden" value="">
<input name="csrf_token" type="hidden" value="` + esc(csrf) + `">
<script>document.cookie="CSRFtoken="+"` + esc(csrf) + `"+"; path=/; secure";</script>
<table id="form_title" cellspacing="0" cellpadding="0" border="0">
<tr><td class="hd"><span>Login</span></td></tr>
</table>
<div id="logon_message_text">` + esc(msg) + `</div>
<div class="box">
<table class="form" border="0" cellspacing="0" cellpadding="0">
<tr><td colspan="2">&nbsp;</td></tr>
<tr><td nowrap id="username_field">USERNAME:</td>
    <td><input autocomplete="off" id="username" name="username" type="text" value=""></td></tr>
<tr><td nowrap id="password_field">PASSWORD:</td>
    <td><input autocomplete="off" id="password_input" name="password" type="password"></td></tr>
<tr height="40"><td colspan="2" align="center">
    <input type="submit" name="Login" value="Login" /></td></tr>
</table>
</div>
</form>
</div>
<script>
function formSubmit(){ return true; }
</script>
</body></html>`)
}

// CSRF token：真机会下发并让页面写入 CSRFtoken cookie，这里只做形似。
func NewCSRF() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// LogonCSS 对应 /+CSCOE+/logon_custom.css（自绘，内容极简）。
func LogonCSS() []byte { return []byte("/* logon_custom.css */\n") }

// PortalCSS 对应 /+CSCOU+/portal.css。
func PortalCSS() []byte { return []byte("/* portal.css */\n") }

// WinJS 对应 /+CSCOE+/win.js。
func WinJS() []byte { return []byte("/* win.js */\n") }

// TinyImage 返回一张 1x1 图片（占位，用于真机会引用的 logo/header 路径）。
func TinyImage(kind string) (data []byte, ctype string) {
	var buf bytes.Buffer
	switch kind {
	case "gif":
		if err := gif.Encode(&buf, image.NewPaletted(image.Rect(0, 0, 1, 1), palette.Plan9), nil); err == nil {
			return buf.Bytes(), "image/gif"
		}
	case "png":
		if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 1, 1))); err == nil {
			return buf.Bytes(), "image/png"
		}
	default:
		if err := jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 1, 1)), nil); err == nil {
			return buf.Bytes(), "image/jpeg"
		}
	}
	return []byte{}, "application/octet-stream"
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
