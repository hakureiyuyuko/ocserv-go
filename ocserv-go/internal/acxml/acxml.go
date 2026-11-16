// Package acxml 处理 Cisco AnyConnect / OpenConnect 的配置握手 XML。
//
// 客户端 → 服务端：<config-auth type="init|auth-reply">，auth-reply 里带
// <auth><username>…</username><password>…</password></auth>。
// 服务端 → 客户端：type="auth-request"（要用户名/密码）或 type="auth-reply"
// （<auth id="success"/> 表示认证通过）。
package acxml

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// DeviceID 是客户端上报的设备标识（我们只做展示/日志用）。
type DeviceID struct {
	Value string `xml:",chardata"`
}

// Version 形如 <version who="vpn">4.10.04071</version>
type Version struct {
	Who   string `xml:"who,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Input 是登录表单里的输入项。
type Input struct {
	Type  string `xml:"type,attr"`
	Name  string `xml:"name,attr"`
	Label string `xml:"label,attr,omitempty"`
}

// Form 是登录表单。
type Form struct {
	Method string  `xml:"method,attr"`
	Action string  `xml:"action,attr"`
	Inputs []Input `xml:"input"`
}

// Auth 同时用于请求与回复。
type Auth struct {
	XMLName  xml.Name `xml:"auth"`
	ID       string   `xml:"id,attr,omitempty"`
	Title    string   `xml:"title,omitempty"`
	Message  string   `xml:"message,omitempty"`
	Username string   `xml:"username,omitempty"`
	Password string   `xml:"password,omitempty"`
	Form     *Form    `xml:"form,omitempty"`
}

// ConfigAuth 是 <config-auth> 的通用表示。
type ConfigAuth struct {
	XMLName      xml.Name      `xml:"config-auth"`
	Client       string        `xml:"client,attr,omitempty"`
	Type         string        `xml:"type,attr,omitempty"`
	AggrVersion  string        `xml:"aggregate-auth-version,attr,omitempty"`
	Version      *Version      `xml:"version,omitempty"`
	DeviceID     *DeviceID     `xml:"device-id,omitempty"`
	Capabilities *Capabilities `xml:"capabilities,omitempty"`
	Auth         *Auth         `xml:"auth,omitempty"`
}

// ASA 的聚合认证（aggregate auth）：真 AnyConnect 客户端默认走这套，
// 首包就是 POST / + <config-auth type="init">，服务端必须回
// <config-auth type="auth-request" aggregate-auth-version="2">，
// 否则客户端直接报「连接尝试失败」（不会退化成表单流程）。
//
// 这里手写 XML：encoding/xml 会把空元素输出成 <input></input>，
// 真 ASA 是自闭合的 <input/>，为兼容老客户端就照真机字节写。
const asaAggr = "2"

const asaFormXML = `<form method="post" action="/">` +
	`<input type="text" name="username" label="Username"/>` +
	`<input type="password" name="password" label="Password"/>` +
	`<input type="submit" name="Login" value="Login"/>` +
	`</form>`

// ASARequestLogin 是聚合认证的「请输用户名密码」回复。
func ASARequestLogin() []byte {
	return []byte(xmlHeader + `<config-auth client="vpn" type="auth-request" aggregate-auth-version="` + asaAggr + `">` +
		`<auth id="main"><title>Login</title><message>Please enter your username and password.</message>` +
		asaFormXML + `</auth></config-auth>\n`)
}

// ASALoginFailed 是聚合认证下密码错的重试回复（仍带表单）。
func ASALoginFailed(msg string) []byte {
	if msg == "" {
		msg = "Login failed."
	}
	return []byte(xmlHeader + `<config-auth client="vpn" type="auth-request" aggregate-auth-version="` + asaAggr + `">` +
		`<auth id="main"><title>Login</title><message>` + escapeXML(msg) + `</message>` +
		asaFormXML + `</auth></config-auth>\n`)
}

// ASASuccess 是聚合认证通过的回复。
func ASASuccess() []byte {
	return []byte(xmlHeader + `<config-auth client="vpn" type="auth-reply" aggregate-auth-version="` + asaAggr + `">` +
		`<auth id="success"/></config-auth>\n`)
}

func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// Capabilities 目前只用到 auth-method。
type Capabilities struct {
	AuthMethods []string `xml:"auth-method"`
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// Parse 解析客户端发来的 XML（容忍前导空白与 BOM）。
func Parse(b []byte) (*ConfigAuth, error) {
	var ca ConfigAuth
	if err := xml.Unmarshal(b, &ca); err != nil {
		return nil, err
	}
	if ca.XMLName.Local != "config-auth" {
		return nil, fmt.Errorf("不是 config-auth 文档: %q", ca.XMLName.Local)
	}
	return &ca, nil
}

// Username / Password 从 <auth> 里取（空白已裁剪）。
func (c *ConfigAuth) Credentials() (user, pass string) {
	if c.Auth == nil {
		return "", ""
	}
	return strings.TrimSpace(c.Auth.Username), strings.TrimSpace(c.Auth.Password)
}

func marshal(ca *ConfigAuth) ([]byte, error) {
	b, err := xml.Marshal(ca)
	if err != nil {
		return nil, err
	}
	return append([]byte(xmlHeader), b...), nil
}

func loginForm(action string) *Form {
	return &Form{
		Method: "post",
		Action: action,
		Inputs: []Input{
			{Type: "text", Name: "username", Label: "Username:"},
			{Type: "password", Name: "password", Label: "Password:"},
		},
	}
}

// RequestUsername 返回首包的登录请求（要用户名）。
func RequestUsername() []byte {
	b, _ := marshal(&ConfigAuth{
		Client:  "vpn",
		Type:    "auth-request",
		Version: &Version{Who: "sg", Value: "0.1(1)"},
		Auth: &Auth{
			ID:      "main",
			Message: "Please enter your username.",
			Form:    loginForm("/auth"),
		},
	})
	return b
}

// RequestPassword 表示用户名已收到，继续要密码。
func RequestPassword() []byte {
	b, _ := marshal(&ConfigAuth{
		Client:  "vpn",
		Type:    "auth-reply",
		Version: &Version{Who: "sg", Value: "0.1(1)"},
		Auth: &Auth{
			ID:      "main",
			Message: "Please enter your password.",
			Form:    loginForm("/auth"),
		},
	})
	return b
}

// Success 表示认证通过。extra 里可放 <config> 之类的扩展节点（暂不用）。
func Success() []byte {
	b, _ := marshal(&ConfigAuth{
		Client: "vpn",
		Type:   "auth-reply",
		Auth:   &Auth{ID: "success"},
	})
	return b
}

// Failure 返回认证失败（消息会显示在客户端）。
func Failure(msg string) []byte {
	if msg == "" {
		msg = "Login failed."
	}
	b, _ := marshal(&ConfigAuth{
		Client:  "vpn",
		Type:    "auth-reply",
		Version: &Version{Who: "sg", Value: "0.1(1)"},
		Auth: &Auth{
			ID:      "main",
			Message: msg,
			Form:    loginForm("/auth"),
		},
	})
	return b
}
