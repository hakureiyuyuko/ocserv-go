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
	Version      *Version      `xml:"version,omitempty"`
	DeviceID     *DeviceID     `xml:"device-id,omitempty"`
	Capabilities *Capabilities `xml:"capabilities,omitempty"`
	Auth         *Auth         `xml:"auth,omitempty"`
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
