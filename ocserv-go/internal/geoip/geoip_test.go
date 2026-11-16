package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// 私有/非法地址不发请求，直接返回空
func TestSkipPrivate(t *testing.T) {
	c := New()
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "not-an-ip"} {
		info, err := c.Lookup(context.Background(), ip)
		if ip == "not-an-ip" {
			if err == nil {
				t.Fatalf("%s 应报错", ip)
			}
			continue
		}
		if err != nil || info.Country != "" {
			t.Fatalf("%s 不应发起查询: %+v %v", ip, info, err)
		}
	}
}

// 用假服务器验证解析与缓存
func TestParseAndCache(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "ocserv-go") {
			t.Errorf("应带自定义 User-Agent，得到 %q", r.Header.Get("User-Agent"))
		}
		_, _ = w.Write([]byte(`{"country":"China","region":"Sichuan","city":"Jiulong","isp":"China Telecom","asn":4134}`))
	}))
	defer srv.Close()

	c := New()
	c.base = srv.URL
	info, err := c.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if info.Country != "China" || info.Region != "Sichuan" || info.City != "Jiulong" || info.ISP != "China Telecom" || info.ASN != "4134" {
		t.Fatalf("解析结果不符: %+v", info)
	}
	if got := info.String(); got != "China · Sichuan · Jiulong · China Telecom" {
		t.Fatalf("展示串不符: %q", got)
	}
	// 第二次应命中缓存
	_, _ = c.Lookup(context.Background(), "8.8.8.8")
	if n != 1 {
		t.Fatalf("应只请求一次（缓存），实际 %d 次", n)
	}
}

// 真实网络测试：GEOIP_LIVE=1 go test ./internal/geoip -run TestLive
func TestLive(t *testing.T) {
	if os.Getenv("GEOIP_LIVE") != "1" {
		t.Skip("设置 GEOIP_LIVE=1 才跑真实网络")
	}
	c := New()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := c.Lookup(ctx, "14.111.128.78")
	if err != nil {
		t.Fatalf("真实查询失败: %v", err)
	}
	t.Logf("14.111.128.78 -> %+v (%s)", info, info.String())
	if info.Country == "" {
		t.Fatal("应返回国家")
	}
}
