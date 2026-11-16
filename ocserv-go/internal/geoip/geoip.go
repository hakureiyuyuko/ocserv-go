// Package geoip 用 ip.sb 的免费 API 查 IP 归属地。
//
// 文档：https://ip.sb/api/ —— GET https://api.ip.sb/geoip/{ip}
// 注意：必须带自定义 User-Agent（默认库 UA 会被拦），限流 100 次/分/来源 IP。
package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Info 是一次查询结果（字段按需缺失）。
type Info struct {
	CountryCode string `json:"country_code,omitempty"`
	Country     string `json:"country,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         string `json:"asn,omitempty"`
}

// String 给界面/日志用：China · Sichuan · Jiulong · China Telecom
func (i Info) String() string {
	var out []string
	seen := map[string]bool{}
	for _, s := range []string{i.Country, i.Region, i.City, i.ISP} {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return strings.Join(out, " · ")
}

// Client 带缓存与限流的查询器。
type Client struct {
	hc     *http.Client
	ua     string
	base   string
	mu     sync.Mutex
	cache  map[string]entry
	minGap time.Duration
	last   time.Time
}

type entry struct {
	info Info
	exp  time.Time
}

// New 创建查询器。
func New() *Client {
	return &Client{
		hc:     &http.Client{Timeout: 6 * time.Second},
		ua:     "ocserv-go/1.1 (self-hosted VPN)",
		base:   "https://api.ip.sb",
		cache:  map[string]entry{},
		minGap: 250 * time.Millisecond, // 限流 4 次/秒，低于官方 5 次/秒
	}
}

// Lookup 查询 IP 归属地；私有/环回地址直接返回空，不发起请求。
func (c *Client) Lookup(ctx context.Context, ipStr string) (Info, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return Info{}, fmt.Errorf("非法 IP: %q", ipStr)
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return Info{}, nil
	}
	key := ip.String()

	c.mu.Lock()
	if e, ok := c.cache[key]; ok && time.Now().Before(e.exp) {
		c.mu.Unlock()
		return e.info, nil
	}
	// 简易限流：距离上次请求不足 minGap 就等一会
	wait := c.minGap - time.Since(c.last)
	if wait > 0 {
		c.mu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return Info{}, ctx.Err()
		}
		c.mu.Lock()
	}
	c.last = time.Now()
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/geoip/"+key, nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusBadRequest {
		// 非法 IP / 查不到：缓存一个空结果，避免反复打
		c.store(key, Info{})
		return Info{}, nil
	}
	if res.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("ip.sb 返回 HTTP %d", res.StatusCode)
	}
	var raw struct {
		CountryCode string          `json:"country_code"`
		Country     string          `json:"country"`
		Region      string          `json:"region"`
		City        string          `json:"city"`
		ISP         string          `json:"isp"`
		ASN         json.RawMessage `json:"asn"`
	}
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return Info{}, fmt.Errorf("解析 ip.sb 响应失败: %v", err)
	}
	info := Info{
		CountryCode: raw.CountryCode,
		Country:     raw.Country,
		Region:      raw.Region,
		City:        raw.City,
		ISP:         raw.ISP,
		ASN:         strings.Trim(string(raw.ASN), `"`),
	}
	c.store(key, info)
	return info, nil
}

func (c *Client) store(key string, info Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) > 2048 { // 简单防膨胀
		for k := range c.cache {
			delete(c.cache, k)
			if len(c.cache) <= 1024 {
				break
			}
		}
	}
	c.cache[key] = entry{info: info, exp: time.Now().Add(24 * time.Hour)}
}
