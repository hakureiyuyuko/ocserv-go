// Package connlog 记录「连接成功」的会话：时间、用户、来源 IP 与归属地。
//
// 存储在 JSONL 文件里（一行一条），服务端写入、面板读取。
package connlog

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hakureiyuyuko/ocserv-go/internal/geoip"
)

// Record 是一行连接日志。
type Record struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user"`
	IP      string    `json:"ip"`
	Country string    `json:"country,omitempty"`
	Region  string    `json:"region,omitempty"`
	City    string    `json:"city,omitempty"`
	ISP     string    `json:"isp,omitempty"`
	ASN     string    `json:"asn,omitempty"`
	GeoErr  string    `json:"geoError,omitempty"`
}

const maxSize = 5 << 20 // 5MB 后轮转一份 .1

// Log 负责追加写 + 后台查归属地。
type Log struct {
	path string
	geo  *geoip.Client
	mu   sync.Mutex
}

// Open 创建写入器；path 为空返回 nil（关闭记录）。
func Open(path string) *Log {
	if path == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	return &Log{path: path, geo: geoip.New()}
}

// Record 查询归属地后写一行（在独立 goroutine 里调用，不阻塞隧道）。
func (l *Log) Record(user, ip string) {
	rec := Record{Time: time.Now(), User: user, IP: ip}
	if l.geo != nil && ip != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		info, err := l.geo.Lookup(ctx, ip)
		cancel()
		if err != nil {
			rec.GeoErr = err.Error()
		} else {
			rec.Country, rec.Region, rec.City, rec.ISP, rec.ASN = info.Country, info.Region, info.City, info.ISP, info.ASN
		}
	}
	if err := l.append(rec); err != nil {
		log.Printf("! 写连接日志失败: %v", err)
	}
}

func (l *Log) append(rec Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if st, err := os.Stat(l.path); err == nil && st.Size() > maxSize {
		_ = os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

// Read 读取最近 limit 条（时间倒序），并返回过滤前的总数。
// userFilter 精确匹配用户名；textFilter 在 用户/IP/国家/省市/ISP/ASN 里模糊匹配。
func Read(path string, limit int, userFilter, textFilter string) ([]Record, int, error) {
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	var all []Record
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if userFilter != "" && !strings.EqualFold(r.User, userFilter) {
			continue
		}
		if textFilter != "" {
			hay := strings.ToLower(strings.Join([]string{r.User, r.IP, r.Country, r.Region, r.City, r.ISP, r.ASN}, " "))
			if !strings.Contains(hay, strings.ToLower(textFilter)) {
				continue
			}
		}
		all = append(all, r)
	}
	total := len(all)
	start := 0
	if total > limit {
		start = total - limit
	}
	out := make([]Record, 0, total-start)
	for i := total - 1; i >= start; i-- {
		out = append(out, all[i])
	}
	return out, total, nil
}
