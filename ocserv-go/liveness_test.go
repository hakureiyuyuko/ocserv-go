package main

// 连接保活/死链检测的回归测试：
//   · decideLiveness 的判定逻辑（纯函数）
//   · 真实隧道：客户端不回 DPD → 服务端在 3×dpd 后断开
//   · 真实隧道：客户端回 DPD → 连接能活过 3×dpd

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakureiyuyuko/ocserv-go/internal/auth"
	"github.com/hakureiyuyuko/ocserv-go/internal/cstp"
)

func TestDecideLiveness(t *testing.T) {
	now := time.Now()
	dpd := 10 * time.Second
	cfg := liveCfg{dpd: dpd}
	fresh := liveClock{tcp: now, udp: now, data: now}

	if d := decideLiveness(now, fresh, false, cfg); d != (liveDecision{}) {
		t.Fatalf("刚连上不应该有任何动作: %+v", d)
	}

	// 2×dpd 没有 TCP 包 → 发 DPD
	old := liveClock{tcp: now.Add(-2*dpd - time.Second), udp: now, data: now}
	if d := decideLiveness(now, old, false, cfg); !d.SendDPDTCP || d.DropTunnel != "" {
		t.Fatalf("2×dpd 应发 TCP DPD: %+v", d)
	}
	// 探测刚发过 → 不重复发
	old.probeTCP = now.Add(-dpd + time.Second)
	if d := decideLiveness(now, old, false, cfg); d.SendDPDTCP {
		t.Fatal("dpd 内不应重复发 DPD")
	}
	// 3×dpd 没有 TCP 包 → 断开
	dead := liveClock{tcp: now.Add(-3*dpd - time.Second), udp: now, data: now}
	if d := decideLiveness(now, dead, false, cfg); !strings.Contains(d.DropTunnel, "DPD 超时") {
		t.Fatalf("3×dpd 应断开隧道: %+v", d)
	}

	// DTLS 侧：2×dpd 没 UDP 包 → DTLS DPD；3×dpd → 提示禁用（不立刻断隧道）
	udpOld := liveClock{tcp: now, udp: now.Add(-2*dpd - time.Second), data: now}
	if d := decideLiveness(now, udpOld, true, cfg); !d.SendDPDUDP {
		t.Fatalf("2×dpd 应发 DTLS DPD: %+v", d)
	}
	udpDead := liveClock{tcp: now, udp: now.Add(-3*dpd - time.Second), data: now}
	if d := decideLiveness(now, udpDead, true, cfg); !strings.Contains(d.DropDTLS, "DTLS 超时") {
		t.Fatalf("3×dpd 应提示 DTLS 超时: %+v", d)
	}
	// DTLS 没建立时不应有 UDP 动作
	if d := decideLiveness(now, udpDead, false, cfg); d.SendDPDUDP || d.DropDTLS != "" {
		t.Fatalf("没有 DTLS 时不应有 UDP 动作: %+v", d)
	}

	// 空闲超时：只在有数据阈值时生效
	idleCfg := liveCfg{idle: 60 * time.Second}
	quiet := liveClock{tcp: now, udp: now, data: now.Add(-61 * time.Second)}
	if d := decideLiveness(now, quiet, false, idleCfg); !strings.Contains(d.DropTunnel, "空闲超时") {
		t.Fatalf("超过空闲阈值应断开: %+v", d)
	}
	if d := decideLiveness(now, quiet, false, liveCfg{}); d.DropTunnel != "" {
		t.Fatalf("默认（idle=0）不应因空闲断开: %+v", d)
	}
}

func TestDTLSEgressSwitch(t *testing.T) {
	now := time.Now()
	cfg := liveCfg{switchTCP: 25 * time.Second}
	if !dtlsEgressOK(now, now.Add(-10*time.Second), cfg) {
		t.Fatal("10 秒内有 UDP 包应继续走 DTLS")
	}
	if dtlsEgressOK(now, now.Add(-26*time.Second), cfg) {
		t.Fatal("超过 25 秒没 UDP 包应改走 TCP")
	}
	if !dtlsEgressOK(now, now.Add(-time.Hour), liveCfg{}) {
		t.Fatal("switch=0 表示不切换")
	}
}

// startDPDTestServer 起一个 DPD=1s、无 DTLS 的测试服务端。
func startDPDTestServer(t *testing.T) (addr string) {
	t.Helper()
	hash, err := auth.Hash("test123")
	if err != nil {
		t.Fatal(err)
	}
	uf := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(uf, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := auth.Load(uf)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newServer(serverConfig{
		Users: users, ClientNet: "10.66.66.0/24", ServerIP: "10.66.66.1",
		MTU: 1400, DPD: 1, DNS: []string{"1.1.1.1"}, Domain: "test.local", Style: "asa",
		SwitchToTCP: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := makeSelfSigned("test.local")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hsrv := &http.Server{
		Handler:     srv,
		ConnContext: withSession,
		ErrorLog:    log.New(io.Discard, "", 0),
	}
	go func() { _ = hsrv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})) }()
	t.Cleanup(func() { _ = hsrv.Close() })
	return ln.Addr().String()
}

// connectTestTunnel 走 ASA 流程拿到 webvpn cookie 并发 CONNECT。
func connectTestTunnel(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	req := func(method, path string, hdrs map[string]string, body string) (string, map[string][]string) {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n", method, path)
		for k, v := range hdrs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
		if body != "" {
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		}
		b.WriteString("\r\n")
		b.WriteString(body)
		if _, err := io.WriteString(c, b.String()); err != nil {
			t.Fatal(err)
		}
		st, hs, _ := readResp(t, br)
		return st, hs
	}
	ua := map[string]string{"User-Agent": "Open AnyConnect VPN Agent v9.12"}
	req("GET", "/+webvpn+/index.html", ua, "")
	status, hdrs := req("POST", "/+webvpn+/index.html", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"User-Agent":   "Open AnyConnect VPN Agent v9.12",
	}, "username=alice&password=test123")
	if !strings.Contains(status, "200") {
		t.Fatalf("登录失败: %s", status)
	}
	tok := cookieValue(hdrs["set-cookie"], "webvpn")
	if tok == "" {
		t.Fatal("没有 webvpn cookie")
	}
	status, _ = req("CONNECT", "/CSTP", map[string]string{
		"User-Agent":      "Open AnyConnect VPN Agent v9.12",
		"X-CSTP-Version":  "1",
		"X-CSTP-Base-Mtu": "1500",
		"Cookie":          "webvpn=" + tok,
	}, "")
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT 失败: %s", status)
	}
	return c, br
}

// TestDPDTimeoutDropsTunnel：客户端建好隧道后不再说话，服务端应在 3×dpd 左右断开。
func TestDPDTimeoutDropsTunnel(t *testing.T) {
	addr := startDPDTestServer(t)
	conn, br := connectTestTunnel(t, addr)
	defer conn.Close()

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, _, err := cstp.ReadFrame(br); err != nil {
			elapsed := time.Since(start)
			if elapsed < 2*time.Second {
				t.Fatalf("断开得太早（%s），可能不是 DPD 判定", elapsed)
			}
			if elapsed > 8*time.Second {
				t.Fatalf("3×dpd 后仍没断开（%s）: %v", elapsed, err)
			}
			t.Logf("DPD 超时断开耗时 %s（dpd=1s，期望 ~3-4s）", elapsed)
			return
		}
	}
}

// TestDPDKeepaliveKeepsTunnel：客户端按 DPD 回包，连接应能活过 3×dpd。
func TestDPDKeepaliveKeepsTunnel(t *testing.T) {
	addr := startDPDTestServer(t)
	conn, br := connectTestTunnel(t, addr)
	defer conn.Close()

	respond := func(until time.Time) error {
		for time.Now().Before(until) {
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			typ, _, err := cstp.ReadFrame(br)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return err
			}
			if typ == cstp.TypeDPDReq {
				if err := cstp.WriteFrame(conn, cstp.TypeDPDResp, nil); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// 先正常回 5 秒（>3×dpd），连接不能被断开
	if err := respond(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("回 DPD 期间连接被断开: %v", err)
	}
	// 之后停止回包，应在 ~3-4 秒内断开
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, _, err := cstp.ReadFrame(br); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if elapsed := time.Since(start); elapsed > 8*time.Second {
				t.Fatalf("停止回应后仍未断开（%s）", elapsed)
			}
			return
		}
	}
}
