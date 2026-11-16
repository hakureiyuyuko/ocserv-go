package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/auth"
	"github.com/hakureiyuyuko/ocserv-deploy-kit/ocserv-go/internal/cstp"
)

// TestASAStyle 覆盖模拟 Cisco ASA 的完整 webvpn 流程：
// GET / → 302 → GET /+webvpn+/index.html → 表单 POST（失败/成功）→ 带 cookie 的 CONNECT → 隧道可用。
func TestASAStyle(t *testing.T) {
	hash, err := auth.Hash("test123")
	if err != nil {
		t.Fatal(err)
	}
	uf := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(uf, []byte("alice:"+hash+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users, err := auth.Load(uf)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newServer(serverConfig{
		Users: users, ClientNet: "10.66.66.0/24", ServerIP: "10.66.66.1",
		MTU: 1400, DPD: 0, DNS: []string{"1.1.1.1"},
		Domain: "test.local", Style: "asa",
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
	hsrv := &http.Server{Handler: srv, ConnContext: withSession, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = hsrv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})) }()
	defer hsrv.Close()
	srvAddr := ln.Addr().String()

	// 1) GET / （AnyConnect UA）→ 302 /+webvpn+/index.html
	conn := dialTLS(t, srvAddr)
	defer conn.Close()
	br := bufio.NewReader(conn)
	status, hdrs, _ := doReq(t, conn, br, "GET", "/", map[string]string{
		"User-Agent": "Open AnyConnect VPN Agent v9.12",
	}, "")
	if !strings.Contains(status, "302") {
		t.Fatalf("GET / 应返回 302，实际 %s", status)
	}
	if got := first(hdrs, "location"); got != "/+webvpn+/index.html" {
		t.Fatalf("Location 不对: %q", got)
	}
	if !strings.Contains(strings.Join(hdrs["set-cookie"], ";"), "tg=") {
		t.Fatalf("缺少 tg cookie: %v", hdrs["set-cookie"])
	}

	// 1b) 浏览器登录页：结构与真机一致（form id/action、隐藏字段）
	status, _, page := doReq(t, conn, br, "GET", "/+CSCOE+/logon.html", map[string]string{
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
	}, "")
	if !strings.Contains(status, "200") {
		t.Fatalf("浏览器登录页状态码: %s", status)
	}
	for _, want := range []string{`id="unicorn_form"`, `action="/+webvpn+/index.html"`, `name="csrf_token"`, `id="password_input"`} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("登录页缺少 %q，实际开头:\n%s", want, string(page[:min(len(page), 300)]))
		}
	}

	// 1c) 浏览器提交错误密码 → HTML 页面里带错误信息（不是 XML）
	status, _, page = doReq(t, conn, br, "POST", "/+webvpn+/index.html", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"User-Agent":   "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
	}, "username=alice&password=wrong")
	if !strings.Contains(status, "200") || !strings.Contains(string(page), "Login failed.") || strings.Contains(string(page), "<auth") {
		t.Fatalf("浏览器失败响应不对: %s\n%s", status, page[:min(len(page), 200)])
	}

	// 2) 登录页 XML
	status, hdrs, body := doReq(t, conn, br, "GET", "/+webvpn+/index.html", map[string]string{
		"User-Agent": "Open AnyConnect VPN Agent v9.12",
	}, "")
	if !strings.Contains(status, "200") {
		t.Fatalf("登录页状态码: %s", status)
	}
	if first(hdrs, "x-transcend-version") != "1" {
		t.Fatalf("缺少 X-Transcend-Version: 1")
	}
	for _, want := range []string{`<auth id="main">`, "username", "password", "text/xml"} {
		hay := string(body) + first(hdrs, "content-type")
		if !strings.Contains(hay, want) {
			t.Fatalf("登录页缺少 %q:\n%s", want, body)
		}
	}

	// 3) 错误密码 → error id=15
	status, _, body = doReq(t, conn, br, "POST", "/+webvpn+/index.html", map[string]string{
		"Content-Type":        "application/x-www-form-urlencoded",
		"User-Agent":          "Open AnyConnect VPN Agent v9.12",
		"X-Transcend-Version": "1",
	}, "username=alice&password=wrong")
	if !strings.Contains(status, "200") || !strings.Contains(string(body), `<error id="15"`) {
		t.Fatalf("失败响应不对: %s\n%s", status, body)
	}

	// 4) 正确密码 → success + webvpn cookie
	status, hdrs, body = doReq(t, conn, br, "POST", "/+webvpn+/index.html", map[string]string{
		"Content-Type":        "application/x-www-form-urlencoded",
		"User-Agent":          "Open AnyConnect VPN Agent v9.12",
		"X-Transcend-Version": "1",
	}, "username=alice&password=test123")
	if !strings.Contains(status, "200") || !strings.Contains(string(body), `id="success"`) {
		t.Fatalf("成功响应不对: %s\n%s", status, body)
	}
	tok := cookieValue(hdrs["set-cookie"], "webvpn")
	if tok == "" {
		t.Fatalf("没有下发 webvpn cookie: %v", hdrs["set-cookie"])
	}

	// 5) 新连接带 cookie 发 CONNECT（ASA 客户端常见做法）
	conn2 := dialTLS(t, srvAddr)
	defer conn2.Close()
	br2 := bufio.NewReader(conn2)
	req := "CONNECT /CSTP HTTP/1.1\r\nHost: " + srvAddr + "\r\nX-CSTP-Version: 1\r\nCookie: webvpn=" + tok + "\r\n\r\n"
	if _, err := io.WriteString(conn2, req); err != nil {
		t.Fatal(err)
	}
	status, hdrs, _ = readResp(t, br2)
	if !strings.Contains(status, "200 CONNECTED") {
		t.Fatalf("CONNECT 失败: %s", status)
	}
	myIP := first(hdrs, "x-cstp-address")
	if myIP == "" {
		t.Fatalf("没有下发地址")
	}

	// 6) 通过隧道发一个 UDP 包，验证数据面：本地起一个 echo 服务
	echoAddr, stop := startUDPEcho(t)
	defer stop()
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	// 目标必须是非回环地址：gVisor 栈会把 127/8 当 martian 丢掉
	host := hostIPv4()

	pkt := buildIPv4UDP(net.ParseIP(myIP), net.ParseIP(host), 40000, uint16(port), []byte("asa-hello"))
	_ = conn2.SetDeadline(time.Now().Add(8 * time.Second))
	for i := 0; i < 5; i++ {
		if err := cstp.WriteFrame(conn2, cstp.TypeData, pkt); err != nil {
			t.Fatal(err)
		}
		typ, payload, err := cstp.ReadFrame(br2)
		if err != nil {
			t.Fatalf("读隧道帧失败: %v", err)
		}
		if typ != cstp.TypeData || len(payload) < 28 {
			continue
		}
		ihl := int(payload[0]&0x0F) * 4
		if payload[9] != 17 || len(payload) < ihl+8 {
			continue
		}
		if strings.Contains(string(payload[ihl+8:]), "asa-hello") {
			t.Logf("ASA 风格端到端成功：认证 → CONNECT → 隧道 UDP 往返（%s:%d）", host, port)
			return
		}
	}
	t.Fatal("隧道内没有收到 UDP 回包")
}

func dialTLS(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	return c
}

// doReq 发请求并读响应（小响应，按 Content-Length 读）。
func doReq(t *testing.T, conn net.Conn, br *bufio.Reader, method, path string, headers map[string]string, body string) (string, map[string][]string, []byte) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: test\r\nConnection: keep-alive\r\n", method, path)
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	if body != "" || method == "POST" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatalf("发送请求失败: %v", err)
	}
	return readResp(t, br)
}

func readResp(t *testing.T, br *bufio.Reader) (string, map[string][]string, []byte) {
	t.Helper()
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读状态行失败: %v", err)
	}
	hdrs := map[string][]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读头部失败: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if i := strings.IndexByte(line, ':'); i > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			v := strings.TrimSpace(line[i+1:])
			hdrs[k] = append(hdrs[k], v)
		}
	}
	// chunked（大页面 Go 会用 chunked，没有 Content-Length）
	if strings.Contains(strings.ToLower(first(hdrs, "transfer-encoding")), "chunked") {
		var out []byte
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("读 chunk 头失败: %v", err)
			}
			sizeStr := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
			n, err := strconv.ParseInt(sizeStr, 16, 64)
			if err != nil {
				t.Fatalf("chunk 长度非法: %q", sizeStr)
			}
			if n == 0 {
				_, _ = br.ReadString('\n')
				break
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(br, chunk); err != nil {
				t.Fatalf("读 chunk 失败: %v", err)
			}
			out = append(out, chunk...)
			_, _ = br.ReadString('\n')
		}
		return strings.TrimSpace(status), hdrs, out
	}
	n, _ := strconv.Atoi(first(hdrs, "content-length"))
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("读响应体失败: %v", err)
		}
	}
	return strings.TrimSpace(status), hdrs, buf
}

func first(h map[string][]string, k string) string {
	if v, ok := h[k]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func cookieValue(setCookies []string, name string) string {
	for _, c := range setCookies {
		parts := strings.SplitN(c, ";", 2)
		kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		if len(kv) == 2 && kv[0] == name && kv[1] != "" {
			return kv[1]
		}
	}
	return ""
}

func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close() }
}

// buildIPv4UDP 手工构造一个 IPv4+UDP 包（校验和按规范计算）。
func buildIPv4UDP(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	binary.BigEndian.PutUint16(ip[4:6], 1)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))
	return append(ip, udp...)
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
