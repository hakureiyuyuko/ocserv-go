package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/hakureiyuyuko/ocserv-go/internal/auth"
	"github.com/hakureiyuyuko/ocserv-go/internal/cstp"
)

// TestTunnelTCP 走完整协议栈：认证 → CONNECT → CSTP 隧道 → 客户端 gVisor 栈
// → 服务端用户态栈 → 从宿主机拨号到本地 HTTP 服务 → 数据回传。
func TestTunnelTCP(t *testing.T) {
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
		Users:     users,
		ClientNet: "10.66.66.0/24",
		ServerIP:  "10.66.66.1",
		MTU:       1400,
		DPD:       0,
		DNS:       []string{"1.1.1.1"},
		Domain:    "test.local",
		Style:     "ocserv", // 这个测试覆盖 ocserv 的 XML 登录风格
	})
	if err != nil {
		t.Fatal(err)
	}
	// 自己起 TLS 监听（要用和生产一致的 ConnContext）
	cert, err := makeSelfSigned("test.local")
	if err != nil {
		t.Fatal(err)
	}
	lnTLS, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hsrv := &http.Server{
		Handler:     srv,
		ConnContext: withSession,
		ErrorLog:    log.New(io.Discard, "", 0),
	}
	go func() { _ = hsrv.Serve(tls.NewListener(lnTLS, &tls.Config{Certificates: []tls.Certificate{cert}})) }()
	defer hsrv.Close()
	srvAddr := lnTLS.Addr().String()

	// 宿主机上的目标服务（监听 0.0.0.0）
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello-from-host")
	})}
	go func() { _ = hs.Serve(ln) }()
	defer hs.Close()
	targetPort := ln.Addr().(*net.TCPAddr).Port
	targetIP := hostIPv4()

	// 1) TLS + 认证
	conn, err := tls.Dial("tcp", srvAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)

	status, _, _ := doPost(t, conn, br, "/", xmlInit())
	if !strings.Contains(status, "200") {
		t.Fatalf("init 失败: %s", status)
	}
	doPost(t, conn, br, "/auth", xmlUser("alice"))
	status, body, _ := doPost(t, conn, br, "/auth", xmlPass("alice", "test123"))
	if !strings.Contains(body, `id="success"`) {
		t.Fatalf("认证未通过: %s / %s", status, body)
	}

	// 2) CONNECT 建隧道
	req := "CONNECT /CSTP HTTP/1.1\r\nHost: " + srvAddr + "\r\nX-CSTP-Version: 1\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	status, _, headers := readHTTP(t, br)
	if !strings.Contains(status, "200 CONNECTED") {
		t.Fatalf("CONNECT 失败: %s", status)
	}
	if headers["x-cstp-address"] == "" {
		t.Fatalf("没有下发地址: %v", headers)
	}
	if headers["x-cstp-dns"] == "" {
		t.Fatalf("没有下发 DNS: %v", headers)
	}

	// 3) 客户端 gVisor 栈
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cst, cep := newClientStack(t, headers["x-cstp-address"])

	var wmu sync.Mutex
	send := func(typ cstp.Type, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return cstp.WriteFrame(conn, typ, p)
	}

	// 隧道 → 客户端栈
	go func() {
		for {
			typ, payload, err := cstp.ReadFrame(br)
			if err != nil {
				return
			}
			switch typ {
			case cstp.TypeData:
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(payload)})
				cep.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			case cstp.TypeDPDReq:
				_ = send(cstp.TypeDPDResp, nil)
			}
		}
	}()
	// 客户端栈 → 隧道
	go func() {
		for {
			pkt := cep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			b := append([]byte(nil), v.AsSlice()...)
			v.Release()
			pkt.DecRef()
			if err := send(cstp.TypeData, b); err != nil {
				return
			}
		}
	}()

	// 4) 在客户端栈里拨 TCP 到宿主机的 HTTP 服务
	var dst [4]byte
	copy(dst[:], net.ParseIP(targetIP).To4())
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	vc, err := gonet.DialContextTCP(dialCtx, cst,
		tcpip.FullAddress{Addr: tcpip.AddrFrom4(dst), Port: uint16(targetPort)}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("隧道内 TCP 拨号失败: %v", err)
	}
	defer vc.Close()

	fmt.Fprintf(vc, "GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", targetIP, targetPort)
	resp, err := http.ReadResponse(bufio.NewReader(vc), nil)
	if err != nil {
		t.Fatalf("读取 HTTP 响应失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if !strings.Contains(string(respBody), "hello-from-host") {
		t.Fatalf("响应内容不对: %q", respBody)
	}
	t.Logf("隧道内 TCP 成功: %s:%d → %q", targetIP, targetPort, strings.TrimSpace(string(respBody)))
}

func newClientStack(t *testing.T, ip string) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(256, 1400, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("客户端 NIC: %v", err)
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		t.Fatalf("客户端地址不合法: %q", ip)
	}
	var a [4]byte
	copy(a[:], v4)
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(a), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("客户端地址: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, ep
}

func hostIPv4() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
			if v4 := n.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return "127.0.0.1"
}

func xmlInit() string {
	return `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="init"><version who="vpn">4.10.04071</version><capabilities><auth-method>single-sign-on-v2</auth-method></capabilities></config-auth>`
}
func xmlUser(u string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-reply"><auth><username>` + u + `</username></auth></config-auth>`
}
func xmlPass(u, p string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-reply"><auth><username>` + u + `</username><password>` + p + `</password></auth></config-auth>`
}

func doPost(t *testing.T, conn net.Conn, br *bufio.Reader, path, body string) (status, respBody string, headers map[string]string) {
	t.Helper()
	req := "POST " + path + " HTTP/1.1\r\nHost: test\r\nContent-Type: application/xml\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: keep-alive\r\n\r\n" + body
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("发送 %s 失败: %v", path, err)
	}
	return readHTTP(t, br)
}

func readHTTP(t *testing.T, br *bufio.Reader) (string, string, map[string]string) {
	t.Helper()
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读状态行失败: %v", err)
	}
	headers := map[string]string{}
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
			headers[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	n, _ := strconv.Atoi(headers["content-length"])
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("读响应体失败: %v", err)
		}
	}
	return strings.TrimSpace(status), string(buf), headers
}
