package usrnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// buildEchoRequest 构造一个 IPv4 + ICMP echo request 包。
func buildEchoRequest(t *testing.T, src, dst net.IP, id, seq uint16, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[28:], payload)

	ip := header.IPv4(pkt[:20])
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	ic := header.ICMPv4(pkt[20:])
	ic.SetType(header.ICMPv4Echo)
	ic.SetCode(0)
	ic.SetIdent(id)
	ic.SetSequence(seq)
	ic.SetChecksum(0)
	ic.SetChecksum(ic.Checksum())
	return pkt
}

func newTestStack(t *testing.T, reply bool) *Stack {
	t.Helper()
	st, err := New(context.Background(), Options{
		MTU:           1400,
		ServerIP:      net.ParseIP("10.66.66.1"),
		PrefixLen:     24,
		ICMPEchoReply: reply,
		Dial: func(network, addr string) (net.Conn, error) {
			t.Logf("不应发起拨号: %s %s", network, addr)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("创建栈失败: %v", err)
	}
	return st
}

// 开启 ICMPEchoReply 时，ping 任意地址都应立刻收到本地应答，
// 源地址是「被 ping 的地址」，延迟即客户端到网关的 RTT。
func TestICMPEchoReply(t *testing.T) {
	st := newTestStack(t, true)
	defer st.Close()

	payload := []byte("hello-ping-payload")
	req := buildEchoRequest(t, net.ParseIP("10.66.66.2"), net.ParseIP("8.8.8.8"), 0x1234, 7, payload)
	if err := st.Inject(req); err != nil {
		t.Fatalf("注入失败: %v", err)
	}

	select {
	case out := <-st.Outbound():
		if len(out) != len(req) {
			t.Fatalf("回复长度不符: got %d want %d", len(out), len(req))
		}
		ip := header.IPv4(out)
		if ip.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
			t.Fatalf("协议应为 ICMP，得到 %d", ip.Protocol())
		}
		if !ip.IsChecksumValid() {
			t.Fatal("IP 头校验和无效")
		}
		if src := net.IP(ip.SourceAddressSlice()); !src.Equal(net.ParseIP("8.8.8.8")) {
			t.Fatalf("回复源地址应为被 ping 的地址 8.8.8.8，得到 %v", src)
		}
		if dst := net.IP(ip.DestinationAddressSlice()); !dst.Equal(net.ParseIP("10.66.66.2")) {
			t.Fatalf("回复目的地址应为客户端 10.66.66.2，得到 %v", dst)
		}

		ic := header.ICMPv4(out[ip.HeaderLength():])
		if ic.Type() != header.ICMPv4EchoReply {
			t.Fatalf("类型应为 echo reply(0)，得到 %d", ic.Type())
		}
		if ic.Code() != 0 {
			t.Fatalf("code 应为 0，得到 %d", ic.Code())
		}
		if ic.Ident() != 0x1234 || ic.Sequence() != 7 {
			t.Fatalf("id/seq 未回显: %d/%d", ic.Ident(), ic.Sequence())
		}
		if sum := checksum.Checksum(out[ip.HeaderLength():], 0); sum != 0xffff {
			t.Fatalf("ICMP 校验和无效（全字之和=%#x，应为 0xffff）", sum)
		}
		if !bytes.Equal(out[28:], payload) {
			t.Fatalf("负载未原样回显: %q", out[28:])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("2 秒内没有收到 ICMP 应答")
	}
}

// 关闭该功能时不本地应答（ping 外部地址不应收到我们伪造的回复）。
func TestICMPEchoDisabled(t *testing.T) {
	st := newTestStack(t, false)
	defer st.Close()

	req := buildEchoRequest(t, net.ParseIP("10.66.66.2"), net.ParseIP("8.8.8.8"), 1, 1, []byte("x"))
	if err := st.Inject(req); err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	select {
	case out := <-st.Outbound():
		// 栈自己回的包（若有）不能是我们伪造的 echo reply
		if len(out) >= 28 && out[9] == 1 && out[20] == byte(header.ICMPv4EchoReply) {
			t.Fatal("关闭后不应本地应答")
		}
	case <-time.After(500 * time.Millisecond):
		// 预期：没有回复
	}
}

// 非 echo request（例如 echo reply、其他类型）不应被本地应答。
func TestICMPNonEchoPassthrough(t *testing.T) {
	st := newTestStack(t, true)
	defer st.Close()

	req := buildEchoRequest(t, net.ParseIP("10.66.66.2"), net.ParseIP("8.8.8.8"), 1, 1, []byte("x"))
	req[20] = byte(header.ICMPv4EchoReply) // 改成 echo reply
	ic := header.ICMPv4(req[20:])
	ic.SetChecksum(0)
	ic.SetChecksum(ic.Checksum())

	if err := st.Inject(req); err != nil {
		t.Fatalf("注入失败: %v", err)
	}
	select {
	case out := <-st.Outbound():
		if len(out) >= 28 && out[9] == 1 && out[20] == byte(header.ICMPv4EchoReply) {
			t.Fatal("非 echo request 不应被本地应答")
		}
	case <-time.After(300 * time.Millisecond):
	}
}
