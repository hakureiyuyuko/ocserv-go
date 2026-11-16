// Package usrnet 把 CTC 隧道里的原始 IP 包接到 gVisor 的用户态 TCP/IP 栈上，
// 并把每个 TCP 连接 / UDP 流代理成普通 socket 从本进程出网。
//
// 这样服务端不需要 /dev/net/tun、不需要 CAP_NET_ADMIN、不需要 iptables
// 或 ip_forward —— 无特权 LXC / Docker 里也能跑。
package usrnet

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

var debug = os.Getenv("OCSERV_GO_DEBUG") != ""

func dbg(f string, a ...any) {
	if debug {
		log.Printf("[usrnet] "+f, a...)
	}
}

// DialFunc 用来从宿主机出网（可换成 SOCKS5 之类的实现）。
type DialFunc func(network, addr string) (net.Conn, error)

// Options 是网络栈参数。
type Options struct {
	MTU       int
	ServerIP  net.IP // 栈内服务端地址，例如 10.66.66.1
	PrefixLen int    // 例如 24
	Dial      DialFunc
	// ICMPEchoReply 为 true 时，客户端发来的 ICMP echo 请求直接由服务端
	// 本地应答（回 echo reply，源地址就是被 ping 的地址）。
	// 这样应用测到的延迟是「客户端 ↔ 网关」的 RTT。
	ICMPEchoReply bool
}

// Stack 是一个客户端专属的用户态网络栈。
type Stack struct {
	s        *stack.Stack
	ep       *channel.Endpoint
	out      chan []byte
	dial     DialFunc
	ctx      context.Context
	cancel   context.CancelFunc
	once     sync.Once
	icmpEcho bool
}

// New 创建并启动一个栈。
func New(ctx context.Context, o Options) (*Stack, error) {
	if o.MTU <= 0 {
		o.MTU = 1400
	}
	if o.Dial == nil {
		d := &net.Dialer{}
		o.Dial = func(network, addr string) (net.Conn, error) { return d.Dial(network, addr) }
	}
	ip4 := o.ServerIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("服务端 IP 必须是 IPv4")
	}
	prefix := o.PrefixLen
	if prefix <= 0 || prefix > 32 {
		prefix = 24
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	ep := channel.New(1024, uint32(o.MTU), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("创建 NIC 失败: %v", err)
	}
	// 允许接收“发往任意目的地址”的包，并把它们交给下面的 forwarder
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	var addr [4]byte
	copy(addr[:], ip4)
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(addr), PrefixLen: prefix},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("添加地址失败: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	st := &Stack{
		s:        s,
		ep:       ep,
		out:      make(chan []byte, 256),
		dial:     o.Dial,
		icmpEcho: o.ICMPEchoReply,
	}
	st.ctx, st.cancel = context.WithCancel(ctx)

	// TCP：每个新连接拨到真实目的地，然后双向拷贝
	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		endp, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true) // 回 RST
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, endp)
		dest := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		dbg("TCP 新连接 -> %s", dest)
		go st.proxyTCP(conn, dest)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// UDP：按流代理（DNS/QUIC 等）
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		endp, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		conn := gonet.NewUDPConn(&wq, endp)
		dest := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		dbg("UDP 新流 -> %s", dest)
		go st.proxyUDP(conn, dest)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go st.readLoop()
	return st, nil
}

func (st *Stack) proxyTCP(client net.Conn, dest string) {
	defer client.Close()
	up, err := st.dial("tcp", dest)
	if err != nil {
		dbg("拨号失败 %s: %v", dest, err)
		return
	}
	defer up.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	select {
	case <-done:
	case <-st.ctx.Done():
	}
}

func (st *Stack) proxyUDP(client net.Conn, dest string) {
	defer client.Close()
	up, err := st.dial("udp", dest)
	if err != nil {
		dbg("UDP 拨号失败 %s: %v", dest, err)
		return
	}
	defer up.Close()
	dbg("UDP 代理就绪 %s", dest)

	buf := make([]byte, 64<<10)
	go func() {
		for {
			n, err := up.Read(buf)
			if err != nil {
				dbg("UDP 上游读结束 %s: %v", dest, err)
				client.Close()
				return
			}
			dbg("UDP 上游->客户端 %d 字节", n)
			if _, werr := client.Write(buf[:n]); werr != nil {
				dbg("UDP 写回客户端失败: %v", werr)
				return
			}
		}
	}()
	for {
		n, err := client.Read(buf)
		if err != nil {
			dbg("UDP 客户端读结束 %s: %v", dest, err)
			return
		}
		dbg("UDP 客户端->上游 %d 字节", n)
		if _, werr := up.Write(buf[:n]); werr != nil {
			dbg("UDP 写上游失败: %v", werr)
			return
		}
	}
}

// Inject 把一个来自客户端的 IP 包送进栈。
func (st *Stack) Inject(b []byte) error {
	if len(b) < 20 {
		return fmt.Errorf("IP 包太短: %d", len(b))
	}
	if b[0]>>4 != 4 {
		return fmt.Errorf("暂只支持 IPv4（收到版本 %d）", b[0]>>4)
	}
	// ICMP echo（ping）：开启时直接本地应答，不去真实目的地
	if st.icmpEcho && st.replyICMPEcho(b) {
		return nil
	}
	if debug && len(b) >= 20 {
		dbg("收到 IP 包: %s -> %s proto=%d len=%d", net.IP(b[12:16]), net.IP(b[16:20]), b[9], len(b))
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), b...)),
	})
	defer pkt.DecRef()
	st.ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	return nil
}

// replyICMPEcho 判断是否为 ICMPv4 echo request，是则构造 echo reply 直接回给客户端，
// 返回 true 表示已处理（调用方不要再把原包送进栈）。
//
// 语义：客户端 ping 任何地址都能立刻得到应答，应用测到的延迟 = 客户端到网关的 RTT。
func (st *Stack) replyICMPEcho(b []byte) bool {
	if len(b) < 28 {
		return false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl+8 {
		return false
	}
	if b[9] != 1 { // IPv4 protocol = ICMP
		return false
	}
	if b[ihl] != 8 || b[ihl+1] != 0 { // type 8 = echo request, code 0
		return false
	}

	out := make([]byte, len(b))
	copy(out, b)

	// 交换源/目的地址：回复的 source 就是被 ping 的地址
	copy(out[12:16], b[16:20])
	copy(out[16:20], b[12:16])
	out[8] = 64             // TTL
	out[10], out[11] = 0, 0 // 先清零 IP 头校验和

	ip := header.IPv4(out[:ihl])
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	ic := header.ICMPv4(out[ihl:])
	ic.SetType(header.ICMPv4EchoReply)
	ic.SetCode(0)
	ic.SetChecksum(0)
	ic.SetChecksum(ic.Checksum())

	if debug {
		dbg("ICMP echo 本地应答: %s -> %s len=%d", net.IP(out[12:16]), net.IP(out[16:20]), len(out))
	}
	select {
	case st.out <- out:
		return true
	case <-st.ctx.Done():
		return true
	}
}

// Outbound 返回栈要发给客户端的 IP 包。
func (st *Stack) Outbound() <-chan []byte { return st.out }

func (st *Stack) readLoop() {
	defer close(st.out)
	for {
		// Read() 是非阻塞的，空读会立刻返回 nil；这里用可取消的阻塞读
		pkt := st.ep.ReadContext(st.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		b := append([]byte(nil), v.AsSlice()...)
		if debug {
			if len(b) >= 20 {
				dbg("出栈包: %s -> %s proto=%d len=%d", net.IP(b[12:16]), net.IP(b[16:20]), b[9], len(b))
			} else {
				dbg("出栈包（短）len=%d", len(b))
			}
		}
		v.Release()
		pkt.DecRef()
		if debug && len(b) >= 20 {
			dbg("回给客户端: %s -> %s proto=%d len=%d", net.IP(b[12:16]), net.IP(b[16:20]), b[9], len(b))
		}
		select {
		case st.out <- b:
		case <-st.ctx.Done():
			return
		}
	}
}

// Close 停止栈。
func (st *Stack) Close() {
	st.once.Do(func() {
		st.cancel()
		st.ep.Close()
		st.s.Close()
	})
}
