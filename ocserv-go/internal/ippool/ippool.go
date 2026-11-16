// Package ippool 从客户端网段里分配地址（服务端地址会被排除）。
package ippool

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// Pool 是一个简单的 IPv4 地址池。
type Pool struct {
	mu        sync.Mutex
	base      uint32 // 网段起始
	broadcast uint32
	server    uint32 // 服务端地址，永不分配
	used      map[uint32]net.IP
}

// New 用 CIDR（如 10.66.66.0/24）与服务端 IP 建池。
func New(cidr, serverIP string) (*Pool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("客户端网段不合法: %w", err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("只支持 IPv4 网段")
	}
	if ones > 30 {
		return nil, fmt.Errorf("网段太小（需要至少 /30）")
	}
	srv := net.ParseIP(serverIP).To4()
	if srv == nil {
		return nil, fmt.Errorf("服务端 IP 不合法: %q", serverIP)
	}
	if !ipnet.Contains(srv) {
		return nil, fmt.Errorf("服务端 IP %s 不在网段 %s 内", serverIP, cidr)
	}
	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	size := uint32(1) << (32 - ones)
	return &Pool{
		base:      base,
		broadcast: base + size - 1,
		server:    binary.BigEndian.Uint32(srv),
		used:      make(map[uint32]net.IP),
	}, nil
}

// Alloc 分配一个可用地址；没有余量时返回 nil。
func (p *Pool) Alloc() net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()
	for a := p.base + 1; a < p.broadcast; a++ {
		if a == p.server {
			continue
		}
		if _, busy := p.used[a]; busy {
			continue
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, a)
		p.used[a] = ip
		return ip
	}
	return nil
}

// Free 归还地址。
func (p *Pool) Free(ip net.IP) {
	if ip == nil {
		return
	}
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	p.mu.Lock()
	delete(p.used, binary.BigEndian.Uint32(v4))
	p.mu.Unlock()
}

// InUse 返回当前占用数。
func (p *Pool) InUse() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.used)
}
