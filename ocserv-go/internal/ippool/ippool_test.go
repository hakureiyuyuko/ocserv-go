package ippool

import (
	"net"
	"testing"
)

func TestAllocFree(t *testing.T) {
	p, err := New("10.66.66.0/24", "10.66.66.1")
	if err != nil {
		t.Fatal(err)
	}
	a := p.Alloc()
	b := p.Alloc()
	if a == nil || b == nil {
		t.Fatal("分配失败")
	}
	if a.Equal(net.ParseIP("10.66.66.1")) || b.Equal(net.ParseIP("10.66.66.1")) {
		t.Fatal("不能把服务端地址分出去")
	}
	if a.Equal(b) {
		t.Fatal("重复分配")
	}
	p.Free(a)
	c := p.Alloc()
	if !c.Equal(a) {
		t.Fatalf("释放后应能复用: 期望 %v 得到 %v", a, c)
	}
}

func TestBadConfig(t *testing.T) {
	if _, err := New("10.66.66.0/24", "10.66.67.1"); err == nil {
		t.Fatal("服务端 IP 不在网段内应该报错")
	}
	if _, err := New("10.66.66.0/31", "10.66.66.1"); err == nil {
		t.Fatal("过小的网段应该报错")
	}
}

func TestPoolExhausted(t *testing.T) {
	// /29：可用 6 个地址，其中一个留给服务端
	p, err := New("10.0.0.0/29", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for p.Alloc() != nil {
		n++
		if n > 100 {
			t.Fatal("分配没有收敛")
		}
	}
	if n != 5 {
		t.Fatalf("/29 应能分出 5 个地址，实际 %d", n)
	}
}
