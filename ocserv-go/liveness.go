package main

// 连接保活与死链检测（语义与 ocserv 的 periodic_check() 对齐）。
//
// 手机熄屏/换网后，旧 TCP 与 DTLS 都可能变成"黑洞"：内核不会报错，
// 客户端却以为还连着。ocserv 的做法是：
//   · 2×dpd 没收到包 → 主动发 DPD 探测（TCP 与 DTLS 分别判断）
//   · 3×dpd 没收到 TCP 帧 → 判定隧道死亡，断开
//   · 3×dpd 没收到 UDP 包 → 禁用 DTLS，数据回落到 TCP
//   · 超过 idle-timeout 没有用户数据 → 断开（默认关闭）
//
// 这里把判定做成纯函数，方便单测。

import (
	"fmt"
	"time"
)

// liveCfg 是一条隧道的保活参数。
type liveCfg struct {
	dpd       time.Duration // DPD 间隔；0 = 关闭保活检测
	idle      time.Duration // 无用户数据的超时；0 = 不限制
	switchTCP time.Duration // DTLS 静默多久后数据改走 TCP；0 = 不切换
}

// liveClock 记录最近一次收包 / 发包的时间点（零值表示"还没发生"）。
type liveClock struct {
	tcp      time.Time // 最近一次收到 TCP CSTP 帧
	udp      time.Time // 最近一次收到 DTLS 数据报
	data     time.Time // 最近一次收到用户数据（隧道里的 IP 包）
	probeTCP time.Time // 最近一次发出 TCP DPD
	probeUDP time.Time // 最近一次发出 DTLS DPD
}

// liveDecision 是一轮检查的结论。
type liveDecision struct {
	SendDPDTCP bool
	SendDPDUDP bool
	DropDTLS   string // 非空 = 关闭 DTLS，内容是日志原因
	DropTunnel string // 非空 = 断开整条隧道，内容是日志原因
}

// decideLiveness 按 ocserv 的语义给出一轮检查该做什么。
func decideLiveness(now time.Time, c liveClock, dtlsActive bool, cfg liveCfg) liveDecision {
	var d liveDecision

	if cfg.dpd > 0 {
		if dtlsActive {
			silent := now.Sub(c.udp)
			switch {
			case silent > 3*cfg.dpd:
				d.DropDTLS = fmt.Sprintf("DTLS 超时：%.0f 秒没收到 UDP 包（3×dpd=%s），数据改走 TCP（保留 DTLS 等待恢复）",
					silent.Seconds(), durText(3*cfg.dpd))
			case silent > 2*cfg.dpd && probeDue(now, c.probeUDP, cfg.dpd):
				d.SendDPDUDP = true
			}
		}
		silent := now.Sub(c.tcp)
		switch {
		case silent > 3*cfg.dpd:
			d.DropTunnel = fmt.Sprintf("DPD 超时：%.0f 秒没收到 TCP 包（3×dpd=%s），断开隧道",
				silent.Seconds(), durText(3*cfg.dpd))
		case silent > 2*cfg.dpd && probeDue(now, c.probeTCP, cfg.dpd):
			d.SendDPDTCP = true
		}
	}

	if d.DropTunnel == "" && cfg.idle > 0 && now.Sub(c.data) > cfg.idle {
		d.DropTunnel = fmt.Sprintf("空闲超时：%.0f 秒没有用户数据（阈值 %s），断开隧道",
			now.Sub(c.data).Seconds(), durText(cfg.idle))
	}
	return d
}

// probeDue 限制探测包最多每个 dpd 发一个（否则每秒都会重复发）。
func probeDue(now, last time.Time, dpd time.Duration) bool {
	return last.IsZero() || now.Sub(last) >= dpd
}

// dtlsEgressOK 判断发数据时还能不能走 DTLS：
// DTLS 静默超过 switch-to-tcp-timeout 就先走 TCP，等客户端再发 UDP 包再切回来。
func dtlsEgressOK(now, lastUDP time.Time, cfg liveCfg) bool {
	if cfg.switchTCP <= 0 {
		return true
	}
	return now.Sub(lastUDP) <= cfg.switchTCP
}

func durText(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
	return d.String()
}
