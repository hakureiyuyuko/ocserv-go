// Package cstp 实现 Cisco SSL VPN 的 CSTP 分帧。
//
// TCP 上的帧头固定 8 字节（与 openconnect 的 cstp.c 一致）：
//
//	0000  Magic "STF\x01"
//	0004  大端 16 位负载长度（不含 8 字节头）
//	0006  包类型（见下方常量）
//	0007  必须为 0
//	0008  负载（通常是一个完整 IP 包）
//
// DTLS 上不用这个头，而是 1 字节类型 + 负载（见 WriteDTLS/ReadDTLS）。
package cstp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// HeaderLen 是 CSTP 头长度。
const HeaderLen = 8

// 魔数 "STF" 与版本号。
const (
	magic0      = 'S'
	magic1      = 'T'
	magic2      = 'F'
	versionByte = 0x01
)

// Type 是 CSTP 包类型（与 openconnect 的 AC_PKT_* 一致）。
type Type uint8

const (
	TypeData       Type = 0 // 未压缩数据（IP 包）
	TypeDPDReq     Type = 3 // 对端保活请求
	TypeDPDResp    Type = 4 // 保活应答
	TypeDisconnect Type = 5 // 客户端断开通知
	TypeKeepalive  Type = 7 // 保活
	TypeCompressed Type = 8 // 压缩数据（未实现）
	TypeTerminate  Type = 9 // 服务端踢下线
)

func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeDPDReq:
		return "DPD-REQ"
	case TypeDPDResp:
		return "DPD-RESP"
	case TypeDisconnect:
		return "DISCONNECT"
	case TypeKeepalive:
		return "KEEPALIVE"
	case TypeCompressed:
		return "COMPRESSED"
	case TypeTerminate:
		return "TERMINATE"
	default:
		return fmt.Sprintf("TYPE(%d)", uint8(t))
	}
}

// ErrBadFrame 表示帧头不合法（不是 CSTP 流）。
var ErrBadFrame = errors.New("cstp: 帧头不合法")

// ErrTooLarge 表示长度字段超过上限。
var ErrTooLarge = errors.New("cstp: 帧过大")

// MaxPayload 是单帧负载上限。
const MaxPayload = 64 * 1024

// WriteFrame 写一个 TCP CSTP 帧。
//
// 必须「帧头 + 负载」一次写出：分两次 Write 时 Go 的 TLS 会拆成两个 TLS 记录，
// 客户端（openconnect / 真 AnyConnect）单次读到的记录只有 8 字节帧头，
// 会报 "Unexpected packet length ... SSL_read returned 8" 并丢包错位，
// 表现为隧道刚建立就断开重连。
func WriteFrame(w io.Writer, typ Type, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrTooLarge
	}
	buf := make([]byte, HeaderLen+len(payload))
	buf[0], buf[1], buf[2], buf[3] = magic0, magic1, magic2, versionByte
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(payload)))
	buf[6] = byte(typ)
	buf[7] = 0
	copy(buf[HeaderLen:], payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame 读一个 TCP CSTP 帧。
func ReadFrame(r io.Reader) (Type, []byte, error) {
	var h [HeaderLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0] != magic0 || h[1] != magic1 || h[2] != magic2 || h[3] != versionByte || h[7] != 0 {
		return 0, nil, fmt.Errorf("%w: %02x %02x %02x %02x", ErrBadFrame, h[0], h[1], h[2], h[3])
	}
	n := int(binary.BigEndian.Uint16(h[4:6]))
	if n > MaxPayload {
		return 0, nil, ErrTooLarge
	}
	typ := Type(h[6])
	if n == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return typ, buf, nil
}

// WriteDTLS 写一个 DTLS 数据报：[1 字节类型][负载]。
func WriteDTLS(w io.Writer, typ Type, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrTooLarge
	}
	b := make([]byte, 1+len(payload))
	b[0] = byte(typ)
	copy(b[1:], payload)
	_, err := w.Write(b)
	return err
}

// ParseDTLS 解析一个 DTLS 数据报。
func ParseDTLS(pkt []byte) (Type, []byte, error) {
	if len(pkt) < 1 {
		return 0, nil, ErrBadFrame
	}
	return Type(pkt[0]), pkt[1:], nil
}
