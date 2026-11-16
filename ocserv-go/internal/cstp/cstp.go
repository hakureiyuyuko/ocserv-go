// Package cstp 实现 Cisco SSL VPN 的 CSTP 分帧。
//
// 隧道建立后（HTTP 200 CONNECTED），双方都用 8 字节头 + 负载的帧：
//
//	字节 0     : STF，固定 0x01
//	字节 1-2   : 负载长度（大端 16 位）
//	字节 3     : 类型
//	字节 4-7   : 保留（0）
//
// 类型 0 的负载是一个完整的 IP 包（客户端 ↔ 服务端）。
package cstp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// HeaderLen 是 CSTP 头长度。
const HeaderLen = 8

// STF 是头首字节的固定值。
const STF = 0x01

// Type 是 CSTP 帧类型。
type Type uint8

const (
	TypeData       Type = 0x00 // IP 数据包
	TypeDPDReq     Type = 0x03 // 对端保活请求
	TypeDPDResp    Type = 0x04 // 保活应答
	TypeDisconnect Type = 0x05 // 断开
	TypeKeepalive  Type = 0x07 // 保活
	TypeCompressed Type = 0x08 // 压缩数据（未实现）
	TypeTerminate  Type = 0x09 // 终止
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

// MaxPayload 是单帧负载上限（IP 包不会超过 MTU，留足余量）。
const MaxPayload = 64 * 1024

// WriteFrame 写一帧。
func WriteFrame(w io.Writer, typ Type, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrTooLarge
	}
	var h [HeaderLen]byte
	h[0] = STF
	binary.BigEndian.PutUint16(h[1:3], uint16(len(payload)))
	h[3] = byte(typ)
	// 4..7 保持 0
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame 读一帧。返回的 payload 是新分配的切片。
func ReadFrame(r io.Reader) (Type, []byte, error) {
	var h [HeaderLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0] != STF {
		return 0, nil, fmt.Errorf("%w: STF=0x%02x", ErrBadFrame, h[0])
	}
	n := int(binary.BigEndian.Uint16(h[1:3]))
	if n > MaxPayload {
		return 0, nil, ErrTooLarge
	}
	typ := Type(h[3])
	if n == 0 {
		return typ, nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return typ, buf, nil
}
