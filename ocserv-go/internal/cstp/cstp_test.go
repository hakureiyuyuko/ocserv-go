package cstp

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		typ     Type
		payload []byte
	}{
		{TypeData, []byte("hello")},
		{TypeDPDReq, nil},
		{TypeDPDResp, []byte{0x01}},
		{TypeData, bytes.Repeat([]byte{0xAB}, 1400)},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, c.typ, c.payload); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		if buf.Len() != HeaderLen+len(c.payload) {
			t.Fatalf("长度不对: %d", buf.Len())
		}
		typ, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
		if typ != c.typ || !bytes.Equal(payload, c.payload) {
			t.Fatalf("往返不一致: %v/%q != %v/%q", typ, payload, c.typ, c.payload)
		}
	}
}

func TestBadSTF(t *testing.T) {
	buf := bytes.NewReader([]byte{0x99, 0, 0, 0, 0, 0, 0, 0})
	if _, _, err := ReadFrame(buf); err == nil {
		t.Fatal("非法 STF 应该报错")
	}
}

func TestTooLarge(t *testing.T) {
	// 长度字段 0xFFFF 超过 MaxPayload（64K）——构造时用 MaxPayload+1
	var buf bytes.Buffer
	_ = WriteFrame(&buf, TypeData, bytes.Repeat([]byte{0}, MaxPayload+1))
	if buf.Len() != 0 {
		t.Fatal("超过上限时不应写出任何内容")
	}
}
