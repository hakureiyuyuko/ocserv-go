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

// 帧头与负载必须一次写出（否则会被拆成两个 TLS 记录，客户端解析失败）。
func TestWriteFrameSingleWrite(t *testing.T) {
	var w oneWrite
	payload := []byte{0x45, 0x00, 0x00, 0x28}
	if err := WriteFrame(&w, TypeData, payload); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("应一次写出，实际 %d 次", w.writes)
	}
	want := []byte{'S', 'T', 'F', 1, 0x00, 0x04, 0x00, 0x00, 0x45, 0x00, 0x00, 0x28}
	if string(w.buf) != string(want) {
		t.Fatalf("字节不符: got % x want % x", w.buf, want)
	}
}

type oneWrite struct {
	buf    []byte
	writes int
}

func (o *oneWrite) Write(p []byte) (int, error) {
	o.writes++
	o.buf = append(o.buf, p...)
	return len(p), nil
}
