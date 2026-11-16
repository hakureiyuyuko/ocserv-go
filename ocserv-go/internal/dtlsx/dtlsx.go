// Package dtlsx 是 pion/dtls 的薄封装：UDP 监听 + 可预置会话（Cisco 风格）。
//
// AnyConnect/ASA 的 DTLS 不是普通握手：客户端在 CSTP CONNECT 里用
// X-DTLS-Master-Secret 给出 48 字节主密钥，双方据此做「恢复握手」。
// 这里用一个内存 SessionStore 把该主密钥按会话 ID 预置进去，pion 就会走恢复流程。
package dtlsx

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/pion/dtls/v3"
)

// Cisco 风格 DTLS 使用的套件（RSA 证书）。
const (
	SuiteRSA     = dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	SuiteNameRSA = "ECDHE-RSA-AES256-GCM-SHA384"
)

// Store 是内存 SessionStore（key = 会话 ID 的 hex）。
type Store struct {
	mu sync.Mutex
	m  map[string]dtls.Session
}

// NewStore 建一个空 store。
func NewStore() *Store { return &Store{m: make(map[string]dtls.Session)} }

// Set 实现 dtls.SessionStore。
func (s *Store) Set(key []byte, sess dtls.Session) error {
	s.mu.Lock()
	s.m[keyString(key)] = sess
	s.mu.Unlock()
	return nil
}

// Get 实现 dtls.SessionStore。
func (s *Store) Get(key []byte) (dtls.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[keyString(key)]
	if !ok {
		return dtls.Session{}, errors.New("session not found")
	}
	return sess, nil
}

// Del 实现 dtls.SessionStore。
func (s *Store) Del(key []byte) error {
	s.mu.Lock()
	delete(s.m, keyString(key))
	s.mu.Unlock()
	return nil
}

func keyString(b []byte) string { return hex.EncodeToString(b) }

// Listener 包住 DTLS 监听器。
type Listener struct {
	ln    net.Listener
	store *Store
}

// Listen 在 addr 上监听 DTLS。
func Listen(addr string, cert tls.Certificate, mtu int, store *Store) (*Listener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("解析 DTLS 监听地址失败: %w", err)
	}
	cfg := &dtls.Config{
		Certificates: []tls.Certificate{cert},
		// Cisco 的恢复握手不带 extended master secret，这里用默认（请求但不强制）
		ExtendedMasterSecret: dtls.RequestExtendedMasterSecret,
		ClientAuth:           dtls.NoClientCert,
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		SessionStore: store,
		MTU:          mtu,
	}
	ln, err := dtls.Listen("udp", ua, cfg)
	if err != nil {
		return nil, fmt.Errorf("DTLS 监听失败: %w", err)
	}
	return &Listener{ln: ln, store: store}, nil
}

// Seed 预置一个恢复会话：会话 ID + 客户端给的主密钥。
func (l *Listener) Seed(id []byte, secret []byte, suite dtls.CipherSuiteID) error {
	if len(secret) != 48 {
		return fmt.Errorf("主密钥长度应为 48，实际 %d", len(secret))
	}
	return l.store.Set(id, dtls.Session{
		ID:                   id,
		Secret:               secret,
		Version:              1,
		IsClient:             false,
		CipherSuiteID:        suite,
		ExtendedMasterSecret: false,
	})
}

// Accept 接受一个 DTLS 连接（握手完成）。
func (l *Listener) Accept() (net.Conn, error) { return l.ln.Accept() }

// Addr 返回监听地址。
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close 关闭监听。
func (l *Listener) Close() error { return l.ln.Close() }
