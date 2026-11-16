// Package auth 提供用户库（bcrypt 哈希）与校验。
//
// 文件格式与 htpasswd 类似，每行 `用户名:哈希`：
//
//	alice:$2a$10$...
//
// 用 `ocserv-go hash <密码>` 生成哈希行。
package auth

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Users 是一份内存中的用户库。
type Users struct {
	m map[string]string // username → bcrypt hash
}

// Load 读取用户文件。行首 # 与空行会被忽略。
func Load(path string) (*Users, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	u := &Users{m: make(map[string]string)}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		i := strings.IndexByte(s, ':')
		if i <= 0 {
			return nil, fmt.Errorf("%s:%d: 需要 用户名:哈希 格式", path, line)
		}
		name := s[:i]
		hash := strings.TrimSpace(s[i+1:])
		if !strings.HasPrefix(hash, "$2") {
			return nil, fmt.Errorf("%s:%d: %q 不是 bcrypt 哈希（用 `ocserv-go hash` 生成）", path, line, name)
		}
		u.m[name] = hash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(u.m) == 0 {
		return nil, fmt.Errorf("%s: 没有任何用户", path)
	}
	return u, nil
}

// Verify 校验用户名与密码。即使用户名不存在也会跑一次 bcrypt，避免用时差探测用户。
func (u *Users) Verify(name, pass string) bool {
	hash, ok := u.m[name]
	if !ok {
		// 固定的假哈希，保证耗时接近
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$C6UzMDM.H6dfI/f/IKcEeO5r1o9Q3g5n8x7y6z5w4v3u2t1s0r9p8"), []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

// Has 判断用户是否存在。
func (u *Users) Has(name string) bool {
	_, ok := u.m[name]
	return ok
}

// Names 返回用户名列表（日志用）。
func (u *Users) Names() []string {
	out := make([]string, 0, len(u.m))
	for k := range u.m {
		out = append(out, k)
	}
	return out
}

// Hash 生成 bcrypt 哈希。
func Hash(pass string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ConstantTimeEqual 是给测试/令牌比较用的小工具。
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
