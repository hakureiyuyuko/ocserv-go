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
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

// Users 是一份内存中的用户库。文件被改写（面板增删用户 / 手工 编辑）后
// 会在下次校验时自动重新加载，不需要重启服务。
type Users struct {
	mu   sync.RWMutex
	path string
	m    map[string]string // username → 哈希
	mod  time.Time
	size int64
}

// Load 读取用户文件。行首 # 与空行会被忽略。
func Load(path string) (*Users, error) {
	u := &Users{path: path}
	if err := u.reload(); err != nil {
		return nil, err
	}
	return u, nil
}

// reload 解析整个文件并替换内存里的表。
func (u *Users) reload() error {
	m, err := parseFile(u.path)
	if err != nil {
		return err
	}
	st, statErr := os.Stat(u.path)
	u.mu.Lock()
	u.m = m
	if statErr == nil {
		u.mod, u.size = st.ModTime(), st.Size()
	}
	u.mu.Unlock()
	return nil
}

// checkReload 发现文件 mtime/大小变了就重新加载；解析失败时保留旧表（不把服务搞崩）。
func (u *Users) checkReload() {
	if u == nil || u.path == "" {
		return
	}
	st, err := os.Stat(u.path)
	if err != nil {
		return
	}
	u.mu.RLock()
	same := st.ModTime().Equal(u.mod) && st.Size() == u.size
	u.mu.RUnlock()
	if same {
		return
	}
	m, err := parseFile(u.path)
	if err != nil {
		log.Printf("用户库 %s 改动后解析失败（继续用旧表）: %v", u.path, err)
		return
	}
	u.mu.Lock()
	u.m, u.mod, u.size = m, st.ModTime(), st.Size()
	n := len(m)
	u.mu.Unlock()
	log.Printf("用户库已重新加载: %s（%d 个用户）", u.path, n)
}

func parseFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		// 支持两种格式：
		//   user:哈希                  （ocserv-go 自己的格式）
		//   user:group:哈希            （ocserv/ocpasswd 的格式，面板在用的就是它）
		parts := strings.Split(s, ":")
		var name, hash string
		switch len(parts) {
		case 2:
			name, hash = parts[0], strings.TrimSpace(parts[1])
		case 3:
			name, hash = parts[0], strings.TrimSpace(parts[2])
		default:
			return nil, fmt.Errorf("%s:%d: 需要 用户名:哈希 或 用户名:组:哈希", path, line)
		}
		if name == "" {
			return nil, fmt.Errorf("%s:%d: 用户名为空", path, line)
		}
		if !isSupportedHash(hash) {
			return nil, fmt.Errorf("%s:%d: %q 的密码哈希不受支持（支持 bcrypt $2x$ 与 crypt $5$/$6$/$1$）", path, line, name)
		}
		m[name] = hash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// 空用户库不算错误：跟 ocserv 一样照常启动，只是所有登录都会被拒绝。
	// （面板向导允许先配证书/服务、后加用户；若这里 fatal 就会变成 systemd 无限重启）
	return m, nil
}

// Len 返回用户数，供启动时提示用。
func (u *Users) Len() int {
	u.checkReload()
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.m)
}

// Verify 校验用户名与密码。即使用户名不存在也会跑一次 bcrypt，避免用时差探测用户。
func (u *Users) Verify(name, pass string) bool {
	u.checkReload()
	u.mu.RLock()
	hash, ok := u.m[name]
	u.mu.RUnlock()
	if !ok {
		// 固定的假哈希，保证耗时接近
		_ = verifyHash("$2a$10$C6UzMDM.H6dfI/f/IKcEeO5r1o9Q3g5n8x7y6z5w4v3u2t1s0r9p8", pass)
		return false
	}
	return verifyHash(hash, pass)
}

// isSupportedHash 判断哈希格式：bcrypt 或 crypt(3)（ocpasswd 默认是 $5$/$6$）。
func isSupportedHash(h string) bool {
	for _, p := range []string{"$2a$", "$2b$", "$2y$", "$5$", "$6$", "$1$"} {
		if strings.HasPrefix(h, p) {
			return true
		}
	}
	return false
}

func verifyHash(hash, pass string) bool {
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
	}
	c := crypt.NewFromHash(hash)
	if c == nil {
		return false
	}
	return c.Verify(hash, []byte(pass)) == nil
}

// Has 判断用户是否存在。
func (u *Users) Has(name string) bool {
	u.checkReload()
	u.mu.RLock()
	defer u.mu.RUnlock()
	_, ok := u.m[name]
	return ok
}

// Names 返回用户名列表（日志用）。
func (u *Users) Names() []string {
	u.checkReload()
	u.mu.RLock()
	defer u.mu.RUnlock()
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
