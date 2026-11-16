package panel

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/hakureiyuyuko/ocserv-go/internal/auth"
)

// VPNUser 是 ocpasswd 里的一行（面板只展示与增删改，不关心具体哈希算法）。
type VPNUser struct {
	Name    string `json:"name"`
	Group   string `json:"group"`
	HasHash bool   `json:"hasHash"`
}

var userNameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,32}$`)

// ReadUsers 解析 ocpasswd：`user:group:hash` 或 `user:hash`。
func ReadUsers(path string) []VPNUser {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []VPNUser
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		u := VPNUser{Name: parts[0], Group: parts[1]}
		if u.Group == "*" {
			u.Group = ""
		}
		if len(parts) >= 3 {
			u.HasHash = strings.TrimSpace(parts[2]) != ""
		} else {
			u.HasHash = strings.TrimSpace(parts[1]) != ""
		}
		if u.Name != "" {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func readUserLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines
}

func writeUserLines(path string, lines []string) error {
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(body), 0o600)
}

// AddUser 新增或重置用户密码（bcrypt，ocserv-go 原生支持；不用等 C 版 ocpasswd）。
func AddUser(path, name, password string) error {
	if !userNameRe.MatchString(name) {
		return fmt.Errorf("用户名只能包含字母/数字/._@-，最长 32 位")
	}
	if len(password) < 6 {
		return fmt.Errorf("密码至少 6 位")
	}
	hash, err := auth.Hash(password)
	if err != nil {
		return err
	}
	line := name + ":*:" + hash
	lines := readUserLines(path)
	found := false
	for i, l := range lines {
		if strings.SplitN(l, ":", 2)[0] == name {
			lines[i] = line
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, line)
	}
	return writeUserLines(path, lines)
}

// DelUser 删除用户。
func DelUser(path, name string) error {
	if !userNameRe.MatchString(name) {
		return fmt.Errorf("非法用户名")
	}
	lines := readUserLines(path)
	out := lines[:0]
	removed := false
	for _, l := range lines {
		if strings.SplitN(l, ":", 2)[0] == name {
			removed = true
			continue
		}
		out = append(out, l)
	}
	if !removed {
		return fmt.Errorf("用户不存在")
	}
	return writeUserLines(path, out)
}
