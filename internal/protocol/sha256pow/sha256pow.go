// Package sha256pow 实现 Cap 的 SHA-256 工作量证明校验与求解。
package sha256pow

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Hex 返回 sha256(s) 的小写 hex（官方 crypto.createHash("sha256").digest("hex")）。
func Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Matches 校验 sha256hex(salt + solution) 的 hex 是否以 target 开头。
// target 必须是合法 hex 字符串；与官方 hash.startsWith(target) 语义一致
// （hex 前缀比较是 capjs-core 字节级前缀比较的超集，二者对合法输入等价）。
func Matches(salt, solution, target string) bool {
	if target == "" {
		return true
	}
	sum := sha256.Sum256([]byte(salt + solution))
	h := hex.EncodeToString(sum[:])
	return len(h) >= len(target) && h[:len(target)] == target
}

// MatchesBytes 是字节级前缀比较（capjs-core powMatchesPrefix 语义），
// 支持 odd-length target（半字节对齐）。capgo 对外统一用 Matches，
// 此函数供 format-2 与官方字节级语义对拍。
func MatchesBytes(salt, solution string, target string) bool {
	hex := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			return int(c-'A') + 10
		}
		return -1
	}
	for i := 0; i < len(target); i++ {
		if hex(target[i]) < 0 {
			return false
		}
	}
	fullBytes := len(target) / 2
	sum := sha256.Sum256([]byte(salt + solution))
	for i := 0; i < fullBytes; i++ {
		if int(sum[i]) != hex(target[i*2])<<4|hex(target[i*2+1]) {
			return false
		}
	}
	if len(target)%2 == 1 {
		if int(sum[fullBytes]>>4) != hex(target[len(target)-1]) {
			return false
		}
	}
	return true
}

// Solve 暴力搜索使 sha256(salt + decimal(n)) 以 target 为前缀的最小非负整数 n。
// 供测试与 tools/capsolve 使用，不进入服务路径。
func Solve(salt, target string) int64 {
	for n := int64(0); ; n++ {
		if Matches(salt, strconv.FormatInt(n, 10), target) {
			return n
		}
	}
}
