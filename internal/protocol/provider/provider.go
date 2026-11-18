// Package provider 为后续协议扩展（HashWX、RSW、instrumentation）定义稳定边界。
//
// 当前版本（PLAN.md §2.1）只实现 format-1 与 format-2 sha256-pow；
// 本包只声明接入契约，不提供任何半成品实现 —— 新协议必须自带 fixture、
// 官方 oracle 双向对拍和真实浏览器测试后才允许注册启用。
package provider

import "encoding/json"

// Challenge 是协议无关的挑战条目（format-2 envelope 的元素）。
type Challenge struct {
	Protocol string          `json:"protocol"`
	Payload  json.RawMessage `json:"payload"`
}

// Solution 是协议无关的解（format-2 redeem body 的 solutions 元素）。
type Solution = json.RawMessage

// Verifier 校验单个挑战条目的解。
// 返回 (ok, err)：ok=false 表示解不匹配；err 非 nil 表示协议内部错误（记 nonce_store_error）。
type Verifier interface {
	// Name 返回 protocol 名（envelope 中 protocol 字段的取值）。
	Name() string

	// Verify 校验 expected（ev 密文中该条目的 expected 部分）与 solution。
	Verify(expected, solution json.RawMessage) (bool, error)
}

// Registry 是协议注册表；WebUI 的协议开关只暴露已注册且测试通过的名字。
type Registry interface {
	// Register 注册一个协议校验器；重名返回 false。
	Register(v Verifier) bool

	// Lookup 按 protocol 名查找。
	Lookup(name string) (Verifier, bool)

	// Names 列出全部已注册协议。
	Names() []string
}

// NewRegistry 返回进程内注册表。
func NewRegistry() Registry { return &mapRegistry{m: map[string]Verifier{}} }

type mapRegistry struct {
	m map[string]Verifier
}

func (r *mapRegistry) Register(v Verifier) bool {
	if _, dup := r.m[v.Name()]; dup {
		return false
	}
	r.m[v.Name()] = v
	return true
}

func (r *mapRegistry) Lookup(name string) (Verifier, bool) {
	v, ok := r.m[name]
	return v, ok
}

func (r *mapRegistry) Names() []string {
	out := make([]string, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	return out
}
