// Package prng 实现官方 cap 的 fnv1a + xorshift32 伪随机数生成器。
//
// 与 @cap.js/server@4.0.5（index.js）和 capjs-core@0.1.18（src/prng.js）
// bit-exact。关键语义：
//   - 种子按 UTF-16 code unit（JS charCodeAt）哈希，不是 UTF-8 字节；
//   - 全部算术是 JS int32 环绕语义；
//   - 每轮输出 uint32 的小写 hex、8 位零填充，最终截断到 length。
//
// 论证见 docs/protocol-notes.md §1。
package prng

import "strings"

// fnvOffset 是 2166136261（0x811C9DC5）的 int32 位型（即 -2128831035）。
const fnvOffset int32 = -2128831035

// CodeUnits 将 Go 字符串展开为 UTF-16 code unit 序列（等价 JS charCodeAt）。
// runes 在 BMP 内占一个 unit；补充平面字符拆成代理对。
func CodeUnits(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	for _, r := range s {
		switch {
		case r < 0x10000:
			units = append(units, uint16(r))
		default: // 代理对
			r -= 0x10000
			units = append(units, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		}
	}
	return units
}

// fnvStep 执行一次 JS 循环体：h ^= u; h += (h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24)。
// int32 环绕运算与 JS 的「double 求和 + XOR 截断」模 2³² 等价。
func fnvStep(h int32, u uint16) int32 {
	h ^= int32(u)
	h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)
	return h
}

// FNV1a 返回 fnv1a(seed) 的 uint32（JS `hash >>> 0`）。
func FNV1a(seed string) uint32 {
	h := fnvOffset
	for _, u := range CodeUnits(seed) {
		h = fnvStep(h, u)
	}
	return uint32(h)
}

// FNV1aResume 对应 capjs-core 的 fnv1aResume(state, str)：从已有状态续哈希。
func FNV1aResume(state uint32, s string) uint32 {
	h := int32(state)
	for _, u := range CodeUnits(s) {
		h = fnvStep(h, u)
	}
	return uint32(h)
}

const hexDigits = "0123456789abcdef"

// GenerateFromHash 从初始状态产出 length 个 hex 字符（xorshift32 输出流）。
// length ≤ 0 返回空串；最后一轮可能多产最多 7 个字符，随后截断（与官方一致）。
func GenerateFromHash(initial uint32, length int) string {
	if length <= 0 {
		return ""
	}
	var b strings.Builder
	state := int32(initial)
	for b.Len() < length {
		state ^= state << 13
		state ^= int32(uint32(state) >> 17) // JS `>>>`：逻辑右移
		state ^= state << 5
		b.WriteByte(hexDigits[(uint32(state)>>28)&0xf])
		b.WriteByte(hexDigits[(uint32(state)>>24)&0xf])
		b.WriteByte(hexDigits[(uint32(state)>>20)&0xf])
		b.WriteByte(hexDigits[(uint32(state)>>16)&0xf])
		b.WriteByte(hexDigits[(uint32(state)>>12)&0xf])
		b.WriteByte(hexDigits[(uint32(state)>>8)&0xf])
		b.WriteByte(hexDigits[(uint32(state)>>4)&0xf])
		b.WriteByte(hexDigits[uint32(state)&0xf])
	}
	return b.String()[:length]
}

// Generate 等价官方 prng(seed, length)。
func Generate(seed string, length int) string {
	return GenerateFromHash(FNV1a(seed), length)
}
