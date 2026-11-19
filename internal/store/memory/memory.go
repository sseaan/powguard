// Package memory 提供进程内短期状态：challenge、verification token、限流窗口。
// 全部消费路径都在锁内完成读-删，保证一次性语义原子。
package memory

import (
	"sync"

	"github.com/sseaan/powguard/internal/protocol/format1"
)

// ChallengeStore 是 format-1 挑战状态存储（等价官方 challengesList）。
type ChallengeStore struct {
	mu sync.Mutex
	m  map[string]format1.ChallengeData
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{m: make(map[string]format1.ChallengeData)}
}

// Put 写入挑战状态（重复 token 覆盖）。
func (s *ChallengeStore) Put(token string, data format1.ChallengeData) {
	s.mu.Lock()
	s.m[token] = data
	s.mu.Unlock()
}

// Consume 原子取出并删除挑战状态；不存在返回 false。
// 官方语义：读取即删除（失败的 redeem 也烧掉挑战）。
func (s *ChallengeStore) Consume(token string) (format1.ChallengeData, bool) {
	s.mu.Lock()
	data, ok := s.m[token]
	if ok {
		delete(s.m, token)
	}
	s.mu.Unlock()
	return data, ok
}

// DeleteExpired 清理过期挑战，返回清理数量。
func (s *ChallengeStore) DeleteExpired(nowMs int64) int {
	s.mu.Lock()
	n := 0
	for k, v := range s.m {
		if v.Expires < nowMs {
			delete(s.m, k)
			n++
		}
	}
	s.mu.Unlock()
	return n
}

// Len 返回当前条目数（监控/测试用）。
func (s *ChallengeStore) Len() int {
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	return n
}

// TokenStore 是通行 token 存储（key = "id:sha256(vertoken)"，值 = 过期毫秒）。
type TokenStore struct {
	mu sync.Mutex
	m  map[string]int64
}

func NewTokenStore() *TokenStore {
	return &TokenStore{m: make(map[string]int64)}
}

// Put 写入通行 token。
func (s *TokenStore) Put(key string, expiresMs int64) {
	s.mu.Lock()
	s.m[key] = expiresMs
	s.mu.Unlock()
}

// TokenStatus 是一次性消费的结果，区分 capd siteverify 的 404/403 语义。
type TokenStatus int

const (
	TokenMissing  TokenStatus = iota // 不存在（含已被消费/清理）
	TokenExpired                     // 存在但已过期（消费时删除）
	TokenConsumed                    // 存在且未过期，已原子消费
)

// Consume 原子消费：返回未找到 / 已过期 / 消费成功。
// 一次性语义（官方 validateToken 默认即删）。
func (s *TokenStore) Consume(key string, nowMs int64) TokenStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[key]
	if !ok {
		return TokenMissing
	}
	if exp < nowMs {
		delete(s.m, key)
		return TokenExpired
	}
	delete(s.m, key)
	return TokenConsumed
}

// TryClaim 原子占位：key 不存在（或已过期）则写入并返回 true；
// 已被占位且未过期返回 false。占位者持有到期为止（nonce 一次性语义，区别于 Consume）。
func (s *TokenStore) TryClaim(key string, nowMs, expiresAt int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.m[key]; ok && exp >= nowMs {
		return false
	}
	s.m[key] = expiresAt
	return true
}

// Peek 只读检查（keepToken 语义 / 测试）。
func (s *TokenStore) Peek(key string, nowMs int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[key]
	return ok && exp >= nowMs
}

// DeleteExpired 清理过期 token，返回清理数量。
func (s *TokenStore) DeleteExpired(nowMs int64) int {
	s.mu.Lock()
	n := 0
	for k, v := range s.m {
		if v < nowMs {
			delete(s.m, k)
			n++
		}
	}
	s.mu.Unlock()
	return n
}

// Len 返回当前条目数。
func (s *TokenStore) Len() int {
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	return n
}

// RateLimiter 是固定窗口限流器（每 key 每窗口 N 次）。
type RateLimiter struct {
	mu sync.Mutex
	m  map[string]windowState
}

type windowState struct {
	windowStart int64
	count       int
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{m: make(map[string]windowState)}
}

// Allow 记录一次请求并判断是否放行。
func (l *RateLimiter) Allow(key string, limit int, windowMs, nowMs int64) bool {
	if limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.m[key]
	if !ok || nowMs-st.windowStart >= windowMs {
		l.m[key] = windowState{windowStart: nowMs, count: 1}
		return true
	}
	st.count++
	l.m[key] = st
	return st.count <= limit
}

// Cleanup 清理已经翻页的窗口（惰性调用）。
func (l *RateLimiter) Cleanup(nowMs, windowMs int64) int {
	l.mu.Lock()
	n := 0
	for k, st := range l.m {
		if nowMs-st.windowStart >= windowMs {
			delete(l.m, k)
			n++
		}
	}
	l.mu.Unlock()
	return n
}

// Len 返回活跃 key 数。
func (l *RateLimiter) Len() int {
	l.mu.Lock()
	n := len(l.m)
	l.mu.Unlock()
	return n
}
