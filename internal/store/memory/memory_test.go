package memory

import (
	"sync"
	"sync/atomic"
	"testing"

	"capgo/internal/protocol/format1"
)

func TestDataChallengeOneShot(t *testing.T) {
	s := NewChallengeStore()
	s.Put("tok", format1.ChallengeData{Expires: 100})
	if _, ok := s.Consume("tok"); !ok {
		t.Fatal("首次消费应成功")
	}
	if _, ok := s.Consume("tok"); ok {
		t.Fatal("二次消费应失败")
	}
	if s.Len() != 0 {
		t.Errorf("存储未清空：%d", s.Len())
	}
}

func TestChallengeConcurrentConsume(t *testing.T) {
	s := NewChallengeStore()
	s.Put("tok", format1.ChallengeData{Expires: 1 << 60})
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.Consume("tok"); ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("并发消费应恰好一次成功，实际 %d 次", w)
	}
}

func TestChallengeDeleteExpired(t *testing.T) {
	s := NewChallengeStore()
	s.Put("a", format1.ChallengeData{Expires: 50})
	s.Put("b", format1.ChallengeData{Expires: 150})
	if n := s.DeleteExpired(100); n != 1 {
		t.Errorf("应清理 1 条，实际 %d", n)
	}
	if s.Len() != 1 {
		t.Errorf("清理后应剩 1 条：%d", s.Len())
	}
}

func TestTokenConsumeStatuses(t *testing.T) {
	s := NewTokenStore()
	s.Put("k1", 200)
	s.Put("k2", 50) // 已过期（相对 now=100）
	if got := s.Consume("k1", 100); got != TokenConsumed {
		t.Errorf("k1 应 TokenConsumed，得到 %d", got)
	}
	if got := s.Consume("k1", 100); got != TokenMissing {
		t.Errorf("k1 二次应 TokenMissing，得到 %d", got)
	}
	if got := s.Consume("k2", 100); got != TokenExpired {
		t.Errorf("k2 应 TokenExpired，得到 %d", got)
	}
	if got := s.Consume("k2", 100); got != TokenMissing {
		t.Errorf("k2 过期清理后应 TokenMissing，得到 %d", got)
	}
	if got := s.Consume("never", 100); got != TokenMissing {
		t.Errorf("不存在的 key 应 TokenMissing，得到 %d", got)
	}
}

func TestTokenConcurrentConsume(t *testing.T) {
	s := NewTokenStore()
	s.Put("k", 1<<60)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Consume("k", 100) == TokenConsumed {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("并发消费应恰好一次成功，实际 %d 次", w)
	}
}

func TestRateLimiterWindow(t *testing.T) {
	l := NewRateLimiter()
	for i := 0; i < 3; i++ {
		if !l.Allow("ip", 3, 5000, 1000) {
			t.Fatalf("第 %d 次应放行", i+1)
		}
	}
	if l.Allow("ip", 3, 5000, 1000) {
		t.Fatal("超限应拒绝")
	}
	// 窗口翻页后重置
	if !l.Allow("ip", 3, 5000, 6000) {
		t.Fatal("翻页后应放行")
	}
	// 其他 key 互不影响
	if !l.Allow("ip2", 3, 5000, 1000) {
		t.Fatal("其他 key 应独立计数")
	}
	if l.Cleanup(15000, 5000) < 1 {
		t.Error("惰性清理应有产出")
	}
}
