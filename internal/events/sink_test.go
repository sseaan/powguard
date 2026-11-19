package events

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sseaan/powguard/internal/store/model"
	"github.com/sseaan/powguard/internal/store/sqlite"
)

func newSink(t *testing.T) (*Sink, *sqlite.EventRepo) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "e.sqlite3")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo := sqlite.NewEventRepo(db)
	return NewSink(repo, []byte("ip-digest-key-32-bytes_________"), 64), repo
}

func TestIPDigest(t *testing.T) {
	sink, _ := newSink(t)
	d := sink.IPDigest("1.2.3.4")
	if len(d) != 16 {
		t.Fatalf("digest 长度：%d", len(d))
	}
	if d != sink.IPDigest("1.2.3.4") {
		t.Error("同 IP 摘要应稳定")
	}
	if d == sink.IPDigest("1.2.3.5") {
		t.Error("不同 IP 应不同")
	}
	if sink.IPDigest("") != "" {
		t.Error("空 IP 应返回空串")
	}
	// 不含明文 IP
	if strings.Contains(d, "1.2.3.4") {
		t.Error("digest 不应包含明文 IP")
	}
}

func TestEmitFlushes(t *testing.T) {
	sink, repo := newSink(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink.Start(ctx)

	for i := 0; i < 10; i++ {
		sink.Emit(&model.Event{SiteSlug: "twikoo", Type: "challenge", Outcome: "pass", Protocol: "format1"})
	}
	// flushEvery=200ms；等最多 2 秒
	deadline := time.Now().Add(2 * time.Second)
	for {
		list, _ := repo.List(sqlite.EventFilter{Limit: 100})
		if len(list) >= 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("事件未落库：%d", len(list))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 落库事件含 IP 摘要吗？Emit 前调用方填 IPDigest（handler 负责）；sink 只透传
}

func TestEmitDropsWhenFull(t *testing.T) {
	sink := NewSink(nil, []byte("k"), 1) // 容量 1，不启动消费协程
	sink.Emit(&model.Event{Type: "a"})
	sink.Emit(&model.Event{Type: "b"}) // 缓冲满，非阻塞丢弃
	if sink.Dropped() == 0 {
		t.Error("缓冲满应计数丢弃")
	}
}

func TestBuildMeta(t *testing.T) {
	if BuildMeta(nil) != "{}" {
		t.Error("空 map 应输出 {}")
	}
	if BuildMeta(map[string]string{"ua": "chrome"}) != `{"ua":"chrome"}` {
		t.Error("白名单序列化错误")
	}
}
