// Package events 提供审计事件的异步落库：公共请求路径永不因审计写入阻塞。
//
// IP 以 keyed digest 存储（HMAC-SHA256(master 派生 key)），
// 事件 metadata 为白名单字段（PLAN.md §6.3），永不写入请求体/密钥/明文 IP。
package events

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sseaan/powguard/internal/store/model"
	"github.com/sseaan/powguard/internal/store/sqlite"
)

// Sink 缓冲异步事件写入器。
type Sink struct {
	repo    *sqlite.EventRepo
	ipKey   []byte
	ch      chan *model.Event
	wg      sync.WaitGroup
	dropped atomic.Int64
	started atomic.Bool

	// batch/flush 参数
	batchSize  int
	flushEvery time.Duration
}

// NewSink 构造（buffer = 通道容量；ipKey 由 secretbox.DeriveIPDigestKey 派生）。
func NewSink(repo *sqlite.EventRepo, ipKey []byte, buffer int) *Sink {
	if buffer <= 0 {
		buffer = 1024
	}
	return &Sink{
		repo:       repo,
		ipKey:      ipKey,
		ch:         make(chan *model.Event, buffer),
		batchSize:  64,
		flushEvery: 200 * time.Millisecond,
	}
}

// IPDigest 返回 IP 的 keyed digest（hex 前 16 位），不存明文 IP。
func (s *Sink) IPDigest(ip string) string {
	if ip == "" {
		return ""
	}
	m := hmac.New(sha256.New, s.ipKey)
	m.Write([]byte(ip))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// BuildMeta 序列化白名单 metadata（调用方只放行过白名单键）。
func BuildMeta(kv map[string]string) string {
	if len(kv) == 0 {
		return "{}"
	}
	b, err := json.Marshal(kv)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Emit 非阻塞投递一条事件；缓冲满则丢弃并计数（保护请求路径）。
func (s *Sink) Emit(e *model.Event) {
	if e.Ts == 0 {
		e.Ts = time.Now().UnixMilli()
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Dropped 返回累计丢弃数（监控）。
func (s *Sink) Dropped() int64 { return s.dropped.Load() }

// Start 启动后台批量写入协程。
func (s *Sink) Start(ctx context.Context) {
	if !s.started.CompareAndSwap(false, true) {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		batch := make([]*model.Event, 0, s.batchSize)
		ticker := time.NewTicker(s.flushEvery)
		defer ticker.Stop()
		for {
			select {
			case e := <-s.ch:
				batch = append(batch, e)
				if len(batch) >= s.batchSize {
					s.flush(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					s.flush(batch)
					batch = batch[:0]
				}
			case <-ctx.Done():
				// 退出前尽力排空缓冲
				for {
					select {
					case e := <-s.ch:
						batch = append(batch, e)
					default:
						s.flush(batch)
						return
					}
				}
			}
		}
	}()
}

func (s *Sink) flush(batch []*model.Event) {
	for _, e := range batch {
		if err := s.repo.Insert(e); err != nil {
			// 审计失败不阻塞业务；计数留在 dropped 之外由日志观察
			continue
		}
	}
}

// Close 排空并结束。
func (s *Sink) Close(ctx context.Context) {
	s.wg.Wait()
}
