package session

import (
	"path/filepath"
	"testing"

	"capgo/internal/store/sqlite"
)

func newManager(t *testing.T) (*Manager, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sqlite3")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewManager(sqlite.NewSessionRepo(db), 0), func() {}
}

func TestHashStable(t *testing.T) {
	if Hash("abc") != Hash("abc") {
		t.Fatal("哈希应稳定")
	}
	if Hash("abc") == Hash("abd") {
		t.Fatal("不同输入应不同")
	}
}

func TestSessionLifecycle(t *testing.T) {
	m, _ := newManager(t)
	now := int64(5000)

	token, expires, err := m.Create(now)
	if err != nil || token == "" || expires != now+DefaultTTL {
		t.Fatalf("Create：%q %d %v", token, expires, err)
	}
	if len(token) != 64 { // 32 bytes hex
		t.Fatalf("token 长度：%d", len(token))
	}

	ok, exp, err := m.Valid(token, now+1)
	if err != nil || !ok || exp != now+DefaultTTL {
		t.Fatalf("Valid：%v %d %v", ok, exp, err)
	}
	// 过期
	if ok, _, _ := m.Valid(token, now+DefaultTTL+1); ok {
		t.Error("过期应无效")
	}
	// 篡改 token 无效
	if ok, _, _ := m.Valid(token+"x", now); ok {
		t.Error("篡改应无效")
	}
	// 撤销
	if err := m.Revoke(token); err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := m.Valid(token, now); ok {
		t.Error("撤销后应无效")
	}
}

func TestCleanup(t *testing.T) {
	m, _ := newManager(t)
	now := int64(9000)
	if _, _, err := m.Create(now); err != nil {
		t.Fatal(err)
	}
	// DeleteExpired 只清「过期超过 24h」的行（宽限撤销窗口），36h 后可清
	if n, err := m.Cleanup(now + 37*60*60*1000); err != nil || n == 0 {
		t.Errorf("清理应有产出：n=%d err=%v", n, err)
	}
}
