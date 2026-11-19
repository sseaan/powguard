// Package sqlite 是 capgo 的持久层（modernc.org/sqlite 纯 Go 驱动，CGO-free）。
package sqlite

import (
	"database/sql"
	"embed"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite" // 纯 Go 驱动注册 "sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Open 打开（并按需创建）数据库，应用全部迁移，返回可用的 *sql.DB。
func Open(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %s: %w", path, err)
	}
	// modernc 驱动在连接上串行化写更稳；限制并发连接避免 SQLITE_BUSY 抖动
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: ping %s: %w", path, err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
