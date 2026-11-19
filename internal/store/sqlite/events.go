package sqlite

import (
	"database/sql"
	"fmt"

	"github.com/sseaan/powguard/internal/store/model"
)

// EventRepo 写入/查询审计事件（白名单字段）。
type EventRepo struct{ db *sql.DB }

func NewEventRepo(db *sql.DB) *EventRepo { return &EventRepo{db: db} }

// Insert 写入一条事件。
func (r *EventRepo) Insert(e *model.Event) error {
	if e.Ts == 0 {
		e.Ts = model.NowMs()
	}
	res, err := r.db.Exec(`INSERT INTO events (ts, site_slug, type, outcome, reason, protocol,
		ip_digest, token_id, dur_ms, meta) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		e.Ts, e.SiteSlug, e.Type, e.Outcome, e.Reason, e.Protocol, e.IPDigest, e.TokenID, e.DurMs, e.Meta)
	if err != nil {
		return fmt.Errorf("sqlite: insert event: %w", err)
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// EventFilter 是 List 查询条件。
type EventFilter struct {
	Site  string
	Type  string
	Limit int
	Since int64 // Unix 毫秒下界
}

// List 按 ts 倒序查询。
func (r *EventRepo) List(f EventFilter) ([]*model.Event, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	where := "WHERE 1=1"
	args := []any{}
	if f.Site != "" {
		where += " AND site_slug=?"
		args = append(args, f.Site)
	}
	if f.Type != "" {
		where += " AND type=?"
		args = append(args, f.Type)
	}
	if f.Since > 0 {
		where += " AND ts>=?"
		args = append(args, f.Since)
	}
	args = append(args, f.Limit)
	rows, err := r.db.Query(`SELECT id, ts, site_slug, type, outcome, reason, protocol, ip_digest, token_id, dur_ms, meta
		FROM events `+where+` ORDER BY ts DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Event
	for rows.Next() {
		e := &model.Event{}
		if err := rows.Scan(&e.ID, &e.Ts, &e.SiteSlug, &e.Type, &e.Outcome, &e.Reason,
			&e.Protocol, &e.IPDigest, &e.TokenID, &e.DurMs, &e.Meta); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DailyStat 是按天聚合行。
type DailyStat struct {
	Day      string `json:"day"` // YYYY-MM-DD（UTC）
	Count    int64  `json:"count"`
	Pass     int64  `json:"pass"`
	Fail     int64  `json:"fail"`
	Blocked  int64  `json:"blocked"`
	LimitHit int64  `json:"limit"`
}

// DailyStats 聚合自 nowMs 向前 days 天的 type 分布。
func (r *EventRepo) DailyStats(nowMs int64, days int, typ string) ([]DailyStat, error) {
	if days <= 0 || days > 90 {
		days = 7
	}
	typeCond := ""
	args := []any{nowMs - int64(days)*86400000}
	if typ != "" {
		typeCond = " AND type=?"
		args = append(args, typ)
	}
	rows, err := r.db.Query(`SELECT date(ts/1000, 'unixepoch') AS day, COUNT(*),
		SUM(outcome='pass'), SUM(outcome='fail'), SUM(outcome='blocked'), SUM(outcome='limit')
		FROM events WHERE ts >= ?`+typeCond+`
		GROUP BY day ORDER BY day`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DailyStat
	for rows.Next() {
		var s DailyStat
		if err := rows.Scan(&s.Day, &s.Count, &s.Pass, &s.Fail, &s.Blocked, &s.LimitHit); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// TopReasons 统计自 nowMs 向前 days 天指定类型的失败原因分布。
func (r *EventRepo) TopReasons(typ string, nowMs int64, days int, limit int) (map[string]int64, error) {
	if days <= 0 {
		days = 7
	}
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.db.Query(`SELECT reason, COUNT(*) FROM events
		WHERE type=? AND outcome != 'pass' AND ts >= ?
		GROUP BY reason ORDER BY COUNT(*) DESC LIMIT ?`, typ, nowMs-int64(days)*86400000, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var reason string
		var n int64
		if err := rows.Scan(&reason, &n); err != nil {
			return nil, err
		}
		out[reason] = n
	}
	return out, rows.Err()
}

// DeleteOlderThan 按保留天数清理（默认 30 天）。
func (r *EventRepo) DeleteOlderThan(nowMs int64, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = model.DefaultEventRetentionDays
	}
	cutoff := nowMs - int64(retentionDays)*24*60*60*1000
	res, err := r.db.Exec(`DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Count 返回事件总数（监控）。
func (r *EventRepo) Count() (int64, error) {
	var n int64
	err := r.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}
