-- 0001：初始 schema
CREATE TABLE sites (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    slug                 TEXT NOT NULL UNIQUE,
    name                 TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 1,
    deleted              INTEGER NOT NULL DEFAULT 0, -- 软删除
    challenge_count      INTEGER NOT NULL DEFAULT 50,
    challenge_size       INTEGER NOT NULL DEFAULT 32,
    challenge_difficulty INTEGER NOT NULL DEFAULT 4,
    challenge_ttl_ms     INTEGER NOT NULL DEFAULT 600000,
    token_ttl_ms         INTEGER NOT NULL DEFAULT 1200000,
    cors_allow_all       INTEGER NOT NULL DEFAULT 1,
    cors_origins         TEXT NOT NULL DEFAULT '',   -- 逗号分隔白名单
    rate_limit_per_window INTEGER NOT NULL DEFAULT 30,
    rate_limit_window_ms  INTEGER NOT NULL DEFAULT 5000,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE site_secrets (
    site_id        INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    field          TEXT NOT NULL,
    ciphertext     TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    rotated_at     INTEGER NOT NULL,
    PRIMARY KEY (site_id, field)
);

CREATE TABLE admin_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    site_slug TEXT NOT NULL,
    type      TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    reason    TEXT NOT NULL DEFAULT '',
    protocol  TEXT NOT NULL DEFAULT 'format1',
    ip_digest TEXT NOT NULL DEFAULT '',
    token_id  TEXT NOT NULL DEFAULT '',
    dur_ms    INTEGER,
    meta      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_site_ts ON events(site_slug, ts);
CREATE INDEX idx_events_type_ts ON events(type, ts);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
