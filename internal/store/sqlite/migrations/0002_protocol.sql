-- 0002：站点协议开关（format1 | format2；format-2 当前仅 sha256-pow，PLAN.md §P2）
ALTER TABLE sites ADD COLUMN protocol TEXT NOT NULL DEFAULT 'format1';
