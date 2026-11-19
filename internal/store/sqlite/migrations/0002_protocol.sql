-- 0002：站点协议开关（format1 | format2；format-2 当前仅 sha256-pow）
ALTER TABLE sites ADD COLUMN protocol TEXT NOT NULL DEFAULT 'format1';
