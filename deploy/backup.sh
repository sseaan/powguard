#!/usr/bin/env bash
# powguard 备份：SQLite 一致性快照 + master key 提示
#
# 用法：BACKUP_DIR=/var/backups/powguard ./deploy/backup.sh
# 建议由 systemd timer 或 cron 每日执行，并异地同步。
#
# 重要：数据库备份与 POWGUARD_MASTER_KEY 必须成对保存。只备份数据库而丢 key
# 等于永久失去所有站点密钥（密文不可恢复，PLAN.md §6.2）。
set -euo pipefail

DB_PATH="${POWGUARD_DB_PATH:-/var/lib/powguard/powguard.sqlite3}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/powguard}"
KEEP_DAYS="${KEEP_DAYS:-14}"
POWGUARD_BIN="${POWGUARD_BIN:-/usr/local/bin/powguard}"

stamp="$(date +%Y%m%d-%H%M%S)"
dest="${BACKUP_DIR}/powguard-${stamp}.sqlite3"

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

if [[ ! -f "$DB_PATH" ]]; then
  echo "错误：数据库不存在：$DB_PATH" >&2
  exit 1
fi

# VACUUM INTO 生成一致性快照，可在服务运行时执行（无需停服）
"$POWGUARD_BIN" backup --db "$DB_PATH" --out "$dest"

sha256sum "$dest" > "${dest}.sha256"
chmod 0600 "$dest" "${dest}.sha256"

# 校验备份可用：能打开并读取 schema
if command -v sqlite3 >/dev/null 2>&1; then
  if ! sqlite3 "$dest" "select count(*) from schema_migrations;" >/dev/null; then
    echo "错误：备份文件校验失败：$dest" >&2
    exit 1
  fi
fi

# 清理过期备份
find "$BACKUP_DIR" -maxdepth 1 -name 'powguard-*.sqlite3*' -mtime "+${KEEP_DAYS}" -delete

echo "备份完成：$dest"
echo "提醒：请确认 POWGUARD_MASTER_KEY 已在独立位置备份（与数据库分开存放）。"
