#!/usr/bin/env bash
# capgo 恢复：把备份快照部署回数据目录
#
# 用法：
#   sudo MASTER_KEY=<key> ./deploy/restore.sh /var/backups/capgo/capgo-20260101-030000.sqlite3
#
# 步骤：停服 → 校验备份完整性 → 原子替换（含 WAL/SHM 清理）→ 校验密文可解 → 启动
set -euo pipefail

BACKUP_FILE="${1:-}"
DB_PATH="${CAPGO_DB_PATH:-/var/lib/capgo/capgo.sqlite3}"
MASTER_KEY="${MASTER_KEY:-}"
CAPGO_BIN="${CAPGO_BIN:-/usr/local/bin/capgo}"
SERVICE="${SERVICE:-capgo}"

if [[ -z "$BACKUP_FILE" || ! -f "$BACKUP_FILE" ]]; then
  echo "用法：MASTER_KEY=<key> $0 <备份文件>" >&2
  exit 1
fi

# 1. 备份自带校验和（如存在）
if [[ -f "${BACKUP_FILE}.sha256" ]]; then
  ( cd "$(dirname "$BACKUP_FILE")" && sha256sum -c "$(basename "${BACKUP_FILE}").sha256" )
fi

# 2. 停服
echo "停止服务 $SERVICE …"
systemctl stop "$SERVICE" || true

# 3. 现有库保留为 .pre-restore（便于回滚）
if [[ -f "$DB_PATH" ]]; then
  echo "保留当前库：${DB_PATH}.pre-restore"
  rm -f "${DB_PATH}.pre-restore" "${DB_PATH}.pre-restore-wal" "${DB_PATH}.pre-restore-shm"
  mv "$DB_PATH" "${DB_PATH}.pre-restore"
fi
# WAL/SHM 必须一并清理，否则旧 WAL 会污染新库
rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"

# 4. 原子放置备份
install -m 0600 -o capgo -g capgo "$BACKUP_FILE" "$DB_PATH"

# 5. 校验密文可用给定 master key 解密（防止恢复后站点密钥全废）
if [[ -n "$MASTER_KEY" ]]; then
  echo "校验 master key …"
  if ! "$CAPGO_BIN" verify-keys --db "$DB_PATH" --master-key "$MASTER_KEY"; then
    echo "错误：备份与 master key 不匹配，已停在停止状态以便排查。" >&2
    exit 1
  fi
else
  echo "警告：未提供 MASTER_KEY，跳过密文校验。" >&2
fi

# 6. 启动并健康检查
echo "启动服务 $SERVICE …"
systemctl start "$SERVICE"
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
  echo "恢复完成：$DB_PATH"
  if [[ -n "$MASTER_KEY" ]]; then
    curl -fsS http://127.0.0.1:3000/healthz >/dev/null && echo "健康检查通过"
  fi
else
  echo "错误：服务未能启动，请查看 journalctl -u $SERVICE -n 50" >&2
  exit 1
fi
