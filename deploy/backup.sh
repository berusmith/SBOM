#!/usr/bin/env bash
# SQLite daily backup — keeps last 14 copies
# Usage: bash backup.sh
# Cron: 0 2 * * * /home/opc/sbom-platform/deploy/backup.sh >> /var/log/sbom-backup.log 2>&1

set -euo pipefail

DB_PATH="${SBOM_DB_PATH:-/home/opc/sbom-platform/backend/sbom.db}"
BACKUP_DIR="${SBOM_BACKUP_DIR:-/home/opc/sbom-backups}"
KEEP_DAYS=14

mkdir -p "$BACKUP_DIR"

if [ ! -f "$DB_PATH" ]; then
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: DB not found at $DB_PATH"
  exit 1
fi

TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
DEST="$BACKUP_DIR/sbom_${TIMESTAMP}.db"

# Use SQLite's .backup command for a consistent snapshot (safe during writes)
sqlite3 "$DB_PATH" ".backup '$DEST'"

SIZE=$(du -sh "$DEST" | cut -f1)
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Backup OK: $DEST ($SIZE)"

# Rotate: delete backups older than KEEP_DAYS days
find "$BACKUP_DIR" -name "sbom_*.db" -mtime +${KEEP_DAYS} -delete
REMAINING=$(find "$BACKUP_DIR" -name "sbom_*.db" | wc -l)
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Retained $REMAINING backup(s)"
