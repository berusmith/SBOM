#!/usr/bin/env bash
# 自動偵測 backend/.env 的 DATABASE_URL,SQLite 走 .backup,Postgres 走 pg_dump custom format。
# 保留最近 KEEP_DAYS 天(預設 14)。
#
# SEC-014 fix (2026-04-26): backups encrypted with gpg AES-256 when
# $SBOM_BACKUP_GPG_KEY points to a readable passphrase file (default
# $HOME/.sbom-backup-key).  If the key is missing, the script prints
# a loud warning and writes plaintext — to avoid breaking existing
# crontabs on first roll-out.  Set $SBOM_BACKUP_REQUIRE_GPG=1 to make
# the script abort instead.
#
# Usage:
#   bash deploy/backup.sh
#
# Schedule (macOS, cron 例):
#   crontab -e
#   0 2 * * * /Users/<you>/sbom/deploy/backup.sh >> /Users/<you>/sbom/logs/backup.log 2>&1
#
# 環境變數覆寫:
#   SBOM_HOME                 部署根(預設 $HOME/sbom)
#   SBOM_DATABASE_URL         直接指定 DSN(略過讀 .env)
#   SBOM_BACKUP_DIR           備份輸出目錄(預設 $SBOM_HOME/backups)
#   SBOM_KEEP_DAYS            保留天數(預設 14)
#   SBOM_BACKUP_GPG_KEY       gpg passphrase file(預設 $HOME/.sbom-backup-key)
#   SBOM_BACKUP_REQUIRE_GPG   設 1 → 找不到 key 就 abort(預設 warn-and-continue)
#
# 一次性設定 gpg passphrase file(off-host store the key separately):
#   umask 077
#   openssl rand -base64 48 > "$HOME/.sbom-backup-key"
#   # backup the key file to USB / 1Password / cloud Vault — this is what
#   # decrypts everything;losing it = 14 天備份永久失效
#
# 還原(SQLite, gpg-encrypted):
#   gpg --batch --passphrase-file "$HOME/.sbom-backup-key" \
#       --decrypt sbom_<ts>.db.gpg > /tmp/restore.db
#   sqlite3 path/to/sbom.db ".restore '/tmp/restore.db'"
#
# 還原(Postgres, gpg-encrypted):
#   gpg --batch --passphrase-file "$HOME/.sbom-backup-key" \
#       --decrypt sbom_<ts>.dump.gpg > /tmp/restore.dump
#   pg_restore --clean --if-exists -d postgresql://user:pass@host/db /tmp/restore.dump

set -euo pipefail

SBOM_HOME="${SBOM_HOME:-$HOME/sbom}"
BACKUP_DIR="${SBOM_BACKUP_DIR:-$SBOM_HOME/backups}"
KEEP_DAYS="${SBOM_KEEP_DAYS:-14}"
ENV_FILE="$SBOM_HOME/backend/.env"
GPG_KEY="${SBOM_BACKUP_GPG_KEY:-$HOME/.sbom-backup-key}"
REQUIRE_GPG="${SBOM_BACKUP_REQUIRE_GPG:-0}"

# Resolve DATABASE_URL: env var wins, then .env file
if [ -z "${SBOM_DATABASE_URL:-}" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: $ENV_FILE not found and SBOM_DATABASE_URL not set"
        exit 1
    fi
    DATABASE_URL="$(grep -E '^DATABASE_URL=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
else
    DATABASE_URL="$SBOM_DATABASE_URL"
fi

if [ -z "${DATABASE_URL:-}" ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: DATABASE_URL is empty"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
TS_LOG="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ── SEC-014: gpg encryption gating ─────────────────────────────────────
GPG_AVAILABLE=0
if [ -r "$GPG_KEY" ]; then
    if command -v gpg >/dev/null 2>&1; then
        GPG_AVAILABLE=1
    else
        echo "[$TS_LOG] WARN: gpg not on PATH;備份將以明文寫入"
    fi
else
    if [ "$REQUIRE_GPG" = "1" ]; then
        echo "[$TS_LOG] ERROR: SBOM_BACKUP_REQUIRE_GPG=1 但 $GPG_KEY 不存在/不可讀"
        exit 1
    fi
    echo "[$TS_LOG] WARN: $GPG_KEY 不存在 — 備份將以明文寫入。SEC-014 防線未啟用。"
    echo "[$TS_LOG]       設定方式：umask 077 && openssl rand -base64 48 > $GPG_KEY"
fi

# encrypt_to_gpg <plain_path> → echoes encrypted path; deletes plain on success.
encrypt_to_gpg() {
    local plain="$1"
    local enc="${plain}.gpg"
    if gpg --batch --yes --quiet --symmetric --cipher-algo AES256 \
           --passphrase-file "$GPG_KEY" \
           --output "$enc" "$plain"; then
        # shred the plain copy if available; otherwise plain rm (best-effort)
        if command -v shred >/dev/null 2>&1; then
            shred -u "$plain" 2>/dev/null || rm -f "$plain"
        else
            rm -f "$plain"
        fi
        echo "$enc"
    else
        echo "[$TS_LOG] ERROR: gpg encryption failed for $plain — leaving plaintext in place"
        echo "$plain"
        return 1
    fi
}

case "$DATABASE_URL" in
    sqlite*)
        # ── SQLite ──────────────────────────────────────────────────────
        # Strip sqlite:/// prefix; resolve relative paths against $SBOM_HOME/backend
        DB_PATH="${DATABASE_URL#sqlite:///}"
        DB_PATH="${DB_PATH#sqlite:////}"
        case "$DB_PATH" in
            /*) ;;  # absolute, keep as-is
            *) DB_PATH="$SBOM_HOME/backend/$DB_PATH" ;;
        esac

        if [ ! -f "$DB_PATH" ]; then
            echo "[$TS_LOG] ERROR: SQLite DB not found at $DB_PATH"
            exit 1
        fi

        DEST="$BACKUP_DIR/sbom_${TIMESTAMP}.db"
        sqlite3 "$DB_PATH" ".backup '$DEST'"
        if [ "$GPG_AVAILABLE" = "1" ]; then
            DEST="$(encrypt_to_gpg "$DEST")"
        fi
        SIZE="$(du -sh "$DEST" | cut -f1)"
        echo "[$TS_LOG] SQLite backup OK: $DEST ($SIZE)"

        # Rotate (cover both legacy plain and new .gpg variants)
        find "$BACKUP_DIR" \( -name "sbom_*.db" -o -name "sbom_*.db.gpg" \) \
            -mtime +${KEEP_DAYS} -delete
        REMAINING="$(find "$BACKUP_DIR" \( -name "sbom_*.db" -o -name "sbom_*.db.gpg" \) | wc -l | tr -d ' ')"
        echo "[$TS_LOG] Retained $REMAINING SQLite backup(s)"
        ;;

    postgresql*|postgres*)
        # ── Postgres ────────────────────────────────────────────────────
        # pg_dump understands SQLAlchemy URLs only after stripping the +driver part.
        PG_URL="$(echo "$DATABASE_URL" | sed -E 's|^(postgres(ql)?)\+[a-z0-9]+://|\1://|')"

        # Locate pg_dump (Homebrew postgresql@16 is keg-only)
        if command -v pg_dump >/dev/null 2>&1; then
            PG_DUMP="pg_dump"
        elif command -v brew >/dev/null 2>&1 && brew --prefix postgresql@16 >/dev/null 2>&1; then
            PG_DUMP="$(brew --prefix postgresql@16)/bin/pg_dump"
        else
            echo "[$TS_LOG] ERROR: pg_dump not found. Install postgresql@16 or add to PATH."
            exit 1
        fi

        DEST="$BACKUP_DIR/sbom_${TIMESTAMP}.dump"
        # --format=custom  → compressed binary, readable by pg_restore
        # --no-owner/--no-acl → restorable into a different user/role
        "$PG_DUMP" --format=custom --no-owner --no-acl --file="$DEST" "$PG_URL"
        if [ "$GPG_AVAILABLE" = "1" ]; then
            DEST="$(encrypt_to_gpg "$DEST")"
        fi
        SIZE="$(du -sh "$DEST" | cut -f1)"
        echo "[$TS_LOG] Postgres backup OK: $DEST ($SIZE)"

        # Rotate (cover both legacy plain and new .gpg variants)
        find "$BACKUP_DIR" \( -name "sbom_*.dump" -o -name "sbom_*.dump.gpg" \) \
            -mtime +${KEEP_DAYS} -delete
        REMAINING="$(find "$BACKUP_DIR" \( -name "sbom_*.dump" -o -name "sbom_*.dump.gpg" \) | wc -l | tr -d ' ')"
        echo "[$TS_LOG] Retained $REMAINING Postgres backup(s)"
        ;;

    *)
        echo "[$TS_LOG] ERROR: Unsupported DATABASE_URL scheme: ${DATABASE_URL%%:*}"
        exit 1
        ;;
esac
