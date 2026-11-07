#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# xbase — Restore a backup produced by backup-postgres.sh.
#
#   ./scripts/restore-postgres.sh <backup.tar.age|backup.tar.enc> [database] [target-db]
#
#   database   which dump inside the archive to restore (default: postgres)
#   target-db  restore into this database (default: <database>_restore_<date>)
#              Restoring into a NEW database lets you verify before swapping.
#
# For age:     AGE_IDENTITY=/path/to/key.txt
# For openssl: BACKUP_PASSPHRASE=...
# =============================================================================

FILE="${1:?usage: restore-postgres.sh <backup file> [database] [target-db]}"
DB="${2:-postgres}"
TARGET="${3:-${DB}_restore_$(date +%Y%m%d%H%M)}"
DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
PGUSER_DUMP="${PGUSER_DUMP:-supabase_admin}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
umask 077

if [ -f "$FILE.sha256" ]; then
  (cd "$(dirname "$FILE")" && sha256sum -c "$(basename "$FILE").sha256")
fi

case "$FILE" in
  *.age) age -d -i "${AGE_IDENTITY:?set AGE_IDENTITY}" -o "$TMP/backup.tar" "$FILE" ;;
  *.enc) openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE -in "$FILE" -out "$TMP/backup.tar" ;;
  *) echo "unknown backup format: $FILE" >&2; exit 1 ;;
esac

tar -C "$TMP" -xf "$TMP/backup.tar"
DUMP="$(find "$TMP" -name "$DB.dump" | head -1)"
[ -n "$DUMP" ] || { echo "no $DB.dump in archive" >&2; exit 1; }

RESTORE_FLAGS=(--no-owner)
if [ "$TARGET" = "$DB" ]; then
  read -r -p "This OVERWRITES live database '$DB'. Type the database name to confirm: " ok
  [ "$ok" = "$DB" ] || { echo "aborted"; exit 1; }
  RESTORE_FLAGS+=(--clean --if-exists)
else
  docker exec "$DB_CONTAINER" createdb -U "$PGUSER_DUMP" "$TARGET"
fi

echo "==> Restoring $DB.dump into $TARGET ..."
# Supabase dumps contain objects owned by internal roles (extensions, event
# triggers) that emit harmless errors, so restore continues past them.
if ! docker exec -i "$DB_CONTAINER" pg_restore -U "$PGUSER_DUMP" -d "$TARGET" \
  "${RESTORE_FLAGS[@]}" < "$DUMP" 2> "$TMP/restore.log"; then
  echo "pg_restore finished with $(grep -c '^pg_restore: error' "$TMP/restore.log" || true) errors; first ones:" >&2
  grep '^pg_restore: error' "$TMP/restore.log" | head -5 >&2 || true
fi
echo "restored into database: $TARGET"
