#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# xbase — Encrypted PostgreSQL backups to S3 / Cloudflare R2 / Backblaze B2.
#
# Dumps every database in the Supabase Postgres container (pg_dumpall globals +
# per-database pg_dump custom format), encrypts with `age` (or OpenSSL as a
# fallback), uploads with `rclone`, and prunes old local + remote copies.
#
# Config: /etc/xbase/backup.env (or env vars):
#   DB_CONTAINER=supabase-db
#   BACKUP_DIR=/var/backups/xbase
#   RETENTION_DAYS=14
#   AGE_RECIPIENT=age1...                 # preferred: public key, private key kept offline
#   BACKUP_PASSPHRASE=...                 # fallback: openssl aes-256 (pbkdf2)
#   RCLONE_REMOTE=r2:my-bucket/xbase      # configure with `rclone config`
#   HEALTHCHECK_URL=https://hc-ping.com/<uuid>   # optional dead-man switch
# =============================================================================

CONFIG_FILE="${CONFIG_FILE:-/etc/xbase/backup.env}"
# shellcheck disable=SC1090
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/xbase}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
PGUSER_DUMP="${PGUSER_DUMP:-supabase_admin}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$BACKUP_DIR/$STAMP"

fail() {
  echo "backup failed: $*" >&2
  [ -n "${HEALTHCHECK_URL:-}" ] && curl -fsS -m 10 "${HEALTHCHECK_URL}/fail" >/dev/null 2>&1 || true
  exit 1
}
trap 'fail "line $LINENO"' ERR

if [ -z "${AGE_RECIPIENT:-}" ] && [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  fail "set AGE_RECIPIENT or BACKUP_PASSPHRASE — refusing to write unencrypted backups"
fi

umask 077
mkdir -p "$WORK"

echo "==> Dumping cluster globals (roles, grants)..."
docker exec "$DB_CONTAINER" pg_dumpall -U "$PGUSER_DUMP" --globals-only --no-role-passwords \
  > "$WORK/globals.sql"

DBS="$(docker exec "$DB_CONTAINER" psql -U "$PGUSER_DUMP" -d postgres -At -c \
  "select datname from pg_database where not datistemplate and datallowconn")"

for db in $DBS; do
  echo "==> Dumping database: $db"
  docker exec "$DB_CONTAINER" pg_dump -U "$PGUSER_DUMP" -d "$db" -Fc -Z 6 > "$WORK/$db.dump"
done

ARCHIVE="$BACKUP_DIR/xbase-$STAMP.tar"
tar -C "$BACKUP_DIR" -cf "$ARCHIVE" "$STAMP"
rm -rf "$WORK"

echo "==> Encrypting..."
if [ -n "${AGE_RECIPIENT:-}" ]; then
  age -r "$AGE_RECIPIENT" -o "$ARCHIVE.age" "$ARCHIVE"
  OUT="$ARCHIVE.age"
else
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
    -pass env:BACKUP_PASSPHRASE -in "$ARCHIVE" -out "$ARCHIVE.enc"
  OUT="$ARCHIVE.enc"
fi
rm -f "$ARCHIVE"
sha256sum "$OUT" > "$OUT.sha256"

if [ -n "${RCLONE_REMOTE:-}" ]; then
  echo "==> Uploading to $RCLONE_REMOTE ..."
  rclone copy "$OUT" "$RCLONE_REMOTE/" --s3-no-check-bucket
  rclone copy "$OUT.sha256" "$RCLONE_REMOTE/" --s3-no-check-bucket
  rclone delete "$RCLONE_REMOTE/" --min-age "${RETENTION_DAYS}d" || true
fi

echo "==> Pruning local backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -maxdepth 1 -name 'xbase-*' -mtime "+${RETENTION_DAYS}" -delete

[ -n "${HEALTHCHECK_URL:-}" ] && curl -fsS -m 10 "$HEALTHCHECK_URL" >/dev/null 2>&1 || true
echo "backup complete: $OUT ($(du -h "$OUT" | cut -f1))"
