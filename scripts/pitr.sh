#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# xbase — Point-in-time recovery (PITR) for the self-hosted Supabase Postgres.
#
#   continuous WAL archiving  +  periodic encrypted base backups  =  restore to
#   any second inside the retention window (RPO ≈ archive_timeout + 1 min).
#
# How it fits together
#   1. docker/supabase-pitr.override.yml makes Postgres copy every finished WAL
#      segment (and one every 60 s at the latest) into a host directory.
#   2. `pitr.sh ship-wal` (systemd timer, every minute) encrypts each segment,
#      uploads it with rclone, and only then deletes the local copy.
#   3. `pitr.sh base-backup` (systemd timer, nightly) streams pg_basebackup →
#      encrypt → rclone, then writes a manifest so half-uploaded bases are never
#      used for a restore.
#   4. `pitr.sh restore` rebuilds a data directory from base + WAL up to a target
#      time and boots it as a THROWAWAY container on 127.0.0.1 so you can check
#      the data before deciding what to do with production. It never touches the
#      live database.
#
# Commands
#   ship-wal                         upload archived WAL, then free local disk
#   base-backup                      take + upload a base backup, then prune
#   prune                            apply RETENTION_DAYS to bases and WAL
#   status [--check]                 archiver health; --check exits 1 if unhealthy
#   restore [TARGET_TIME|latest]     rehearse / perform recovery into a scratch dir
#                                    TARGET_TIME e.g. "2026-11-08 14:30:00+00"
#
# Config: /etc/xbase/pitr.env (or env vars)
#   DB_CONTAINER=supabase-db        PGUSER_ADMIN=supabase_admin
#   WAL_DIR=/var/lib/xbase/wal-archive         (bind-mounted at /wal-archive)
#   RCLONE_REMOTE=r2:my-bucket/xbase-pitr      (rclone config)
#   AGE_RECIPIENT=age1...   AGE_IDENTITY=/path/key.txt   (restore only)
#   BACKUP_PASSPHRASE=...   (fallback to openssl when age is not installed)
#   RETENTION_DAYS=7        MAX_LOCAL_WAL_MB=2048       HEALTHCHECK_URL=...
#   RESTORE_ROOT=/var/lib/xbase/pitr-restore   RESTORE_PORT=54329
# =============================================================================

CONFIG_FILE="${CONFIG_FILE:-/etc/xbase/pitr.env}"
# shellcheck disable=SC1090
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
PGUSER_ADMIN="${PGUSER_ADMIN:-supabase_admin}"
WAL_DIR="${WAL_DIR:-/var/lib/xbase/wal-archive}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
MAX_LOCAL_WAL_MB="${MAX_LOCAL_WAL_MB:-2048}"
RESTORE_ROOT="${RESTORE_ROOT:-/var/lib/xbase/pitr-restore}"
RESTORE_PORT="${RESTORE_PORT:-54329}"
REMOTE="${RCLONE_REMOTE:-}"

log() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; ping_health fail; exit 1; }
ping_health() {
  [ -n "${HEALTHCHECK_URL:-}" ] || return 0
  curl -fsS -m 10 "${HEALTHCHECK_URL}${1:+/$1}" >/dev/null 2>&1 || true
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
need_remote() { [ -n "$REMOTE" ] || die "RCLONE_REMOTE is not set"; need rclone; }

# --- encryption (age preferred, openssl fallback) ----------------------------
if [ -n "${AGE_RECIPIENT:-}" ] || [ -n "${AGE_IDENTITY:-}" ]; then
  ENC_EXT=".age"
else
  ENC_EXT=".enc"
fi

encrypt() {
  if [ "$ENC_EXT" = ".age" ]; then
    [ -n "${AGE_RECIPIENT:-}" ] || die "AGE_RECIPIENT is required to encrypt"
    age -r "$AGE_RECIPIENT"
  else
    [ -n "${BACKUP_PASSPHRASE:-}" ] || die "set AGE_RECIPIENT or BACKUP_PASSPHRASE — refusing to upload unencrypted data"
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:BACKUP_PASSPHRASE
  fi
}

decrypt() {
  if [ "$ENC_EXT" = ".age" ]; then
    [ -n "${AGE_IDENTITY:-}" ] || die "AGE_IDENTITY (private key file) is required to decrypt"
    age -d -i "$AGE_IDENTITY"
  else
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_PASSPHRASE
  fi
}

psql_admin() {
  docker exec "$DB_CONTAINER" psql -U "$PGUSER_ADMIN" -d postgres -v ON_ERROR_STOP=1 -qAt "$@"
}

# The Supabase image's pg_hba.conf has no `replication` rules at all (`all` does not
# match the replication pseudo-database), so pg_basebackup is refused out of the
# box. Allow it for the admin role over the container-local socket only, which is
# the same trust `local all supabase_admin trust` already grants. Idempotent, and
# re-applied on every base backup because the file lives in the container's own
# filesystem and is lost when the container is recreated.
ensure_replication_access() {
  local hba
  hba="$(psql_admin -c 'show hba_file')"
  docker exec -u root "$DB_CONTAINER" sh -c \
    "grep -Eq '^local[[:space:]]+replication[[:space:]]+$PGUSER_ADMIN[[:space:]]' '$hba' || echo 'local replication $PGUSER_ADMIN trust' >> '$hba'"
  psql_admin -c 'select pg_reload_conf()' >/dev/null
}

# --- ship-wal -----------------------------------------------------------------
cmd_ship_wal() {
  need_remote
  [ -d "$WAL_DIR" ] || die "WAL_DIR $WAL_DIR does not exist (run install-pitr.sh)"
  # flock: a slow upload must not overlap the next timer tick
  exec 9>"$WAL_DIR/.ship.lock"
  flock -n 9 || { log "another ship-wal is running"; return 0; }

  local shipped=0 f name tmp
  umask 077
  tmp="$(mktemp)"
  # *.tmp are mid-copy; the archive_command renames them when complete.
  while IFS= read -r -d '' f; do
    name="$(basename "$f")"
    encrypt < "$f" > "$tmp"
    # copyto verifies size/hash; only a verified upload lets us drop the local copy
    rclone copyto "$tmp" "$REMOTE/wal/$name$ENC_EXT" --s3-no-check-bucket
    rm -f -- "$f"
    shipped=$((shipped + 1))
  done < <(find "$WAL_DIR" -maxdepth 1 -type f ! -name '*.tmp' ! -name '.*' -print0 | sort -z)

  rm -f "$tmp"
  [ "$shipped" -eq 0 ] || log "shipped $shipped WAL file(s)"
  check_local_backlog
  ping_health
}

check_local_backlog() {
  local mb
  mb="$(du -sm "$WAL_DIR" 2>/dev/null | cut -f1)"
  if [ "${mb:-0}" -gt "$MAX_LOCAL_WAL_MB" ]; then
    # A full disk makes archive_command fail, pg_wal then grows, and Postgres
    # eventually stops. Shout before that happens.
    log "WARNING: ${mb} MB of WAL waiting locally (limit ${MAX_LOCAL_WAL_MB}) — uploads are failing or too slow"
    ping_health fail
  fi
}

# --- base-backup --------------------------------------------------------------
cmd_base_backup() {
  need_remote; need docker
  local stamp started
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "base backup $stamp ..."
  ensure_replication_access

  # -X fetch bundles the WAL needed for consistency; -D - streams the tar so no
  # extra disk is needed on the VPS. rcat uploads it as it is produced.
  if ! docker exec "$DB_CONTAINER" pg_basebackup -U "$PGUSER_ADMIN" -D - -Ft -z -X fetch -c fast -l "xbase-$stamp" \
      | encrypt \
      | rclone rcat "$REMOTE/base/$stamp.tar.gz$ENC_EXT" --s3-no-check-bucket; then
    # No manifest is written, so restore would ignore this object anyway — but don't leave junk behind.
    rclone deletefile "$REMOTE/base/$stamp.tar.gz$ENC_EXT" >/dev/null 2>&1 || true
    die "base backup $stamp failed"
  fi

  # Force the in-progress WAL segment out so it archives now, not at the next timeout.
  psql_admin -c "select pg_switch_wal()" >/dev/null

  printf '{"stamp":"%s","started_at":"%s","finished_at":"%s","encryption":"%s"}\n' \
    "$stamp" "$started" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ENC_EXT#.}" \
    | rclone rcat "$REMOTE/base/$stamp.json" --s3-no-check-bucket

  log "base backup $stamp uploaded"
  cmd_prune
  ping_health
}

# --- prune --------------------------------------------------------------------
stamp_to_epoch() { date -u -d "${1:0:4}-${1:4:2}-${1:6:2} ${1:9:2}:${1:11:2}:${1:13:2}" +%s; }

cmd_prune() {
  need_remote
  local now stamps keep_from oldest_kept s age_days
  now="$(date -u +%s)"
  mapfile -t stamps < <(rclone lsf "$REMOTE/base" --include '*.json' 2>/dev/null | sed 's/\.json$//' | sort)
  [ "${#stamps[@]}" -gt 0 ] || { log "no base backups yet; nothing to prune"; return 0; }

  # Always keep the 2 newest bases, whatever their age. Candidates for deletion
  # are the older ones, oldest first; the first one still inside the retention
  # window (and everything after it) is kept.
  keep_from=$(( ${#stamps[@]} > 2 ? ${#stamps[@]} - 2 : 0 ))
  oldest_kept="${stamps[$keep_from]}"
  local i
  for (( i = 0; i < keep_from; i++ )); do
    s="${stamps[$i]}"
    age_days=$(( (now - $(stamp_to_epoch "$s")) / 86400 ))
    if [ "$age_days" -ge "$RETENTION_DAYS" ]; then
      log "pruning base $s (${age_days}d old)"
      rclone deletefile "$REMOTE/base/$s.json" || true
      rclone deletefile "$REMOTE/base/$s.tar.gz$ENC_EXT" || true
    else
      oldest_kept="$s"
      break
    fi
  done

  # WAL is only useful from the oldest base we still keep (minus a day of slack).
  local wal_hours=$(( (now - $(stamp_to_epoch "$oldest_kept")) / 3600 + 24 ))
  rclone delete "$REMOTE/wal" --min-age "${wal_hours}h" || true
}

# --- status -------------------------------------------------------------------
cmd_status() {
  local check=0 rc=0
  [ "${1:-}" = "--check" ] && check=1
  need_remote

  echo "== Postgres archiver (pg_stat_archiver) =="
  psql_admin -F ' | ' -c "select archived_count, failed_count, last_archived_wal, last_archived_time, last_failed_time from pg_stat_archiver" || rc=1
  echo "archive_mode=$(psql_admin -c 'show archive_mode') archive_timeout=$(psql_admin -c 'show archive_timeout')"
  [ "$(psql_admin -c 'show archive_mode')" = "on" ] || { echo "!! archive_mode is OFF — apply docker/supabase-pitr.override.yml"; rc=1; }

  echo "== Local WAL waiting to ship =="
  local n mb
  n="$(find "$WAL_DIR" -maxdepth 1 -type f ! -name '.*' ! -name '*.tmp' 2>/dev/null | wc -l | tr -d ' ')"
  mb="$(du -sm "$WAL_DIR" 2>/dev/null | cut -f1)"
  echo "${n} file(s), ${mb:-0} MB"
  [ "${mb:-0}" -le "$MAX_LOCAL_WAL_MB" ] || { echo "!! backlog above ${MAX_LOCAL_WAL_MB} MB"; rc=1; }

  echo "== Remote =="
  local latest
  latest="$(rclone lsf "$REMOTE/base" --include '*.json' 2>/dev/null | sed 's/\.json$//' | sort | tail -1)"
  if [ -z "$latest" ]; then
    echo "!! no base backup found — run: pitr.sh base-backup"; rc=1
  else
    local age_h=$(( ($(date -u +%s) - $(stamp_to_epoch "$latest")) / 3600 ))
    echo "latest base: $latest (${age_h}h old)"
    [ "$age_h" -le 36 ] || { echo "!! newest base backup is older than 36h"; rc=1; }
  fi
  echo "WAL objects: $(rclone lsf "$REMOTE/wal" 2>/dev/null | wc -l | tr -d ' ')"

  if [ "$check" -eq 1 ]; then
    [ "$rc" -eq 0 ] && ping_health || ping_health fail
    return "$rc"
  fi
}

# --- restore ------------------------------------------------------------------
cmd_restore() {
  need_remote; need docker; need tar
  local target="${1:-latest}" base="" s stamps=()
  mapfile -t stamps < <(rclone lsf "$REMOTE/base" --include '*.json' | sed 's/\.json$//' | sort)
  [ "${#stamps[@]}" -gt 0 ] || die "no completed base backups at $REMOTE/base"

  if [ "$target" = "latest" ]; then
    base="${stamps[-1]}"
  else
    local target_epoch
    target_epoch="$(date -u -d "$target" +%s)" || die "cannot parse target time '$target'"
    for s in "${stamps[@]}"; do
      # a base is usable when it FINISHED before the target
      [ "$(stamp_to_epoch "$s")" -le "$target_epoch" ] && base="$s"
    done
    [ -n "$base" ] || die "no base backup older than $target (oldest is ${stamps[0]})"
  fi
  log "using base backup $base (target: $target)"

  local dir="$RESTORE_ROOT/$base-$(date -u +%H%M%S)"
  mkdir -p "$dir/data" "$dir/wal" "$dir/etc"
  chmod 700 "$dir" "$dir/data"

  log "downloading + decrypting base backup ..."
  rclone cat "$REMOTE/base/$base.tar.gz$ENC_EXT" | decrypt | tar -xz -C "$dir/data"

  log "downloading + decrypting WAL ..."
  local base_epoch name
  base_epoch="$(stamp_to_epoch "$base")"
  # newer than (base - 1 day) to be safe about clock skew between objects
  rclone lsf "$REMOTE/wal" --max-age "$(( ( $(date -u +%s) - base_epoch ) / 3600 + 24 ))h" | while IFS= read -r name; do
    rclone cat "$REMOTE/wal/$name" | decrypt > "$dir/wal/${name%"$ENC_EXT"}"
  done
  log "$(find "$dir/wal" -type f | wc -l | tr -d ' ') WAL file(s) available"

  local image
  image="$(docker inspect -f '{{.Config.Image}}' "$DB_CONTAINER")"
  # Same server config as production (minus archiving, so the rehearsal never
  # ships WAL into your real archive).
  docker cp "$DB_CONTAINER:/etc/postgresql" "$dir/etc/postgresql" >/dev/null 2>&1 || true
  docker cp "$DB_CONTAINER:/etc/postgresql-custom" "$dir/etc/postgresql-custom" >/dev/null 2>&1 || true

  touch "$dir/data/recovery.signal"
  {
    echo "# --- written by xbase pitr.sh restore ---"
    echo "restore_command = 'cp /wal-restore/%f %p'"
    [ "$target" = "latest" ] || echo "recovery_target_time = '$target'"
    echo "recovery_target_action = 'promote'"
    echo "archive_mode = off"
    echo "archive_command = ''"
  } >> "$dir/data/postgresql.auto.conf"

  local pg_uid pg_gid
  pg_uid="$(docker exec "$DB_CONTAINER" id -u postgres)"
  pg_gid="$(docker exec "$DB_CONTAINER" id -g postgres)"
  chown -R "$pg_uid:$pg_gid" "$dir/data" "$dir/wal"

  local name_c="xbase-pitr-verify"
  docker rm -f "$name_c" >/dev/null 2>&1 || true
  local mounts=(-v "$dir/data:/var/lib/postgresql/data" -v "$dir/wal:/wal-restore:ro")
  [ -d "$dir/etc/postgresql" ] && mounts+=(-v "$dir/etc/postgresql:/etc/postgresql:ro")
  [ -d "$dir/etc/postgresql-custom" ] && mounts+=(-v "$dir/etc/postgresql-custom:/etc/postgresql-custom")

  log "starting throwaway recovery instance on 127.0.0.1:$RESTORE_PORT ..."
  docker run -d --name "$name_c" "${mounts[@]}" -p "127.0.0.1:$RESTORE_PORT:5432" "$image" \
    postgres -c config_file=/etc/postgresql/postgresql.conf -c log_min_messages=warning >/dev/null

  local i in_recovery=t
  for i in $(seq 1 120); do
    in_recovery="$(docker exec "$name_c" psql -U "$PGUSER_ADMIN" -d postgres -qAt -c 'select pg_is_in_recovery()' 2>/dev/null || echo wait)"
    [ "$in_recovery" = "f" ] && break
    sleep 5
  done
  [ "$in_recovery" = "f" ] || die "recovery did not finish in 10 min — inspect: docker logs $name_c"

  log "recovery complete. Replayed up to:"
  docker exec "$name_c" psql -U "$PGUSER_ADMIN" -d postgres -qAt \
    -c "select 'last commit replayed: ' || coalesce(pg_last_xact_replay_timestamp()::text, 'n/a (promoted)'), 'now: ' || now()" || true

  cat >&2 <<EOF

──────────────────────────────────────────────────────────────────────────────
Recovered database is running (read/write) in container '$name_c':
  psql "postgres://$PGUSER_ADMIN@127.0.0.1:$RESTORE_PORT/postgres"
  data dir: $dir/data

Check it (row counts, the table you lost, ...). Then, to make it production:
  1. docker compose ... stop              (stop the Supabase stack)
  2. mv the live volume aside (keep it!):   <supabase>/volumes/db/data → data.broken
  3. cp -a $dir/data <supabase>/volumes/db/data
  4. start the stack; re-run  pitr.sh base-backup  (new timeline → new base)
When done:  docker rm -f $name_c
──────────────────────────────────────────────────────────────────────────────
EOF
}

case "${1:-}" in
  ship-wal)    shift; cmd_ship_wal "$@" ;;
  base-backup) shift; cmd_base_backup "$@" ;;
  prune)       shift; cmd_prune "$@" ;;
  status)      shift; cmd_status "$@" ;;
  restore)     shift; cmd_restore "$@" ;;
  *) sed -n '3,40p' "$0" >&2; exit 2 ;;
esac
