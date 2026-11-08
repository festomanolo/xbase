#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Installs point-in-time recovery plumbing on the VPS:
#   * /usr/local/bin/xbase-pitr            (scripts/pitr.sh)
#   * /etc/xbase/pitr.env                  (config template, mode 600)
#   * the WAL spool directory, owned by the container's postgres user
#   * systemd timers: ship WAL every minute, base backup nightly at 02:30
#
#   sudo ./scripts/install-pitr.sh
#
# Then apply docker/supabase-pitr.override.yml and restart the db container.
# =============================================================================

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
for dep in docker rclone flock; do
  command -v "$dep" >/dev/null || { echo "missing dependency: $dep  (apt install -y rclone util-linux)" >&2; exit 1; }
done
command -v age >/dev/null || echo "note: 'age' not found — falling back to openssl + BACKUP_PASSPHRASE (apt install -y age is better)"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
WAL_DIR="${WAL_DIR:-/var/lib/xbase/wal-archive}"

install -m 0755 "$REPO_DIR/scripts/pitr.sh" /usr/local/bin/xbase-pitr
install -d -m 0700 /etc/xbase /var/lib/xbase

# The container's postgres user must be able to write here; ids differ per image.
PG_UID="$(docker exec "$DB_CONTAINER" id -u postgres 2>/dev/null || echo 105)"
PG_GID="$(docker exec "$DB_CONTAINER" id -g postgres 2>/dev/null || echo 106)"
install -d -m 0750 -o "$PG_UID" -g "$PG_GID" "$WAL_DIR"

if [ ! -f /etc/xbase/pitr.env ]; then
  cat > /etc/xbase/pitr.env <<EOF
DB_CONTAINER=$DB_CONTAINER
PGUSER_ADMIN=supabase_admin
WAL_DIR=$WAL_DIR
# \`rclone config\` → e.g. r2:my-bucket/xbase-pitr  (use a bucket with versioning/object lock if you can)
RCLONE_REMOTE=
# age-keygen -o key.txt on your laptop; paste the PUBLIC key here, keep key.txt OFFLINE.
AGE_RECIPIENT=
# only needed on the machine that runs 'restore':
AGE_IDENTITY=
# fallback when age is unavailable:
BACKUP_PASSPHRASE=
RETENTION_DAYS=7
MAX_LOCAL_WAL_MB=2048
HEALTHCHECK_URL=
EOF
  chmod 600 /etc/xbase/pitr.env
fi

cat > /etc/systemd/system/xbase-pitr-ship.service <<'EOF'
[Unit]
Description=Ship archived Postgres WAL to object storage
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xbase-pitr ship-wal
Nice=10
IOSchedulingClass=idle
EOF

cat > /etc/systemd/system/xbase-pitr-ship.timer <<'EOF'
[Unit]
Description=Ship Postgres WAL every minute

[Timer]
OnBootSec=2min
OnUnitInactiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/xbase-pitr-base.service <<'EOF'
[Unit]
Description=Nightly Postgres base backup (PITR)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xbase-pitr base-backup
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=4h
EOF

cat > /etc/systemd/system/xbase-pitr-base.timer <<'EOF'
[Unit]
Description=Nightly Postgres base backup (PITR)

[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
echo "Installed. Next:"
echo "  1. edit /etc/xbase/pitr.env  (RCLONE_REMOTE + AGE_RECIPIENT at minimum)"
echo "  2. apply the compose override, restart db ONCE:"
echo "       docker compose -f docker-compose.yml -f $REPO_DIR/docker/supabase-pitr.override.yml up -d db"
echo "  3. systemctl enable --now xbase-pitr-ship.timer xbase-pitr-base.timer"
echo "  4. first base backup now:   sudo xbase-pitr base-backup"
echo "  5. verify:                  sudo xbase-pitr status"
echo "  6. REHEARSE a restore before you need one:  sudo xbase-pitr restore latest"
