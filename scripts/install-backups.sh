#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Installs a systemd timer that runs backup-postgres.sh every night at 03:15
# (with jitter) and keeps a config template at /etc/xbase/backup.env.
#   sudo ./scripts/install-backups.sh
# =============================================================================

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
install -m 0755 "$REPO_DIR/scripts/backup-postgres.sh" /usr/local/bin/xbase-backup
install -d -m 0700 /etc/xbase /var/backups/xbase

if [ ! -f /etc/xbase/backup.env ]; then
  cat > /etc/xbase/backup.env <<'EOF'
DB_CONTAINER=supabase-db
BACKUP_DIR=/var/backups/xbase
RETENTION_DAYS=14
# Preferred: `age-keygen -o key.txt` on your laptop, paste the public key here.
AGE_RECIPIENT=
# Fallback if age is not installed:
BACKUP_PASSPHRASE=
# `rclone config` → e.g. r2:my-bucket/xbase or b2:my-bucket/xbase
RCLONE_REMOTE=
HEALTHCHECK_URL=
EOF
  chmod 600 /etc/xbase/backup.env
fi

cat > /etc/systemd/system/xbase-backup.service <<'EOF'
[Unit]
Description=xbase encrypted PostgreSQL backup
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
EnvironmentFile=/etc/xbase/backup.env
ExecStart=/usr/local/bin/xbase-backup
Nice=10
IOSchedulingClass=idle
EOF

cat > /etc/systemd/system/xbase-backup.timer <<'EOF'
[Unit]
Description=Nightly xbase PostgreSQL backup

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now xbase-backup.timer
echo "Installed. Edit /etc/xbase/backup.env, then test with: sudo systemctl start xbase-backup && journalctl -u xbase-backup -n 50"
echo "Install tools if missing: sudo apt install -y age rclone"
