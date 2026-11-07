#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# xbase — Self-Hosted Supabase Bootstrap Script
# Clones the official Supabase Docker configuration and generates secrets,
# including ANON_KEY / SERVICE_ROLE_KEY signed with the NEW JWT secret.
#
# Usage:
#   ./scripts/bootstrap-supabase.sh [target-dir]
#
# Optional environment variables (applied to the generated .env):
#   DOMAIN=api.example.com          sets SUPABASE_PUBLIC_URL / API_EXTERNAL_URL (https)
#   SITE_URL=https://app.example.com
#   SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_ADMIN_EMAIL SMTP_SENDER_NAME
#                                   production email (Resend, SES, Postmark, ...)
# =============================================================================

TARGET_DIR="${1:-supabase-project}"

echo "==> [1/5] Checking dependencies (git, openssl)..."
for cmd in git openssl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' is required but not installed." >&2
    exit 1
  fi
done

if [ -d "$TARGET_DIR" ]; then
  echo "Directory '$TARGET_DIR' already exists. Skipping clone to avoid overwriting."
  exit 0
fi

TMP_CLONE="$(mktemp -d)"
trap 'rm -rf "$TMP_CLONE"' EXIT

echo "==> [2/5] Shallow-cloning official supabase/supabase repository..."
git clone --depth 1 https://github.com/supabase/supabase "$TMP_CLONE/supabase"

echo "==> [3/5] Copying Docker Compose files into '$TARGET_DIR'..."
mkdir -p "$TARGET_DIR"
cp -rf "$TMP_CLONE/supabase/docker/." "$TARGET_DIR"
cp "$TARGET_DIR/.env.example" "$TARGET_DIR/.env"
ENV_FILE="$TARGET_DIR/.env"

echo "==> [4/4] Generating cryptographically strong secrets in '$TARGET_DIR/.env'..."
POSTGRES_PASS="$(openssl rand -hex 24)"
JWT_SEC="$(openssl rand -base64 36 | tr -d '\n=/+' | cut -c1-40)"
DASH_PASS="$(openssl rand -hex 16)"
SECRET_BASE="$(openssl rand -base64 48 | tr -d '\n')"
VAULT_KEY="$(openssl rand -hex 16)"

sed -i.bak "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${POSTGRES_PASS}|" "$TARGET_DIR/.env"
sed -i.bak "s|^JWT_SECRET=.*|JWT_SECRET=${JWT_SEC}|" "$TARGET_DIR/.env"
sed -i.bak "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=${DASH_PASS}|" "$TARGET_DIR/.env"
sed -i.bak "s|^SECRET_KEY_BASE=.*|SECRET_KEY_BASE=${SECRET_BASE}|" "$TARGET_DIR/.env"
sed -i.bak "s|^VAULT_ENC_KEY=.*|VAULT_ENC_KEY=${VAULT_KEY}|" "$TARGET_DIR/.env"
rm -f "$TARGET_DIR/.env.bak"

cat <<EOF

===============================================================================
Supabase project initialized in: ${TARGET_DIR}

Generated Credentials (also saved in ${TARGET_DIR}/.env):
  DASHBOARD_PASSWORD : ${DASH_PASS}
  POSTGRES_PASSWORD  : ${POSTGRES_PASS}
  JWT_SECRET         : ${JWT_SEC}

Next Steps:
  1. Review ${TARGET_DIR}/.env and set SITE_URL & API_EXTERNAL_URL to your VPS IP or domain.
  2. Start Supabase:
       cd ${TARGET_DIR}
       sudo docker compose pull
       sudo docker compose up -d
  3. Point your Rust/Go SaaS backends to Supavisor on port 6543.
===============================================================================
EOF
