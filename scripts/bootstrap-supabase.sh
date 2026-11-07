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

# Portable in-place "KEY=value" replacement (GNU + BSD sed). Values are
# escaped for sed so secrets containing / & | are safe.
set_env() {
  local key="$1" value="$2" escaped
  escaped="$(printf '%s' "$value" | sed -e 's/[\/&|]/\\&/g')"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i.bak "s|^${key}=.*|${key}=${escaped}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
  rm -f "$ENV_FILE.bak"
}

get_env() { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-; }

b64url() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }

sign_jwt() {
  local payload="$1" secret="$2" header body sig
  header="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)"
  body="$(printf '%s' "$payload" | b64url)"
  sig="$(printf '%s' "$header.$body" | openssl dgst -binary -sha256 -hmac "$secret" | b64url)"
  printf '%s.%s.%s' "$header" "$body" "$sig"
}

echo "==> [4/5] Generating cryptographically strong secrets..."
if [ -f "$TARGET_DIR/utils/generate-keys.sh" ]; then
  # Upstream generator: JWT secret, matching ANON/SERVICE_ROLE keys, and every
  # other service secret (vault, realtime, pg-meta, logflare, s3, minio).
  (cd "$TARGET_DIR" && sh utils/generate-keys.sh --update-env >/dev/null)
  rm -f "$ENV_FILE.old"
else
  JWT_SEC="$(openssl rand -base64 36 | tr -d '\n=/+' | cut -c1-40)"
  IAT="$(date +%s)"
  EXP=$((IAT + 5 * 365 * 24 * 3600))
  set_env JWT_SECRET "$JWT_SEC"
  set_env ANON_KEY "$(sign_jwt "{\"role\":\"anon\",\"iss\":\"supabase\",\"iat\":$IAT,\"exp\":$EXP}" "$JWT_SEC")"
  set_env SERVICE_ROLE_KEY "$(sign_jwt "{\"role\":\"service_role\",\"iss\":\"supabase\",\"iat\":$IAT,\"exp\":$EXP}" "$JWT_SEC")"
  set_env POSTGRES_PASSWORD "$(openssl rand -hex 24)"
  set_env DASHBOARD_PASSWORD "$(openssl rand -hex 16)"
  set_env SECRET_KEY_BASE "$(openssl rand -base64 48 | tr -d '\n')"
  set_env VAULT_ENC_KEY "$(openssl rand -hex 16)"
fi

# Unique Supavisor tenant id (used in postgres.<tenant>@supavisor:6543 URLs).
set_env POOLER_TENANT_ID "xbase-$(openssl rand -hex 4)"

echo "==> [5/5] Applying optional domain / SMTP settings..."
if [ -n "${DOMAIN:-}" ]; then
  set_env SUPABASE_PUBLIC_URL "https://${DOMAIN}"
  set_env API_EXTERNAL_URL "https://${DOMAIN}"
fi
[ -n "${SITE_URL:-}" ] && set_env SITE_URL "$SITE_URL"
for var in SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_ADMIN_EMAIL SMTP_SENDER_NAME; do
  if [ -n "${!var:-}" ]; then
    set_env "$var" "${!var}"
  fi
done
if [ -n "${SMTP_HOST:-}" ]; then
  # Real SMTP configured: require email confirmation.
  set_env ENABLE_EMAIL_AUTOCONFIRM "false"
fi
chmod 600 "$ENV_FILE"

cat <<EOF

===============================================================================
Supabase project initialized in: ${TARGET_DIR}

Generated credentials (stored in ${ENV_FILE}, mode 600):
  DASHBOARD_PASSWORD : $(get_env DASHBOARD_PASSWORD)
  POSTGRES_PASSWORD  : $(get_env POSTGRES_PASSWORD)
  POOLER_TENANT_ID   : $(get_env POOLER_TENANT_ID)
  JWT_SECRET, ANON_KEY and SERVICE_ROLE_KEY were regenerated together.

Next Steps:
  1. Review ${ENV_FILE}: SITE_URL, API_EXTERNAL_URL, SUPABASE_PUBLIC_URL and SMTP_*
     (without SMTP, GoTrue cannot send confirmation / magic-link / reset emails).
  2. Optional OAuth providers: see docker/supabase-auth.override.yml.
  3. Start Supabase:
       cd ${TARGET_DIR}
       sudo docker compose pull
       sudo docker compose up -d
  3. Point your Rust/Go SaaS backends to Supavisor on port 6543.
===============================================================================
EOF
