#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# xbase — Install the workspace-scoped storage.objects RLS policies.
#
# storage.objects is owned by supabase_storage_admin, so the platform user that
# runs migrations may be unable to create policies on it (migration 0005 then
# skips with a NOTICE). Run this once as the cluster superuser instead:
#
#   ./scripts/apply-storage-policies.sh
#
# Requires migration 0005 (the xbase.can_access_storage_object helper) to have
# been applied first — start any xbase backend once. Idempotent.
# =============================================================================

DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
PGUSER_ADMIN="${PGUSER_ADMIN:-supabase_admin}"
PGDATABASE="${PGDATABASE:-postgres}"
SQL_FILE="$(cd "$(dirname "$0")/.." && pwd)/docker/storage-policies.sql"

[ -f "$SQL_FILE" ] || { echo "missing $SQL_FILE" >&2; exit 1; }

docker exec "$DB_CONTAINER" psql -U "$PGUSER_ADMIN" -d "$PGDATABASE" -qAt \
  -c "select to_regprocedure('xbase.can_access_storage_object(text,text,text[])') is not null" \
  | grep -qx t || { echo "xbase.can_access_storage_object() not found — boot an xbase backend first so migration 0005 runs" >&2; exit 1; }

echo "==> Applying storage policies to $PGDATABASE ..."
docker exec -i "$DB_CONTAINER" psql -U "$PGUSER_ADMIN" -d "$PGDATABASE" -v ON_ERROR_STOP=1 -q < "$SQL_FILE"

echo "==> Installed policies:"
docker exec "$DB_CONTAINER" psql -U "$PGUSER_ADMIN" -d "$PGDATABASE" -At \
  -c "select policyname || ' (' || cmd || ')' from pg_policies where schemaname='storage' and tablename='objects' and policyname like 'xbase %' order by 1"
