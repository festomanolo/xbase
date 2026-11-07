#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# xbase — Lightweight database branching for preview environments.
#
# Self-hosted Supabase has no branching, so this clones the main database into
# an ephemeral `branch_<name>` database on the same cluster (schema only by
# default, or with data). Point a preview backend's DATABASE_URL at
# .../branch_<name>; RUN_MIGRATIONS=true then applies the PR's new migrations.
#
#   ./scripts/db-branch.sh create pr-42 [--with-data]
#   ./scripts/db-branch.sh list
#   ./scripts/db-branch.sh url pr-42
#   ./scripts/db-branch.sh delete pr-42
#
# CI (GitHub Actions over SSH): create on pull_request opened/synchronize,
# delete on closed.
# =============================================================================

DB_CONTAINER="${DB_CONTAINER:-supabase-db}"
SOURCE_DB="${SOURCE_DB:-postgres}"
PGUSER_ADMIN="${PGUSER_ADMIN:-supabase_admin}"

cmd="${1:-}"
name="${2:-}"

psql_admin() { docker exec -i "$DB_CONTAINER" psql -U "$PGUSER_ADMIN" -v ON_ERROR_STOP=1 -At "$@"; }

branch_db() {
  local n
  n="$(printf '%s' "$1" | tr '[:upper:]-' '[:lower:]_' | tr -cd 'a-z0-9_')"
  [ -n "$n" ] || { echo "invalid branch name" >&2; exit 1; }
  printf 'branch_%s' "$n"
}

case "$cmd" in
  create)
    [ -n "$name" ] || { echo "usage: db-branch.sh create <name> [--with-data]" >&2; exit 1; }
    db="$(branch_db "$name")"
    if psql_admin -d postgres -c "select 1 from pg_database where datname = '$db'" | grep -q 1; then
      echo "branch $db already exists"; exit 0
    fi
    dump_flags=(--no-owner --no-privileges)
    [ "${3:-}" = "--with-data" ] || dump_flags+=(--schema-only)
    echo "==> Creating $db from $SOURCE_DB (${3:-schema only})..."
    psql_admin -d postgres -c "create database \"$db\" owner postgres"
    docker exec "$DB_CONTAINER" sh -c \
      "pg_dump -U $PGUSER_ADMIN -d $SOURCE_DB ${dump_flags[*]} | psql -U $PGUSER_ADMIN -d $db -q -v ON_ERROR_STOP=0 >/dev/null"
    echo "created: $db"
    ;;
  delete)
    [ -n "$name" ] || { echo "usage: db-branch.sh delete <name>" >&2; exit 1; }
    db="$(branch_db "$name")"
    psql_admin -d postgres -c "drop database if exists \"$db\" with (force)"
    echo "deleted: $db"
    ;;
  list)
    psql_admin -d postgres -c "select datname from pg_database where datname like 'branch\_%' order by 1"
    ;;
  url)
    [ -n "$name" ] || { echo "usage: db-branch.sh url <name>" >&2; exit 1; }
    echo "postgres://postgres:\${POSTGRES_PASSWORD}@db:5432/$(branch_db "$name")"
    ;;
  *)
    sed -n '4,20p' "$0"
    exit 1
    ;;
esac
