//! Supabase-style RLS impersonation.
//!
//! Every query issued inside [`begin_rls`] / [`with_rls_claims`] runs as the
//! `authenticated` (or `anon` / `service_role`) Postgres role with
//! `request.jwt.claims` set, so `auth.uid()`, `auth.jwt()` and every RLS policy
//! are enforced natively by PostgreSQL — exactly like PostgREST does.
//!
//! `set_config(..., true)` is transaction-local, which makes it safe through
//! Supavisor in transaction mode: settings never leak to another backend.

use futures_util::future::BoxFuture;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

use crate::{auth::SupabaseClaims, error::ApiError};

const ALLOWED_ROLES: [&str; 3] = ["authenticated", "anon", "service_role"];

/// Opens a transaction that impersonates the JWT's role and claims.
/// The caller must `commit()` it; dropping it rolls back.
pub async fn begin_rls(
    pool: &PgPool,
    claims: &SupabaseClaims,
) -> Result<Transaction<'static, Postgres>, ApiError> {
    let role = ALLOWED_ROLES
        .iter()
        .find(|r| **r == claims.role)
        .ok_or_else(|| ApiError::forbidden("JWT role is not allowed to access the database"))?;

    let claims_json =
        serde_json::to_string(claims).map_err(|e| ApiError::internal(e.to_string()))?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        "select set_config('request.jwt.claims', $1, true), \
                set_config('request.jwt.claim.sub', $2, true), \
                set_config('request.jwt.claim.role', $3, true), \
                set_config('role', $3, true)",
    )
    .bind(claims_json)
    .bind(claims.sub.to_string())
    .bind(*role)
    .execute(&mut *tx)
    .await?;

    Ok(tx)
}

/// Runs `f` inside an RLS-impersonated transaction, committing on success.
///
/// ```ignore
/// let rows = with_rls_claims(&pool, &claims, |conn| Box::pin(async move {
///     Ok(sqlx::query_as::<_, Workspace>("select * from xbase.workspaces")
///         .fetch_all(&mut *conn).await?)
/// })).await?;
/// ```
pub async fn with_rls_claims<T, F>(pool: &PgPool, claims: &SupabaseClaims, f: F) -> Result<T, ApiError>
where
    T: Send,
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, ApiError>> + Send,
{
    let mut tx = begin_rls(pool, claims).await?;
    let out = f(&mut tx).await?;
    tx.commit().await?;
    Ok(out)
}
