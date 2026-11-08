//! PostgREST-style generic CRUD: `/api/v1/rest/:table`.
//!
//! Enabled with `REST_ENABLED=true`; the schemas it may expose come from
//! `REST_SCHEMAS` (default `public`). Every request runs inside [`begin_rls`], so
//! the *database* decides what a user may see or change — grants + RLS policies,
//! exactly as with PostgREST. `xbase`, `auth`, `storage` and other Supabase
//! internals can never be exposed, whatever `REST_SCHEMAS` says: `xbase` tables
//! have dedicated endpoints that enforce the `app_slug` predicate.
//!
//! Supported (PostgREST dialect):
//!
//! ```text
//! GET    /api/v1/rest/todos?select=id,title&done=eq.false&order=created_at.desc&limit=20&offset=40
//! GET    ...?id=in.(1,2,3)   ?title=ilike.*milk*   ?deleted_at=is.null   ?done=not.eq.true
//! POST   /api/v1/rest/todos            {"title":"x"}  or  [{"title":"a"},{"title":"b"}]
//!        Prefer: resolution=merge-duplicates  +  ?on_conflict=id      (upsert)
//! PATCH  /api/v1/rest/todos?id=eq.7    {"done":true}      (a filter is mandatory)
//! DELETE /api/v1/rest/todos?id=eq.7                       (a filter is mandatory)
//! ```
//!
//! Headers: `Accept-Profile` / `Content-Profile` pick the schema, and
//! `Prefer: count=exact` adds a `Content-Range` total to GETs.
//!
//! Not supported: resource embedding (joins), `or=`/`and=` groups, RPC. Use a SQL
//! view for joins, or a dedicated endpoint. API keys are not accepted (they
//! bypass RLS); use a user JWT.
//!
//! Injection safety: table and column names are only ever taken from the catalog
//! (`pg_attribute`) and quoted; every value is a bound parameter cast with the
//! column's own type (`($n::text)::<type>`), never interpolated.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::Value;
use sqlx::PgPool;

use crate::{
    auth::SupabaseClaims,
    error::{ApiError, ApiResult},
    rls::begin_rls,
    state::AppState,
};

/// Never exposable, regardless of `REST_SCHEMAS`.
const DENIED_SCHEMAS: &[&str] = &[
    "xbase", "auth", "storage", "extensions", "vault", "graphql", "graphql_public", "realtime",
    "pgsodium", "pgsodium_masks", "supabase_functions", "supabase_migrations", "net", "cron",
    "pgbouncer", "information_schema", "public_internal",
];
const SCHEMA_TTL: Duration = Duration::from_secs(60);
const MAX_BODY_ROWS: usize = 1000;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/v1/rest/:table",
        get(select_rows).post(insert_rows).patch(update_rows).delete(delete_rows),
    )
}

// --- schema introspection --------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Column {
    pub name: String,
    /// `format_type()` output — valid SQL, taken from the catalog.
    pub ty: String,
}

/// Short-lived cache of table definitions (columns + types).
#[derive(Default)]
pub struct SchemaCache {
    inner: Mutex<HashMap<(String, String), (Instant, Arc<Vec<Column>>)>>,
}

impl SchemaCache {
    async fn columns(&self, pool: &PgPool, schema: &str, table: &str) -> ApiResult<Arc<Vec<Column>>> {
        let key = (schema.to_string(), table.to_string());
        if let Some((at, cols)) = self.inner.lock().unwrap().get(&key) {
            if at.elapsed() < SCHEMA_TTL {
                return Ok(cols.clone());
            }
        }
        let rows: Vec<(String, String)> = sqlx::query_as(
            "select a.attname::text, format_type(a.atttypid, a.atttypmod) \
               from pg_attribute a \
               join pg_class c on c.oid = a.attrelid \
               join pg_namespace n on n.oid = c.relnamespace \
              where n.nspname = $1 and c.relname = $2 \
                and c.relkind in ('r', 'p', 'v', 'm', 'f') \
                and a.attnum > 0 and not a.attisdropped \
              order by a.attnum",
        )
        .bind(schema)
        .bind(table)
        .fetch_all(pool)
        .await?;
        let cols = Arc::new(rows.into_iter().map(|(name, ty)| Column { name, ty }).collect::<Vec<_>>());
        if !cols.is_empty() {
            // Unknown tables are not cached, so random names cannot grow the map.
            let mut map = self.inner.lock().unwrap();
            if map.len() > 512 {
                map.clear();
            }
            map.insert(key, (Instant::now(), cols.clone()));
        }
        Ok(cols)
    }
}

// --- query model -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Text(String),
    TextArray(Vec<String>),
    Json(Value),
}

#[derive(Debug, Default)]
pub struct Params {
    select: Option<String>,
    order: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    on_conflict: Option<String>,
    filters: Vec<(String, String)>,
}

fn q(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn parse_params(raw: Option<&str>) -> ApiResult<Params> {
    let mut p = Params::default();
    let Some(raw) = raw.filter(|r| !r.is_empty()) else { return Ok(p) };
    let url = reqwest::Url::parse(&format!("http://localhost/?{raw}"))
        .map_err(|_| ApiError::bad_request("Malformed query string"))?;
    for (k, v) in url.query_pairs() {
        let (k, v) = (k.into_owned(), v.into_owned());
        match k.as_str() {
            "select" => p.select = Some(v),
            "order" => p.order = Some(v),
            "limit" => p.limit = Some(v.parse().map_err(|_| ApiError::bad_request("limit must be an integer"))?),
            "offset" => p.offset = Some(v.parse().map_err(|_| ApiError::bad_request("offset must be an integer"))?),
            "on_conflict" => p.on_conflict = Some(v),
            "or" | "and" | "not" => {
                return Err(ApiError::bad_request(format!("'{k}' groups are not supported; filter by column")))
            }
            _ => p.filters.push((k, v)),
        }
    }
    Ok(p)
}

fn find<'a>(cols: &'a [Column], name: &str) -> ApiResult<&'a Column> {
    cols.iter()
        .find(|c| c.name == name)
        .ok_or_else(|| ApiError::bad_request(format!("Unknown column '{name}'")))
}

/// Splits `(a,b,"c d")` into items.
fn parse_in_list(v: &str) -> ApiResult<Vec<String>> {
    let inner = v
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| ApiError::bad_request("in.(...) requires a parenthesised list"))?;
    let (mut items, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for ch in inner.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => items.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    items.push(cur);
    if items.len() > 1000 {
        return Err(ApiError::bad_request("in.(...) accepts at most 1000 items"));
    }
    Ok(items)
}

/// Compiles `col=op.value` filters into `AND`-joined predicates over `alias`.
/// Parameter numbering starts at `first_param`.
fn build_filters(
    cols: &[Column],
    filters: &[(String, String)],
    alias: &str,
    first_param: usize,
) -> ApiResult<(Vec<String>, Vec<Bind>)> {
    let (mut clauses, mut binds) = (Vec::new(), Vec::new());
    for (name, spec) in filters {
        let col = find(cols, name)?;
        let lhs = format!("{}.{}", q(alias), q(&col.name));
        let (negate, spec) = match spec.strip_prefix("not.") {
            Some(rest) => (true, rest),
            None => (false, spec.as_str()),
        };
        let (op, value) = spec
            .split_once('.')
            .ok_or_else(|| ApiError::bad_request(format!("Filter on '{name}' must look like op.value")))?;
        let n = first_param + binds.len();

        let clause = match op {
            "is" => {
                let lit = match value.to_ascii_lowercase().as_str() {
                    "null" => "null",
                    "true" => "true",
                    "false" => "false",
                    "unknown" => "unknown",
                    _ => return Err(ApiError::bad_request("is.<null|true|false|unknown>")),
                };
                let not = if negate { "not " } else { "" };
                format!("({lhs} is {not}{lit})")
            }
            "in" => {
                if col.ty.ends_with(']') {
                    return Err(ApiError::bad_request(format!("in.(...) is not supported on array column '{name}'")));
                }
                binds.push(Bind::TextArray(parse_in_list(value)?));
                let c = format!("{lhs} = any((${n}::text[])::{}[])", col.ty);
                if negate { format!("(not ({c}))") } else { format!("({c})") }
            }
            "like" | "ilike" => {
                binds.push(Bind::Text(value.replace('*', "%")));
                let c = format!("{lhs}::text {op} ${n}");
                if negate { format!("(not ({c}))") } else { format!("({c})") }
            }
            "eq" | "neq" | "gt" | "gte" | "lt" | "lte" => {
                let sym = match op {
                    "eq" => "=",
                    "neq" => "<>",
                    "gt" => ">",
                    "gte" => ">=",
                    "lt" => "<",
                    _ => "<=",
                };
                binds.push(Bind::Text(value.to_string()));
                let c = format!("{lhs} {sym} (${n}::text)::{}", col.ty);
                if negate { format!("(not ({c}))") } else { format!("({c})") }
            }
            other => return Err(ApiError::bad_request(format!("Unsupported operator '{other}'"))),
        };
        clauses.push(clause);
    }
    Ok((clauses, binds))
}

fn where_sql(clauses: &[String]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!(" where {}", clauses.join(" and "))
    }
}

pub struct Built {
    pub sql: String,
    pub count_sql: Option<String>,
    pub binds: Vec<Bind>,
}

const AGG: &str = "coalesce(jsonb_agg(to_jsonb(r)), '[]'::jsonb)";

pub fn build_select(schema: &str, table: &str, cols: &[Column], p: &Params, max_rows: i64) -> ApiResult<Built> {
    let sel = match p.select.as_deref() {
        None | Some("*") | Some("") => cols.iter().map(|c| q(&c.name)).collect::<Vec<_>>().join(", "),
        Some(list) => list
            .split(',')
            .map(|c| {
                let c = c.trim();
                if c.contains(['(', ')', ':']) {
                    return Err(ApiError::bad_request("select supports plain column names only (no embedding or casts)"));
                }
                find(cols, c).map(|c| q(&c.name))
            })
            .collect::<ApiResult<Vec<_>>>()?
            .join(", "),
    };

    let (clauses, binds) = build_filters(cols, &p.filters, "t", 1)?;
    let filter = where_sql(&clauses);

    let mut order = String::new();
    if let Some(spec) = p.order.as_deref().filter(|s| !s.is_empty()) {
        let parts = spec
            .split(',')
            .map(|item| {
                let mut it = item.trim().split('.');
                let col = find(cols, it.next().unwrap_or_default())?;
                let mut out = q(&col.name);
                for m in it {
                    match m {
                        "asc" => out.push_str(" asc"),
                        "desc" => out.push_str(" desc"),
                        "nullsfirst" => out.push_str(" nulls first"),
                        "nullslast" => out.push_str(" nulls last"),
                        _ => return Err(ApiError::bad_request(format!("Unknown order modifier '{m}'"))),
                    }
                }
                Ok(out)
            })
            .collect::<ApiResult<Vec<_>>>()?;
        order = format!(" order by {}", parts.join(", "));
    }

    let limit = p.limit.unwrap_or(max_rows).clamp(0, max_rows);
    let offset = p.offset.unwrap_or(0).max(0);
    let from = format!("{}.{}", q(schema), q(table));
    Ok(Built {
        sql: format!(
            "select {AGG} from (select {sel} from {from} as t{filter}{order} limit {limit} offset {offset}) r"
        ),
        count_sql: Some(format!("select count(*) from {from} as t{filter}")),
        binds,
    })
}

fn body_rows(body: &Value) -> ApiResult<Vec<&serde_json::Map<String, Value>>> {
    let rows: Vec<&serde_json::Map<String, Value>> = match body {
        Value::Object(o) => vec![o],
        Value::Array(a) => a
            .iter()
            .map(|v| v.as_object().ok_or_else(|| ApiError::bad_request("Array items must be JSON objects")))
            .collect::<ApiResult<_>>()?,
        _ => return Err(ApiError::bad_request("Body must be a JSON object or array of objects")),
    };
    if rows.is_empty() || rows.len() > MAX_BODY_ROWS {
        return Err(ApiError::bad_request(format!("Body must contain 1-{MAX_BODY_ROWS} rows")));
    }
    Ok(rows)
}

/// Columns named by the body, in table order (validated against the catalog).
fn body_columns<'a>(cols: &'a [Column], rows: &[&serde_json::Map<String, Value>]) -> ApiResult<Vec<&'a Column>> {
    for row in rows {
        for key in row.keys() {
            find(cols, key)?;
        }
    }
    let used: Vec<&Column> = cols
        .iter()
        .filter(|c| rows.iter().any(|r| r.contains_key(&c.name)))
        .collect();
    if used.is_empty() {
        return Err(ApiError::bad_request("Body has no columns"));
    }
    Ok(used)
}

pub fn build_insert(
    schema: &str,
    table: &str,
    cols: &[Column],
    body: &Value,
    on_conflict: Option<&str>,
    merge: bool,
) -> ApiResult<Built> {
    let rows = body_rows(body)?;
    let used = body_columns(cols, &rows)?;
    let names = used.iter().map(|c| q(&c.name)).collect::<Vec<_>>().join(", ");
    let target = format!("{}.{}", q(schema), q(table));

    let conflict = match on_conflict.filter(|c| !c.is_empty()) {
        None => String::new(),
        Some(list) => {
            let keys = list
                .split(',')
                .map(|c| find(cols, c.trim()).map(|c| c.name.clone()))
                .collect::<ApiResult<Vec<_>>>()?;
            let key_sql = keys.iter().map(|k| q(k)).collect::<Vec<_>>().join(", ");
            let updates: Vec<String> = used
                .iter()
                .filter(|c| !keys.contains(&c.name))
                .map(|c| format!("{0} = excluded.{0}", q(&c.name)))
                .collect();
            if merge && !updates.is_empty() {
                format!(" on conflict ({key_sql}) do update set {}", updates.join(", "))
            } else {
                format!(" on conflict ({key_sql}) do nothing")
            }
        }
    };

    Ok(Built {
        sql: format!(
            "with r as (insert into {target} ({names}) \
             select {names} from jsonb_populate_recordset(null::{target}, $1::jsonb){conflict} returning *) \
             select {AGG} from r"
        ),
        count_sql: None,
        binds: vec![Bind::Json(Value::Array(rows.into_iter().map(|r| Value::Object(r.clone())).collect()))],
    })
}

pub fn build_update(schema: &str, table: &str, cols: &[Column], body: &Value, p: &Params) -> ApiResult<Built> {
    if p.filters.is_empty() {
        return Err(ApiError::bad_request("PATCH requires at least one filter (e.g. ?id=eq.1)"));
    }
    let Value::Object(obj) = body else {
        return Err(ApiError::bad_request("Body must be a JSON object"));
    };
    let used = body_columns(cols, &[obj])?;
    let sets = used
        .iter()
        .map(|c| format!("{} = s.{}", q(&c.name), q(&c.name)))
        .collect::<Vec<_>>()
        .join(", ");
    let (clauses, mut binds) = build_filters(cols, &p.filters, "t", 2)?;
    binds.insert(0, Bind::Json(body.clone()));
    let target = format!("{}.{}", q(schema), q(table));
    Ok(Built {
        sql: format!(
            "with r as (update {target} as t set {sets} from jsonb_populate_record(null::{target}, $1::jsonb) as s{} \
             returning t.*) select {AGG} from r",
            where_sql(&clauses)
        ),
        count_sql: None,
        binds,
    })
}

pub fn build_delete(schema: &str, table: &str, cols: &[Column], p: &Params) -> ApiResult<Built> {
    if p.filters.is_empty() {
        return Err(ApiError::bad_request("DELETE requires at least one filter (e.g. ?id=eq.1)"));
    }
    let (clauses, binds) = build_filters(cols, &p.filters, "t", 1)?;
    let target = format!("{}.{}", q(schema), q(table));
    Ok(Built {
        sql: format!(
            "with r as (delete from {target} as t{} returning t.*) select {AGG} from r",
            where_sql(&clauses)
        ),
        count_sql: None,
        binds,
    })
}

// --- execution -------------------------------------------------------------

async fn resolve(
    state: &AppState,
    headers: &HeaderMap,
    profile_header: &str,
    table: &str,
) -> ApiResult<(String, Arc<Vec<Column>>)> {
    if !state.config.rest_enabled {
        return Err(ApiError::not_found("The REST API is disabled (set REST_ENABLED=true)"));
    }
    let schema = headers
        .get(profile_header)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| state.config.rest_schemas.first().cloned())
        .ok_or_else(|| ApiError::internal("no REST schema configured"))?;
    if !state.config.rest_schemas.contains(&schema)
        || DENIED_SCHEMAS.contains(&schema.as_str())
        || schema.starts_with("pg_")
    {
        return Err(ApiError::forbidden(format!("Schema '{schema}' is not exposed")));
    }
    let valid = !table.is_empty()
        && table.len() <= 63
        && table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(ApiError::bad_request("Invalid table name"));
    }
    let cols = state.rest_cache.columns(&state.pool, &schema, table).await?;
    if cols.is_empty() {
        return Err(ApiError::not_found(format!("Table '{schema}.{table}' not found")));
    }
    Ok((schema, cols))
}

fn bind_all<'q>(
    mut query: sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments>,
    binds: &'q [Bind],
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, Value, sqlx::postgres::PgArguments> {
    for b in binds {
        query = match b {
            Bind::Text(s) => query.bind(s.as_str()),
            Bind::TextArray(v) => query.bind(v.as_slice()),
            Bind::Json(j) => query.bind(j),
        };
    }
    query
}

async fn run(state: &AppState, claims: &SupabaseClaims, built: &Built, want_count: bool) -> ApiResult<(Value, Option<i64>)> {
    let mut tx = begin_rls(&state.pool, claims).await?;
    let data: Value = bind_all(sqlx::query_scalar(&built.sql), &built.binds).fetch_one(&mut *tx).await?;
    let mut total = None;
    if let (true, Some(sql)) = (want_count, &built.count_sql) {
        let mut query = sqlx::query_scalar::<_, i64>(sql);
        for b in &built.binds {
            query = match b {
                Bind::Text(s) => query.bind(s.as_str()),
                Bind::TextArray(v) => query.bind(v.as_slice()),
                Bind::Json(_) => query,
            };
        }
        total = Some(query.fetch_one(&mut *tx).await?);
    }
    tx.commit().await?;
    Ok((data, total))
}

fn prefers(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all("prefer")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

async fn select_rows(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (schema, cols) = resolve(&state, &headers, "accept-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let built = build_select(&schema, &table, &cols, &params, state.config.rest_max_rows)?;
    let want_count = prefers(&headers, "count=exact");
    let (data, total) = run(&state, &claims, &built, want_count).await?;

    let returned = data.as_array().map_or(0, Vec::len) as i64;
    let start = params.offset.unwrap_or(0).max(0);
    let mut resp = Json(data).into_response();
    if let Some(total) = total {
        let range = if returned == 0 { "*".to_string() } else { format!("{start}-{}", start + returned - 1) };
        if let Ok(v) = header::HeaderValue::from_str(&format!("{range}/{total}")) {
            resp.headers_mut().insert(header::CONTENT_RANGE, v);
        }
    }
    Ok(resp)
}

async fn insert_rows(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let (schema, cols) = resolve(&state, &headers, "content-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let merge = prefers(&headers, "resolution=merge-duplicates");
    let ignore = prefers(&headers, "resolution=ignore-duplicates");
    if (merge || ignore) && params.on_conflict.is_none() {
        return Err(ApiError::bad_request("Upserts require ?on_conflict=<column[,column]>"));
    }
    let on_conflict = if merge || ignore { params.on_conflict.as_deref() } else { None };
    let built = build_insert(&schema, &table, &cols, &body, on_conflict, merge)?;
    let (data, _) = run(&state, &claims, &built, false).await?;
    Ok((StatusCode::CREATED, Json(data)))
}

async fn update_rows(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let (schema, cols) = resolve(&state, &headers, "content-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let built = build_update(&schema, &table, &cols, &body, &params)?;
    Ok(Json(run(&state, &claims, &built, false).await?.0))
}

async fn delete_rows(
    State(state): State<AppState>,
    claims: SupabaseClaims,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (schema, cols) = resolve(&state, &headers, "content-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let built = build_delete(&schema, &table, &cols, &params)?;
    Ok(Json(run(&state, &claims, &built, false).await?.0))
}

fn _shape() -> serde_json::Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cols() -> Vec<Column> {
        [("id", "bigint"), ("title", "text"), ("done", "boolean"), ("tags", "text[]"), ("meta", "jsonb")]
            .into_iter()
            .map(|(n, t)| Column { name: n.into(), ty: t.into() })
            .collect()
    }

    fn params(q: &str) -> Params {
        parse_params(Some(q)).unwrap()
    }

    #[test]
    fn select_with_filters_order_and_paging() {
        let b = build_select(
            "public",
            "todos",
            &cols(),
            &params("select=id,title&done=eq.false&title=ilike.*milk*&order=id.desc.nullslast&limit=20&offset=40"),
            1000,
        )
        .unwrap();
        assert!(b.sql.contains(r#"select "id", "title" from "public"."todos" as t"#), "{}", b.sql);
        assert!(b.sql.contains(r#"("t"."done" = ($1::text)::boolean)"#), "{}", b.sql);
        assert!(b.sql.contains(r#"("t"."title"::text ilike $2)"#), "{}", b.sql);
        assert!(b.sql.contains(r#"order by "id" desc nulls last limit 20 offset 40"#), "{}", b.sql);
        assert_eq!(b.binds, vec![Bind::Text("false".into()), Bind::Text("%milk%".into())]);
    }

    #[test]
    fn limit_is_capped_by_max_rows() {
        let b = build_select("public", "todos", &cols(), &params("limit=999999"), 50).unwrap();
        assert!(b.sql.contains("limit 50 offset 0"));
    }

    #[test]
    fn in_is_and_negation() {
        let b = build_select("public", "todos", &cols(), &params(r#"id=in.(1,2,"3,4")&meta=is.null&done=not.eq.true"#), 100).unwrap();
        assert!(b.sql.contains(r#""t"."id" = any(($1::text[])::bigint[])"#), "{}", b.sql);
        assert!(b.sql.contains(r#""t"."meta" is null"#));
        assert!(b.sql.contains(r#"(not ("t"."done" = ($2::text)::boolean))"#), "{}", b.sql);
        assert_eq!(b.binds[0], Bind::TextArray(vec!["1".into(), "2".into(), "3,4".into()]));
    }

    #[test]
    fn injection_attempts_are_rejected_or_bound() {
        // column names must exist in the catalog
        assert!(build_select("public", "todos", &cols(), &params(r#"id"%3Bdrop=eq.1"#), 10).is_err());
        assert!(build_select("public", "todos", &cols(), &params("select=id;drop"), 10).is_err());
        assert!(build_select("public", "todos", &cols(), &params("order=nope.asc"), 10).is_err());
        assert!(build_select("public", "todos", &cols(), &params("order=id.desc;drop"), 10).is_err());
        assert!(build_select("public", "todos", &cols(), &params("id=in.(1)&done=is.true;drop"), 10).is_err());
        assert!(parse_params(Some("or=(id.eq.1,id.eq.2)")).is_err());
        // values are bound, never interpolated
        let b = build_select("public", "todos", &cols(), &params("title=eq.x'%3B+drop+table+todos;--"), 10).unwrap();
        assert!(!b.sql.contains("drop table"));
        assert_eq!(b.binds, vec![Bind::Text("x'; drop table todos;--".into())]);
        // unsupported shapes fail closed
        assert!(build_select("public", "todos", &cols(), &params("select=id,other(*)"), 10).is_err());
        assert!(build_select("public", "todos", &cols(), &params("tags=in.(a)"), 10).is_err());
        assert!(build_select("public", "todos", &cols(), &params("id=bogus.1"), 10).is_err());
    }

    #[test]
    fn quoting_escapes_embedded_quotes() {
        assert_eq!(q(r#"we"ird"#), r#""we""ird""#);
    }

    #[test]
    fn insert_names_only_supplied_columns() {
        let body = json!([{"title": "a"}, {"title": "b", "done": true}]);
        let b = build_insert("public", "todos", &cols(), &body, None, false).unwrap();
        assert!(b.sql.contains(r#"insert into "public"."todos" ("title", "done") select "title", "done" from jsonb_populate_recordset"#), "{}", b.sql);
        assert!(build_insert("public", "todos", &cols(), &json!({"nope": 1}), None, false).is_err());
        assert!(build_insert("public", "todos", &cols(), &json!([]), None, false).is_err());
        assert!(build_insert("public", "todos", &cols(), &json!(5), None, false).is_err());
    }

    #[test]
    fn upsert_merges_or_ignores() {
        let body = json!({"id": 1, "title": "x"});
        let merge = build_insert("public", "todos", &cols(), &body, Some("id"), true).unwrap();
        assert!(merge.sql.contains(r#"on conflict ("id") do update set "title" = excluded."title""#), "{}", merge.sql);
        let ignore = build_insert("public", "todos", &cols(), &body, Some("id"), false).unwrap();
        assert!(ignore.sql.contains(r#"on conflict ("id") do nothing"#));
        assert!(build_insert("public", "todos", &cols(), &body, Some("zzz"), true).is_err());
    }

    #[test]
    fn mutations_require_a_filter() {
        assert!(build_update("public", "todos", &cols(), &json!({"done": true}), &params("")).is_err());
        assert!(build_delete("public", "todos", &cols(), &params("")).is_err());
        let u = build_update("public", "todos", &cols(), &json!({"done": true}), &params("id=eq.7")).unwrap();
        assert!(u.sql.contains(r#"set "done" = s."done" from jsonb_populate_record"#), "{}", u.sql);
        assert!(u.sql.contains(r#"where ("t"."id" = ($2::text)::bigint)"#), "{}", u.sql);
        assert_eq!(u.binds[1], Bind::Text("7".into()));
        let d = build_delete("public", "todos", &cols(), &params("id=eq.7")).unwrap();
        assert!(d.sql.contains(r#"delete from "public"."todos" as t where"#));
    }

    #[test]
    fn prefer_header_parsing() {
        let mut h = HeaderMap::new();
        h.insert("prefer", "return=representation, count=exact".parse().unwrap());
        assert!(prefers(&h, "count=exact"));
        assert!(!prefers(&h, "resolution=merge-duplicates"));
    }
}
