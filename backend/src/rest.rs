//! PostgREST-style generic CRUD: `/api/v1/rest/:table` and `/api/v1/rest/rpc/:function`.
//!
//! Enabled with `REST_ENABLED=true`; the schemas it may expose come from
//! `REST_SCHEMAS` (default `public`). Every request runs inside an RLS transaction
//! ([`begin_rls`] for users, [`begin_rls_for_key`] for API keys), so the *database*
//! decides what a caller may see or change — grants + RLS policies, exactly as with
//! PostgREST. `xbase`, `auth`, `storage` and other Supabase internals can never be
//! exposed, whatever `REST_SCHEMAS` says: `xbase` tables have dedicated endpoints
//! that enforce the `app_slug` predicate.
//!
//! Supported (PostgREST dialect):
//!
//! ```text
//! GET    /api/v1/rest/todos?select=id,title&done=eq.false&order=created_at.desc&limit=20&offset=40
//! GET    ...?id=in.(1,2,3)   ?title=ilike.*milk*   ?deleted_at=is.null   ?done=not.eq.true
//! GET    ...?or=(done.eq.true,title.ilike.*urgent*)   ?and=(id.gt.1,or(a.eq.1,b.eq.2))   ?not.or=(...)
//! GET    ...?select=id,title,author:profiles(name),comments(id,body)   (embedding over foreign keys)
//!        ...?select=id,owner:users!todos_owner_fk(email)                (disambiguate with !constraint)
//! POST   /api/v1/rest/todos            {"title":"x"}  or  [{"title":"a"},{"title":"b"}]
//!        Prefer: resolution=merge-duplicates  +  ?on_conflict=id      (upsert)
//! PATCH  /api/v1/rest/todos?id=eq.7    {"done":true}      (a filter is mandatory)
//! DELETE /api/v1/rest/todos?id=eq.7                       (a filter is mandatory)
//! POST   /api/v1/rest/rpc/my_function  {"arg1": 1, "arg2": "x"}  (named arguments)
//! ```
//!
//! Headers: `Accept-Profile` / `Content-Profile` pick the schema, and
//! `Prefer: count=exact` adds a `Content-Range` total to GETs.
//!
//! Embedding: `rel(cols)` follows a foreign key in either direction between two
//! tables of the same exposed schema — many-to-one gives an object (or null),
//! one-to-many an array. It nests up to 3 levels; embedded resources run under the
//! same RLS as the parent. Filters/ordering apply to the top-level table only.
//!
//! API keys: accepted only with the explicit scopes `rest:read` (GET, and RPC of
//! STABLE/IMMUTABLE functions) / `rest:write` (everything else) — `*` does not
//! imply them. A key runs as `authenticated` with no user id; a table admits it
//! only through a policy on `xbase.request_workspace_id()` (migration 0006).
//!
//! Injection safety: table, column, constraint and function names are only ever
//! taken from the catalog (`pg_attribute`, `pg_constraint`, `pg_proc`) and quoted;
//! every value is a bound parameter cast with the column's own type
//! (`($n::text)::<type>`), never interpolated.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

use crate::{
    auth::Principal,
    error::{ApiError, ApiResult},
    rls::{begin_rls, begin_rls_for_key},
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
const MAX_EMBED_DEPTH: usize = 3;
const MAX_GROUP_DEPTH: usize = 4;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/rest/rpc/:function", post(call_rpc))
        .route(
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

/// A foreign key `table(cols) -> ftable(fcols)` inside one schema.
#[derive(Clone, Debug, PartialEq)]
pub struct ForeignKey {
    pub name: String,
    pub table: String,
    pub cols: Vec<String>,
    pub ftable: String,
    pub fcols: Vec<String>,
}

/// One input argument of a function.
#[derive(Clone, Debug, PartialEq)]
pub struct FnArg {
    pub name: String,
    pub ty: String,
    pub has_default: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Function {
    pub args: Vec<FnArg>,
    pub returns_set: bool,
    /// composite / record results come back as objects
    pub returns_row: bool,
    pub returns_void: bool,
    /// STABLE or IMMUTABLE: callable with `rest:read`
    pub read_only: bool,
    pub variadic: bool,
}

type Cached<T> = (Instant, Arc<T>);
type CacheMap<T> = Mutex<HashMap<(String, String), Cached<T>>>;
type FkRow = (String, String, Vec<String>, String, Vec<String>);

/// Short-lived cache of table definitions, foreign keys and functions.
#[derive(Default)]
pub struct SchemaCache {
    columns: CacheMap<Vec<Column>>,
    fks: CacheMap<Vec<ForeignKey>>,
    functions: CacheMap<Vec<Function>>,
}

fn cache_get<T>(map: &CacheMap<T>, key: &(String, String)) -> Option<Arc<T>> {
    map.lock()
        .unwrap()
        .get(key)
        .filter(|(at, _)| at.elapsed() < SCHEMA_TTL)
        .map(|(_, v)| v.clone())
}

fn cache_put<T>(map: &CacheMap<T>, key: (String, String), v: Arc<T>) {
    let mut m = map.lock().unwrap();
    if m.len() > 512 {
        m.clear();
    }
    m.insert(key, (Instant::now(), v));
}

impl SchemaCache {
    async fn columns(&self, pool: &PgPool, schema: &str, table: &str) -> ApiResult<Arc<Vec<Column>>> {
        let key = (schema.to_string(), table.to_string());
        if let Some(c) = cache_get(&self.columns, &key) {
            return Ok(c);
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
            cache_put(&self.columns, key, cols.clone());
        }
        Ok(cols)
    }

    /// Foreign keys from or to `table`, both ends inside `schema`.
    async fn foreign_keys(&self, pool: &PgPool, schema: &str, table: &str) -> ApiResult<Arc<Vec<ForeignKey>>> {
        let key = (schema.to_string(), table.to_string());
        if let Some(c) = cache_get(&self.fks, &key) {
            return Ok(c);
        }
        let rows: Vec<FkRow> = sqlx::query_as(
            "select con.conname::text, cl.relname::text, \
                    array(select a.attname::text from unnest(con.conkey) with ordinality k(n, i) \
                          join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.n order by k.i), \
                    fcl.relname::text, \
                    array(select a.attname::text from unnest(con.confkey) with ordinality k(n, i) \
                          join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.n order by k.i) \
               from pg_constraint con \
               join pg_class cl on cl.oid = con.conrelid \
               join pg_namespace n on n.oid = cl.relnamespace \
               join pg_class fcl on fcl.oid = con.confrelid \
               join pg_namespace fn on fn.oid = fcl.relnamespace \
              where con.contype = 'f' and n.nspname = $1 and fn.nspname = $1 \
                and (cl.relname = $2 or fcl.relname = $2) \
              order by con.conname",
        )
        .bind(schema)
        .bind(table)
        .fetch_all(pool)
        .await?;
        let fks = Arc::new(
            rows.into_iter()
                .map(|(name, table, cols, ftable, fcols)| ForeignKey { name, table, cols, ftable, fcols })
                .collect::<Vec<_>>(),
        );
        cache_put(&self.fks, key, fks.clone());
        Ok(fks)
    }

    async fn functions(&self, pool: &PgPool, schema: &str, name: &str) -> ApiResult<Arc<Vec<Function>>> {
        let key = (schema.to_string(), name.to_string());
        if let Some(c) = cache_get(&self.functions, &key) {
            return Ok(c);
        }
        // Input arguments only (modes i / b / v); proargnames covers OUT args too.
        #[allow(clippy::type_complexity)]
        let rows: Vec<(bool, String, String, String, bool, i16, Vec<String>, Vec<String>)> = sqlx::query_as(
            "select p.proretset, t.typtype::text, t.typname::text, p.provolatile::text, \
                    coalesce('v' = any(p.proargmodes::text[]), false), p.pronargdefaults, \
                    array(select coalesce((p.proargnames)[o.i], '') from unnest(coalesce(p.proallargtypes, p.proargtypes::oid[])) \
                          with ordinality o(t, i) \
                          where coalesce((p.proargmodes::text[])[o.i], 'i') in ('i', 'b', 'v') order by o.i), \
                    array(select format_type(o.t, null) from unnest(coalesce(p.proallargtypes, p.proargtypes::oid[])) \
                          with ordinality o(t, i) \
                          where coalesce((p.proargmodes::text[])[o.i], 'i') in ('i', 'b', 'v') order by o.i) \
               from pg_proc p \
               join pg_namespace n on n.oid = p.pronamespace \
               join pg_type t on t.oid = p.prorettype \
              where n.nspname = $1 and p.proname = $2 and p.prokind = 'f'",
        )
        .bind(schema)
        .bind(name)
        .fetch_all(pool)
        .await?;
        let fns = Arc::new(
            rows.into_iter()
                .map(|(retset, typtype, typname, vol, variadic, ndefaults, names, types)| {
                    let n = names.len();
                    let first_default = n.saturating_sub(ndefaults.max(0) as usize);
                    Function {
                        args: names
                            .into_iter()
                            .zip(types)
                            .enumerate()
                            .map(|(i, (name, ty))| FnArg { name, ty, has_default: i >= first_default })
                            .collect(),
                        returns_set: retset,
                        returns_row: typtype == "c" || typname == "record",
                        returns_void: typname == "void",
                        read_only: vol == "s" || vol == "i",
                        variadic,
                    }
                })
                .collect::<Vec<_>>(),
        );
        if !fns.is_empty() {
            cache_put(&self.functions, key, fns.clone());
        }
        Ok(fns)
    }
}

/// Everything a query over one schema may reference, loaded before building SQL so
/// that the builders stay pure (and unit-testable).
#[derive(Debug, Default, Clone)]
pub struct Catalog {
    pub schema: String,
    pub tables: HashMap<String, Arc<Vec<Column>>>,
    pub fks: Vec<ForeignKey>,
}

impl Catalog {
    fn columns(&self, table: &str) -> ApiResult<&[Column]> {
        self.tables
            .get(table)
            .map(|c| c.as_slice())
            .ok_or_else(|| ApiError::bad_request(format!("Unknown table '{table}'")))
    }
}

// --- query model -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    Text(String),
    TextArray(Vec<String>),
    Json(Value),
}

/// A filter: `col=op.value`, or a logical group `or=(...)` / `and=(...)`.
#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    Leaf { col: String, spec: String },
    Group { and: bool, negate: bool, items: Vec<Cond> },
}

#[derive(Debug, Default)]
pub struct Params {
    select: Option<String>,
    order: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    on_conflict: Option<String>,
    filters: Vec<Cond>,
}

fn q(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// Splits on `sep` outside parentheses and double quotes.
fn split_top(s: &str, sep: char) -> ApiResult<Vec<String>> {
    let (mut out, mut cur, mut depth, mut quoted) = (Vec::new(), String::new(), 0i32, false);
    for ch in s.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                cur.push(ch);
            }
            '(' if !quoted => {
                depth += 1;
                cur.push(ch);
            }
            ')' if !quoted => {
                depth -= 1;
                if depth < 0 {
                    return Err(ApiError::bad_request("Unbalanced parentheses"));
                }
                cur.push(ch);
            }
            c if c == sep && depth == 0 && !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    if depth != 0 || quoted {
        return Err(ApiError::bad_request("Unbalanced parentheses or quotes"));
    }
    out.push(cur);
    Ok(out)
}

/// Parses the inside of `or=(…)`: `col.op.value`, `col.not.op.value`, `and(…)`, `not.or(…)`.
fn parse_group(and: bool, negate: bool, body: &str, depth: usize) -> ApiResult<Cond> {
    if depth > MAX_GROUP_DEPTH {
        return Err(ApiError::bad_request("Logical groups nest at most 4 levels"));
    }
    let inner = body
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| ApiError::bad_request("or=/and= take a parenthesised list, e.g. or=(a.eq.1,b.eq.2)"))?;
    let mut items = Vec::new();
    for raw in split_top(inner, ',')? {
        let item = raw.trim();
        let (neg, rest) = match item.strip_prefix("not.") {
            Some(r) if r.starts_with("or(") || r.starts_with("and(") => (true, r),
            _ => (false, item),
        };
        if let Some(b) = rest.strip_prefix("or(") {
            items.push(parse_group(false, neg, &format!("({b}"), depth + 1)?);
        } else if let Some(b) = rest.strip_prefix("and(") {
            items.push(parse_group(true, neg, &format!("({b}"), depth + 1)?);
        } else {
            let (col, spec) = item
                .split_once('.')
                .ok_or_else(|| ApiError::bad_request(format!("Group item '{item}' must look like column.op.value")))?;
            items.push(Cond::Leaf { col: col.to_string(), spec: unquote_value(spec) });
        }
    }
    if items.is_empty() {
        return Err(ApiError::bad_request("Empty logical group"));
    }
    Ok(Cond::Group { and, negate, items })
}

/// Inside groups `"a,b"` quotes a value containing reserved characters.
fn unquote_value(spec: &str) -> String {
    let Some((op, value)) = spec.split_once('.') else { return spec.to_string() };
    let (op, value) = if op == "not" {
        match value.split_once('.') {
            Some((op2, v)) => (format!("not.{op2}"), v),
            None => return spec.to_string(),
        }
    } else {
        (op.to_string(), value)
    };
    if op.ends_with("in") {
        return format!("{op}.{value}");
    }
    let v = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    format!("{op}.{v}")
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
            "or" => p.filters.push(parse_group(false, false, &v, 1)?),
            "and" => p.filters.push(parse_group(true, false, &v, 1)?),
            "not.or" => p.filters.push(parse_group(false, true, &v, 1)?),
            "not.and" => p.filters.push(parse_group(true, true, &v, 1)?),
            "not" => return Err(ApiError::bad_request("use not.or=(...) / not.and=(...) or col=not.op.value")),
            _ => p.filters.push(Cond::Leaf { col: k, spec: v }),
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

/// Compiles one `col=op.value` predicate; `binds` grows, numbering from `first_param`.
fn build_leaf(cols: &[Column], name: &str, spec: &str, alias: &str, first_param: usize, binds: &mut Vec<Bind>) -> ApiResult<String> {
    let col = find(cols, name)?;
    let lhs = format!("{}.{}", q(alias), q(&col.name));
    let (negate, spec) = match spec.strip_prefix("not.") {
        Some(rest) => (true, rest),
        None => (false, spec),
    };
    let (op, value) = spec
        .split_once('.')
        .ok_or_else(|| ApiError::bad_request(format!("Filter on '{name}' must look like op.value")))?;
    let n = first_param + binds.len();
    let wrap = |c: String| if negate { format!("(not ({c}))") } else { format!("({c})") };

    Ok(match op {
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
            wrap(format!("{lhs} = any((${n}::text[])::{}[])", col.ty))
        }
        "like" | "ilike" => {
            binds.push(Bind::Text(value.replace('*', "%")));
            wrap(format!("{lhs}::text {op} ${n}"))
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
            wrap(format!("{lhs} {sym} (${n}::text)::{}", col.ty))
        }
        other => return Err(ApiError::bad_request(format!("Unsupported operator '{other}'"))),
    })
}

fn build_cond(cols: &[Column], cond: &Cond, alias: &str, first_param: usize, binds: &mut Vec<Bind>) -> ApiResult<String> {
    match cond {
        Cond::Leaf { col, spec } => build_leaf(cols, col, spec, alias, first_param, binds),
        Cond::Group { and, negate, items } => {
            let parts = items
                .iter()
                .map(|c| build_cond(cols, c, alias, first_param, binds))
                .collect::<ApiResult<Vec<_>>>()?;
            let joined = parts.join(if *and { " and " } else { " or " });
            Ok(if *negate { format!("(not ({joined}))") } else { format!("({joined})") })
        }
    }
}

/// Compiles filters into `AND`-joined predicates over `alias`.
/// Parameter numbering starts at `first_param`.
fn build_filters(cols: &[Column], filters: &[Cond], alias: &str, first_param: usize) -> ApiResult<(Vec<String>, Vec<Bind>)> {
    let mut binds = Vec::new();
    let clauses = filters
        .iter()
        .map(|c| build_cond(cols, c, alias, first_param, &mut binds))
        .collect::<ApiResult<Vec<_>>>()?;
    Ok((clauses, binds))
}

fn where_sql(clauses: &[String]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!(" where {}", clauses.join(" and "))
    }
}

// --- select list + embedding -------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SelectItem {
    Star,
    Column { name: String, alias: Option<String> },
    Embed { rel: String, hint: Option<String>, alias: Option<String>, items: Vec<SelectItem> },
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parses `id,title,author:profiles!fk(name,org:orgs(name))`.
pub fn parse_select(spec: Option<&str>, depth: usize) -> ApiResult<Vec<SelectItem>> {
    let spec = match spec.map(str::trim) {
        None | Some("") | Some("*") => return Ok(vec![SelectItem::Star]),
        Some(s) => s,
    };
    let mut out = Vec::new();
    for raw in split_top(spec, ',')? {
        let item = raw.trim();
        if item == "*" {
            out.push(SelectItem::Star);
            continue;
        }
        if item.contains("::") {
            return Err(ApiError::bad_request("select does not support casts"));
        }
        let (alias, rest) = match item.split_once(':') {
            Some((a, r)) if !a.contains('(') => (Some(a.trim().to_string()), r.trim()),
            _ => (None, item),
        };
        if let Some(a) = &alias {
            if !is_ident(a) {
                return Err(ApiError::bad_request(format!("Invalid alias '{a}'")));
            }
        }
        if let Some(open) = rest.find('(') {
            if depth >= MAX_EMBED_DEPTH {
                return Err(ApiError::bad_request("Embedding nests at most 3 levels"));
            }
            let inner = rest[open..]
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .ok_or_else(|| ApiError::bad_request(format!("Malformed embed '{item}'")))?;
            let head = &rest[..open];
            let (rel, hint) = match head.split_once('!') {
                Some((r, h)) => (r.to_string(), Some(h.to_string())),
                None => (head.to_string(), None),
            };
            if !is_ident(&rel) || hint.as_deref().is_some_and(|h| !is_ident(h)) {
                return Err(ApiError::bad_request(format!("Invalid embed '{item}'")));
            }
            out.push(SelectItem::Embed { rel, hint, alias, items: parse_select(Some(inner), depth + 1)? });
        } else {
            if rest.contains([')', '!']) {
                return Err(ApiError::bad_request(format!("Invalid select item '{item}'")));
            }
            out.push(SelectItem::Column { name: rest.to_string(), alias });
        }
    }
    Ok(out)
}

/// Tables named by embeds anywhere in the tree (for catalog loading).
pub fn embedded_tables(items: &[SelectItem], parent: &str, out: &mut Vec<(String, String)>) {
    for it in items {
        if let SelectItem::Embed { rel, items, .. } = it {
            out.push((parent.to_string(), rel.clone()));
            embedded_tables(items, rel, out);
        }
    }
}

enum Direction {
    /// parent.cols -> rel.fcols: at most one row (object)
    ToOne,
    /// rel.cols -> parent.fcols: many rows (array)
    ToMany,
}

fn resolve_relationship<'a>(cat: &'a Catalog, parent: &str, rel: &str, hint: Option<&str>) -> ApiResult<(&'a ForeignKey, Direction)> {
    let mut found: Vec<(&ForeignKey, Direction)> = Vec::new();
    for fk in &cat.fks {
        let hint_ok = |cols: &[String]| match hint {
            None => true,
            Some(h) => fk.name == h || (cols.len() == 1 && cols[0] == h),
        };
        if fk.table == parent && fk.ftable == rel && hint_ok(&fk.cols) {
            found.push((fk, Direction::ToOne));
        } else if parent != rel && fk.table == rel && fk.ftable == parent && hint_ok(&fk.cols) {
            found.push((fk, Direction::ToMany));
        }
    }
    match found.len() {
        0 => Err(ApiError::bad_request(format!("No foreign key between '{parent}' and '{rel}'"))),
        1 => Ok(found.pop().unwrap()),
        _ => Err(ApiError::bad_request(format!(
            "More than one relationship between '{parent}' and '{rel}'; disambiguate with {rel}!<constraint>(...), one of: {}",
            found.iter().map(|(f, _)| f.name.as_str()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// Renders a select list over `alias` (a row of `table`). Embedded resources become
/// correlated subqueries, so they run under the same RLS as the outer query.
fn build_select_list(cat: &Catalog, table: &str, alias: &str, items: &[SelectItem], counter: &mut usize) -> ApiResult<String> {
    let cols = cat.columns(table)?;
    let mut parts = Vec::new();
    for it in items {
        match it {
            SelectItem::Star => parts.extend(cols.iter().map(|c| format!("{}.{}", q(alias), q(&c.name)))),
            SelectItem::Column { name, alias: a } => {
                let c = find(cols, name)?;
                let expr = format!("{}.{}", q(alias), q(&c.name));
                parts.push(match a {
                    Some(a) => format!("{expr} as {}", q(a)),
                    None => expr,
                });
            }
            SelectItem::Embed { rel, hint, alias: a, items } => {
                let (fk, dir) = resolve_relationship(cat, table, rel, hint.as_deref())?;
                *counter += 1;
                let (inner, row) = (format!("e{counter}"), format!("r{counter}"));
                let sel = build_select_list(cat, rel, &inner, items, counter)?;
                let target = format!("{}.{}", q(&cat.schema), q(rel));
                let on = |rel_cols: &[String], parent_cols: &[String]| {
                    rel_cols
                        .iter()
                        .zip(parent_cols)
                        .map(|(r, p)| format!("{}.{} = {}.{}", q(&inner), q(r), q(alias), q(p)))
                        .collect::<Vec<_>>()
                        .join(" and ")
                };
                let name = q(a.as_deref().unwrap_or(rel));
                parts.push(match dir {
                    Direction::ToOne => format!(
                        "(select to_jsonb({row}) from (select {sel} from {target} as {} where {} limit 1) {row}) as {name}",
                        q(&inner),
                        on(&fk.fcols, &fk.cols)
                    ),
                    Direction::ToMany => format!(
                        "(select coalesce(jsonb_agg(to_jsonb({row})), '[]'::jsonb) from (select {sel} from {target} as {} where {}) {row}) as {name}",
                        q(&inner),
                        on(&fk.cols, &fk.fcols)
                    ),
                });
            }
        }
    }
    if parts.is_empty() {
        return Err(ApiError::bad_request("Empty select"));
    }
    Ok(parts.join(", "))
}

pub struct Built {
    pub sql: String,
    pub count_sql: Option<String>,
    pub binds: Vec<Bind>,
}

const AGG: &str = "coalesce(jsonb_agg(to_jsonb(r)), '[]'::jsonb)";

pub fn build_select(cat: &Catalog, table: &str, p: &Params, max_rows: i64) -> ApiResult<Built> {
    let cols = cat.columns(table)?;
    let items = parse_select(p.select.as_deref(), 0)?;
    let mut counter = 0;
    let sel = build_select_list(cat, table, "t", &items, &mut counter)?;

    let (clauses, binds) = build_filters(cols, &p.filters, "t", 1)?;
    let filter = where_sql(&clauses);

    let mut order = String::new();
    if let Some(spec) = p.order.as_deref().filter(|s| !s.is_empty()) {
        let parts = spec
            .split(',')
            .map(|item| {
                let mut it = item.trim().split('.');
                let col = find(cols, it.next().unwrap_or_default())?;
                let mut out = format!("\"t\".{}", q(&col.name));
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
    let from = format!("{}.{}", q(&cat.schema), q(table));
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

/// Rows are grouped by the exact set of keys they supply and each group becomes
/// its own `INSERT` (chained as data-modifying CTEs, so still one statement and
/// one transaction). A column a row does not mention therefore takes its DEFAULT
/// instead of being forced to NULL, which a single `INSERT … SELECT cols` over
/// rows with different keys would do. Response rows come back grouped, not in
/// request order, when a batch mixes key sets.
pub fn build_insert(
    schema: &str,
    table: &str,
    cols: &[Column],
    body: &Value,
    on_conflict: Option<&str>,
    merge: bool,
) -> ApiResult<Built> {
    let rows = body_rows(body)?;
    body_columns(cols, &rows)?; // validates every key against the catalog
    let target = format!("{}.{}", q(schema), q(table));

    let conflict_keys: Option<Vec<String>> = match on_conflict.filter(|c| !c.is_empty()) {
        None => None,
        Some(list) => Some(
            list.split(',')
                .map(|c| find(cols, c.trim()).map(|c| c.name.clone()))
                .collect::<ApiResult<Vec<_>>>()?,
        ),
    };

    let mut groups: Vec<(Vec<&Column>, Vec<Value>)> = Vec::new();
    for row in rows {
        let used: Vec<&Column> = cols.iter().filter(|c| row.contains_key(&c.name)).collect();
        if used.is_empty() {
            return Err(ApiError::bad_request("Every row must set at least one column"));
        }
        let value = Value::Object(row.clone());
        match groups.iter_mut().find(|(g, _)| g.len() == used.len() && g.iter().zip(&used).all(|(a, b)| a.name == b.name)) {
            Some((_, rows)) => rows.push(value),
            None => groups.push((used, vec![value])),
        }
    }

    let (mut ctes, mut selects, mut binds) = (Vec::new(), Vec::new(), Vec::new());
    for (n, (used, group_rows)) in groups.into_iter().enumerate() {
        let names = used.iter().map(|c| q(&c.name)).collect::<Vec<_>>().join(", ");
        let conflict = match &conflict_keys {
            None => String::new(),
            Some(keys) => {
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
        binds.push(Bind::Json(Value::Array(group_rows)));
        ctes.push(format!(
            "i{n} as (insert into {target} ({names}) select {names} from jsonb_populate_recordset(null::{target}, ${}::jsonb){conflict} returning *)",
            n + 1
        ));
        selects.push(format!("select * from i{n}"));
    }

    Ok(Built {
        sql: format!(
            "with {} select {AGG} from ({}) r",
            ctes.join(", "),
            selects.join(" union all ")
        ),
        count_sql: None,
        binds,
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

/// SQL literal for a catalog-sourced name (used as a jsonb key).
fn lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Picks the overload matching the body's argument names.
pub fn pick_function<'a>(fns: &'a [Function], keys: &[String]) -> ApiResult<&'a Function> {
    let fits: Vec<&Function> = fns
        .iter()
        .filter(|f| {
            !f.variadic
                && f.args.iter().all(|a| !a.name.is_empty())
                && keys.iter().all(|k| f.args.iter().any(|a| &a.name == k))
                && f.args.iter().all(|a| a.has_default || keys.contains(&a.name))
        })
        .collect();
    match fits.len() {
        1 => Ok(fits[0]),
        0 => Err(ApiError::bad_request(
            "No function matches these named arguments (functions need named, non-variadic arguments)",
        )),
        _ => Err(ApiError::bad_request("Ambiguous call: several overloads match these arguments")),
    }
}

/// `select … from "schema"."fn"("a" => ($1::jsonb ->> 'a')::int, …)` with the whole
/// argument object bound once as `$1`.
pub fn build_rpc(schema: &str, name: &str, f: &Function, args: &serde_json::Map<String, Value>) -> Built {
    let call_args = f
        .args
        .iter()
        .filter(|a| args.contains_key(&a.name))
        .map(|a| {
            let get = format!("($1::jsonb -> {})", lit(&a.name));
            let expr = if a.ty == "jsonb" || a.ty == "json" {
                format!("{get}::{}", a.ty)
            } else if a.ty.ends_with(']') {
                format!(
                    "(case when jsonb_typeof({get}) = 'array' then array(select jsonb_array_elements_text({get})) end)::{}",
                    a.ty
                )
            } else {
                format!("($1::jsonb ->> {})::{}", lit(&a.name), a.ty)
            };
            format!("{} => {expr}", q(&a.name))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let call = format!("{}.{}({call_args})", q(schema), q(name));
    let sql = if f.returns_void {
        format!("select 'null'::jsonb from {call} r")
    } else if f.returns_set {
        format!("select coalesce(jsonb_agg(to_jsonb(r)), '[]'::jsonb) from {call} r")
    } else if f.returns_row {
        format!("select to_jsonb(r) from {call} r")
    } else {
        format!("select to_jsonb({call})")
    };
    Built { sql, count_sql: None, binds: vec![Bind::Json(Value::Object(args.clone()))] }
}

// --- execution -------------------------------------------------------------

fn schema_for(state: &AppState, headers: &HeaderMap, profile_header: &str) -> ApiResult<String> {
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
    Ok(schema)
}

async fn resolve(state: &AppState, headers: &HeaderMap, profile_header: &str, table: &str) -> ApiResult<Catalog> {
    let schema = schema_for(state, headers, profile_header)?;
    if !is_ident(table) {
        return Err(ApiError::bad_request("Invalid table name"));
    }
    let cols = state.rest_cache.columns(&state.pool, &schema, table).await?;
    if cols.is_empty() {
        return Err(ApiError::not_found(format!("Table '{schema}.{table}' not found")));
    }
    let mut cat = Catalog { schema, ..Default::default() };
    cat.tables.insert(table.to_string(), cols);
    Ok(cat)
}

/// Loads the columns and foreign keys every embed of `select` needs.
async fn load_embeds(state: &AppState, cat: &mut Catalog, table: &str, select: Option<&str>) -> ApiResult<()> {
    let items = parse_select(select, 0)?;
    let mut pairs = Vec::new();
    embedded_tables(&items, table, &mut pairs);
    let mut fk_loaded = std::collections::HashSet::new();
    for (parent, rel) in pairs {
        if fk_loaded.insert(parent.clone()) {
            for fk in state.rest_cache.foreign_keys(&state.pool, &cat.schema, &parent).await?.iter() {
                if !cat.fks.contains(fk) {
                    cat.fks.push(fk.clone());
                }
            }
        }
        if !cat.tables.contains_key(&rel) {
            let cols = state.rest_cache.columns(&state.pool, &cat.schema, &rel).await?;
            if cols.is_empty() {
                return Err(ApiError::bad_request(format!("Unknown embedded table '{rel}'")));
            }
            cat.tables.insert(rel, cols);
        }
    }
    Ok(())
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

/// Opens the RLS transaction for the caller. API keys need an explicit REST scope.
async fn begin_for(state: &AppState, principal: &Principal, write: bool) -> ApiResult<Transaction<'static, Postgres>> {
    match principal {
        Principal::User(claims) => begin_rls(&state.pool, claims).await,
        Principal::ApiKey(key) => {
            let scope = if write { "rest:write" } else { "rest:read" };
            // `*` deliberately does not imply REST access: keys predate it.
            if !key.scopes.iter().any(|s| s == scope) {
                return Err(ApiError::forbidden(format!("API key lacks scope '{scope}'")));
            }
            if key.app_slug != state.config.app_id {
                return Err(ApiError::forbidden("API key belongs to another app"));
            }
            begin_rls_for_key(&state.pool, key).await
        }
    }
}

async fn run(state: &AppState, principal: &Principal, write: bool, built: &Built, want_count: bool) -> ApiResult<(Value, Option<i64>)> {
    let mut tx = begin_for(state, principal, write).await?;
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
    principal: Principal,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let mut cat = resolve(&state, &headers, "accept-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    load_embeds(&state, &mut cat, &table, params.select.as_deref()).await?;
    let built = build_select(&cat, &table, &params, state.config.rest_max_rows)?;
    let want_count = prefers(&headers, "count=exact");
    let (data, total) = run(&state, &principal, false, &built, want_count).await?;

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
    principal: Principal,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let cat = resolve(&state, &headers, "content-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let merge = prefers(&headers, "resolution=merge-duplicates");
    let ignore = prefers(&headers, "resolution=ignore-duplicates");
    if (merge || ignore) && params.on_conflict.is_none() {
        return Err(ApiError::bad_request("Upserts require ?on_conflict=<column[,column]>"));
    }
    let on_conflict = if merge || ignore { params.on_conflict.as_deref() } else { None };
    let built = build_insert(&cat.schema, &table, cat.columns(&table)?, &body, on_conflict, merge)?;
    let (data, _) = run(&state, &principal, true, &built, false).await?;
    Ok((StatusCode::CREATED, Json(data)))
}

async fn update_rows(
    State(state): State<AppState>,
    principal: Principal,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let cat = resolve(&state, &headers, "content-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let built = build_update(&cat.schema, &table, cat.columns(&table)?, &body, &params)?;
    Ok(Json(run(&state, &principal, true, &built, false).await?.0))
}

async fn delete_rows(
    State(state): State<AppState>,
    principal: Principal,
    Path(table): Path<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let cat = resolve(&state, &headers, "content-profile", &table).await?;
    let params = parse_params(raw.as_deref())?;
    let built = build_delete(&cat.schema, &table, cat.columns(&table)?, &params)?;
    Ok(Json(run(&state, &principal, true, &built, false).await?.0))
}

/// `POST /api/v1/rest/rpc/:function` with a JSON object of named arguments (`{}` for none).
async fn call_rpc(
    State(state): State<AppState>,
    principal: Principal,
    Path(function): Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> ApiResult<Json<Value>> {
    let schema = schema_for(&state, &headers, "content-profile")?;
    if !is_ident(&function) {
        return Err(ApiError::bad_request("Invalid function name"));
    }
    let args = match body.map(|Json(v)| v) {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(o)) => o,
        Some(_) => return Err(ApiError::bad_request("RPC body must be a JSON object of named arguments")),
    };
    let fns = state.rest_cache.functions(&state.pool, &schema, &function).await?;
    if fns.is_empty() {
        return Err(ApiError::not_found(format!("Function '{schema}.{function}' not found")));
    }
    let keys: Vec<String> = args.keys().cloned().collect();
    let f = pick_function(&fns, &keys)?;
    let built = build_rpc(&schema, &function, f, &args);
    Ok(Json(run(&state, &principal, !f.read_only, &built, false).await?.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cols() -> Vec<Column> {
        [("id", "bigint"), ("title", "text"), ("done", "boolean"), ("tags", "text[]"), ("meta", "jsonb"), ("author_id", "uuid")]
            .into_iter()
            .map(|(n, t)| Column { name: n.into(), ty: t.into() })
            .collect()
    }

    fn cat() -> Catalog {
        let mut c = Catalog { schema: "public".into(), ..Default::default() };
        c.tables.insert("todos".into(), Arc::new(cols()));
        c.tables.insert(
            "profiles".into(),
            Arc::new(vec![Column { name: "id".into(), ty: "uuid".into() }, Column { name: "name".into(), ty: "text".into() }]),
        );
        c.tables.insert(
            "comments".into(),
            Arc::new(vec![
                Column { name: "id".into(), ty: "bigint".into() },
                Column { name: "todo_id".into(), ty: "bigint".into() },
                Column { name: "author_id".into(), ty: "uuid".into() },
                Column { name: "body".into(), ty: "text".into() },
            ]),
        );
        c.fks = vec![
            ForeignKey { name: "todos_author_fk".into(), table: "todos".into(), cols: vec!["author_id".into()], ftable: "profiles".into(), fcols: vec!["id".into()] },
            ForeignKey { name: "comments_todo_fk".into(), table: "comments".into(), cols: vec!["todo_id".into()], ftable: "todos".into(), fcols: vec!["id".into()] },
            ForeignKey { name: "comments_author_fk".into(), table: "comments".into(), cols: vec!["author_id".into()], ftable: "profiles".into(), fcols: vec!["id".into()] },
        ];
        c
    }

    fn params(q: &str) -> Params {
        parse_params(Some(q)).unwrap()
    }

    fn sel(q: &str) -> ApiResult<Built> {
        build_select(&cat(), "todos", &parse_params(Some(q))?, 1000)
    }

    #[test]
    fn select_with_filters_order_and_paging() {
        let b = sel("select=id,title&done=eq.false&title=ilike.*milk*&order=id.desc.nullslast&limit=20&offset=40").unwrap();
        assert!(b.sql.contains(r#"select "t"."id", "t"."title" from "public"."todos" as t"#), "{}", b.sql);
        assert!(b.sql.contains(r#"("t"."done" = ($1::text)::boolean)"#), "{}", b.sql);
        assert!(b.sql.contains(r#"("t"."title"::text ilike $2)"#), "{}", b.sql);
        assert!(b.sql.contains(r#"order by "t"."id" desc nulls last limit 20 offset 40"#), "{}", b.sql);
        assert_eq!(b.binds, vec![Bind::Text("false".into()), Bind::Text("%milk%".into())]);
    }

    #[test]
    fn limit_is_capped_by_max_rows() {
        let b = build_select(&cat(), "todos", &params("limit=999999"), 50).unwrap();
        assert!(b.sql.contains("limit 50 offset 0"));
    }

    #[test]
    fn in_is_and_negation() {
        let b = sel(r#"id=in.(1,2,"3,4")&meta=is.null&done=not.eq.true"#).unwrap();
        assert!(b.sql.contains(r#""t"."id" = any(($1::text[])::bigint[])"#), "{}", b.sql);
        assert!(b.sql.contains(r#""t"."meta" is null"#));
        assert!(b.sql.contains(r#"(not ("t"."done" = ($2::text)::boolean))"#), "{}", b.sql);
        assert_eq!(b.binds[0], Bind::TextArray(vec!["1".into(), "2".into(), "3,4".into()]));
    }

    #[test]
    fn or_and_groups() {
        let b = sel(r#"or=(done.eq.true,title.ilike.*urgent*)&id=gt.5"#).unwrap();
        assert!(
            b.sql.contains(r#"where (("t"."done" = ($1::text)::boolean) or ("t"."title"::text ilike $2)) and ("t"."id" > ($3::text)::bigint)"#),
            "{}",
            b.sql
        );
        let nested = sel(r#"and=(id.gte.1,or(done.is.true,title.eq."a,b"),not.or(id.eq.9,id.eq.10))"#).unwrap();
        assert!(nested.sql.contains(r#"(("t"."id" >= ($1::text)::bigint) and (("t"."done" is true) or ("t"."title" = ($2::text)::text)) and (not (("t"."id" = ($3::text)::bigint) or ("t"."id" = ($4::text)::bigint))))"#), "{}", nested.sql);
        assert_eq!(nested.binds[1], Bind::Text("a,b".into()));
        let neg = sel("not.and=(id.eq.1,done.eq.false)").unwrap();
        assert!(neg.sql.contains(r#"where (not (("t"."id" = ($1::text)::bigint) and ("t"."done" = ($2::text)::boolean)))"#), "{}", neg.sql);
        let inlist = sel("or=(id.in.(1,2),title.not.eq.x)").unwrap();
        assert!(inlist.sql.contains(r#"any(($1::text[])::bigint[])"#), "{}", inlist.sql);
        assert!(inlist.sql.contains(r#"(not ("t"."title" = ($2::text)::text))"#), "{}", inlist.sql);
        // malformed / unknown columns fail closed
        assert!(sel("or=(nope.eq.1)").is_err());
        assert!(sel("or=done.eq.true").is_err());
        assert!(sel("or=(done.eq.true").is_err());
        assert!(sel("or=()").is_err());
        assert!(sel("or=(and(and(and(and(id.eq.1)))))").is_err());
        assert!(parse_params(Some("not=x")).is_err());
    }

    #[test]
    fn embedding_both_directions_and_nesting() {
        let b = sel("select=id,author:profiles(name),comments(id,body,profiles(name))").unwrap();
        assert!(b.sql.contains(r#"(select to_jsonb(r1) from (select "e1"."name" from "public"."profiles" as "e1" where "e1"."id" = "t"."author_id" limit 1) r1) as "author""#), "{}", b.sql);
        assert!(b.sql.contains(r#"(select coalesce(jsonb_agg(to_jsonb(r2)), '[]'::jsonb) from (select "e2"."id", "e2"."body", (select to_jsonb(r3) from (select "e3"."name" from "public"."profiles" as "e3" where "e3"."id" = "e2"."author_id" limit 1) r3) as "profiles" from "public"."comments" as "e2" where "e2"."todo_id" = "t"."id") r2) as "comments""#), "{}", b.sql);
        // hints and aliases
        assert!(sel("select=id,a:profiles!todos_author_fk(*)").is_ok());
        assert!(sel("select=id,a:profiles!author_id(id)").is_ok());
        assert!(sel("select=id,profiles!nope(id)").is_err());
        assert!(sel("select=id,todos(id)").is_err(), "self relation without FK");
        assert!(sel("select=id,nothere(id)").is_err());
        assert!(sel("select=id,profiles(secret)").is_err());
        assert!(sel("select=t:title").is_ok());
        assert!(sel("select=a:b:c(id)").is_err());
        assert!(sel("select=id,comments(id,todos(id,comments(id,todos(id))))").is_err(), "depth limit");
    }

    #[test]
    fn ambiguous_relationships_need_a_hint() {
        let mut c = cat();
        c.fks.push(ForeignKey { name: "todos_reviewer_fk".into(), table: "todos".into(), cols: vec!["id".into()], ftable: "profiles".into(), fcols: vec!["id".into()] });
        assert!(build_select(&c, "todos", &params("select=profiles(name)"), 10).is_err());
        assert!(build_select(&c, "todos", &params("select=profiles!todos_reviewer_fk(name)"), 10).is_ok());
    }

    #[test]
    fn injection_attempts_are_rejected_or_bound() {
        // column names must exist in the catalog
        assert!(sel(r#"id"%3Bdrop=eq.1"#).is_err());
        assert!(sel("select=id;drop").is_err());
        assert!(sel("order=nope.asc").is_err());
        assert!(sel("order=id.desc;drop").is_err());
        assert!(sel("id=in.(1)&done=is.true;drop").is_err());
        assert!(sel(r#"select=id,profiles"x(id)"#).is_err());
        assert!(sel(r#"select=x%22y:title"#).is_err());
        assert!(sel("or=(id.eq.1;drop,id.eq.2)").is_ok_and(|b| !b.sql.contains("drop")));
        // values are bound, never interpolated
        let b = sel("title=eq.x'%3B+drop+table+todos;--").unwrap();
        assert!(!b.sql.contains("drop table"));
        assert_eq!(b.binds, vec![Bind::Text("x'; drop table todos;--".into())]);
        // unsupported shapes fail closed
        assert!(sel("select=id::text").is_err());
        assert!(sel("tags=in.(a)").is_err());
        assert!(sel("id=bogus.1").is_err());
    }

    #[test]
    fn quoting_escapes_embedded_quotes() {
        assert_eq!(q(r#"we"ird"#), r#""we""ird""#);
        assert_eq!(lit("it's"), "'it''s'");
    }

    #[test]
    fn insert_names_only_supplied_columns() {
        let body = json!([{"title": "a"}, {"title": "b", "done": true}]);
        let b = build_insert("public", "todos", &cols(), &body, None, false).unwrap();
        // different key sets => separate INSERTs, so "done" keeps its DEFAULT for the first row
        assert!(b.sql.contains(r#"insert into "public"."todos" ("title") select "title" from jsonb_populate_recordset(null::"public"."todos", $1::jsonb)"#), "{}", b.sql);
        assert!(b.sql.contains(r#"("title", "done") select "title", "done" from jsonb_populate_recordset(null::"public"."todos", $2::jsonb)"#), "{}", b.sql);
        assert_eq!(b.binds.len(), 2);
        // identical key sets share one INSERT
        let same = build_insert("public", "todos", &cols(), &json!([{"title":"a"},{"title":"b"}]), None, false).unwrap();
        assert_eq!(same.binds.len(), 1);
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
        let g = build_delete("public", "todos", &cols(), &params("or=(id.eq.1,id.eq.2)")).unwrap();
        assert!(g.sql.contains(r#"where (("t"."id" = ($1::text)::bigint) or ("t"."id" = ($2::text)::bigint))"#), "{}", g.sql);
    }

    fn func(args: &[(&str, &str, bool)]) -> Function {
        Function {
            args: args.iter().map(|(n, t, d)| FnArg { name: n.to_string(), ty: t.to_string(), has_default: *d }).collect(),
            returns_set: false,
            returns_row: false,
            returns_void: false,
            read_only: true,
            variadic: false,
        }
    }

    #[test]
    fn rpc_builds_named_calls() {
        let f = func(&[("n", "integer", false), ("tags", "text[]", true), ("doc", "jsonb", true)]);
        let args = json!({"n": 3, "tags": ["a"], "doc": {"x": 1}});
        let b = build_rpc("public", "add_it", &f, args.as_object().unwrap());
        assert_eq!(
            b.sql,
            r#"select to_jsonb("public"."add_it"("n" => ($1::jsonb ->> 'n')::integer, "tags" => (case when jsonb_typeof(($1::jsonb -> 'tags')) = 'array' then array(select jsonb_array_elements_text(($1::jsonb -> 'tags'))) end)::text[], "doc" => ($1::jsonb -> 'doc')::jsonb))"#
        );
        let mut set = f.clone();
        set.returns_set = true;
        assert!(build_rpc("public", "f", &set, &serde_json::Map::new()).sql.starts_with("select coalesce(jsonb_agg(to_jsonb(r))"));
        let mut void = f.clone();
        void.returns_void = true;
        assert!(build_rpc("public", "f", &void, &serde_json::Map::new()).sql.starts_with("select 'null'::jsonb"));
        // omitted defaulted args are left out of the call
        let only_n = build_rpc("public", "f", &f, json!({"n": 1}).as_object().unwrap());
        assert!(!only_n.sql.contains("tags"));
    }

    #[test]
    fn rpc_overload_selection() {
        let a = func(&[("x", "integer", false)]);
        let b = func(&[("x", "integer", false), ("y", "integer", false)]);
        let fns = vec![a.clone(), b.clone()];
        assert_eq!(pick_function(&fns, &["x".into()]).unwrap(), &a);
        assert_eq!(pick_function(&fns, &["x".into(), "y".into()]).unwrap(), &b);
        assert!(pick_function(&fns, &["z".into()]).is_err());
        assert!(pick_function(&fns, &[]).is_err(), "required arg missing");
        let unnamed = func(&[("", "integer", false)]);
        assert!(pick_function(&[unnamed], &[]).is_err());
        let ambiguous = vec![func(&[("x", "integer", true)]), func(&[("x", "text", true)])];
        assert!(pick_function(&ambiguous, &["x".into()]).is_err());
    }

    #[test]
    fn prefer_header_parsing() {
        let mut h = HeaderMap::new();
        h.insert("prefer", "return=representation, count=exact".parse().unwrap());
        assert!(prefers(&h, "count=exact"));
        assert!(!prefers(&h, "resolution=merge-duplicates"));
    }
}
