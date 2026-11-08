//! Storage (buckets & objects) via the Supabase Storage API.
//!
//! * Bucket management uses the service role key and requires an admin caller.
//! * Object operations forward the caller's own JWT, so Storage's RLS policies
//!   on `storage.objects` decide access — identical to Supabase Cloud.
//! * API keys (`x-api-key`, scopes `storage:read` / `storage:write`) are also
//!   accepted: Storage then runs with the service role, so the key is confined
//!   *by this proxy* to objects under `<its workspace id>/`. That is the same
//!   layout the `storage.objects` policies (migration 0005) use for users.
//! * Buckets are namespaced per SaaS (`<APP_ID>-<name>`) so ten apps can share
//!   one Storage service without seeing each other's files.
//! * Large uploads use the TUS resumable protocol. Users may talk to Storage
//!   directly (`/uploads/resumable` returns the details); `/storage/tus/:bucket`
//!   is a TUS proxy that also works with API keys: the creation request is
//!   confined like any other key write, and the upload URL it hands back carries
//!   an HMAC binding the upload to that caller, so it cannot be reused by another.
//! * Image transformations are applied through signed render URLs.

use axum::{
    async_trait,
    body::Body,
    extract::{FromRequestParts, Path, Query, State},
    http::{header, request::Parts, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api_keys::{self, ApiKeyPrincipal},
    auth::{AdminClaims, UserToken},
    error::{ApiError, ApiResult},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/storage/buckets", get(list_buckets).post(create_bucket))
        .route("/api/v1/storage/buckets/:bucket", delete(delete_bucket))
        .route("/api/v1/storage/objects/:bucket/list", post(list_objects))
        .route("/api/v1/storage/objects/:bucket/sign-upload", post(sign_upload))
        .route("/api/v1/storage/objects/:bucket/sign-download", post(sign_download))
        .route("/api/v1/storage/objects/:bucket", delete(delete_objects))
        .route(
            "/api/v1/storage/objects/:bucket/*path",
            get(download_object).put(upload_object).post(upload_object),
        )
        .route("/api/v1/storage/uploads/resumable", post(resumable_upload_info))
        .route("/api/v1/storage/tus/:bucket", post(tus_create))
        .route("/api/v1/storage/tus/:bucket/:token", axum::routing::any(tus_forward))
}

/// Applies the per-app bucket namespace.
pub fn scoped_bucket(app_id: &str, bucket: &str) -> ApiResult<String> {
    let valid = !bucket.is_empty()
        && bucket.len() <= 63
        && bucket
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !valid {
        return Err(ApiError::bad_request(
            "Bucket names may contain lowercase letters, digits, '-' and '_' (max 63)",
        ));
    }
    let prefix = format!("{app_id}-");
    Ok(if bucket.starts_with(&prefix) {
        bucket.to_string()
    } else {
        format!("{prefix}{bucket}")
    })
}

/// Rejects traversal and empty segments in object paths.
pub fn validate_object_path(path: &str) -> ApiResult<&str> {
    let path = path.trim_start_matches('/');
    if path.is_empty()
        || path.len() > 1024
        || path.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(ApiError::bad_request("Invalid object path"));
    }
    Ok(path)
}

/// Builds `{base}/{fixed...}/{bucket}/{path segments}` with proper percent-encoding.
fn storage_url(base: &str, fixed: &[&str], bucket: &str, path: Option<&str>) -> ApiResult<reqwest::Url> {
    let mut url = reqwest::Url::parse(base).map_err(|e| ApiError::internal(e.to_string()))?;
    {
        let mut segs = url
            .path_segments_mut()
            .map_err(|_| ApiError::internal("invalid storage base url"))?;
        segs.pop_if_empty();
        segs.extend(fixed);
        segs.push(bucket);
        if let Some(path) = path {
            segs.extend(path.split('/'));
        }
    }
    Ok(url)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    Read,
    Write,
}

/// Who is calling an object endpoint: a signed-in user (Storage RLS decides) or
/// an API key (this proxy confines it to its workspace folder).
enum Caller {
    User(UserToken),
    Key(ApiKeyPrincipal),
}

#[async_trait]
impl FromRequestParts<AppState> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if let Some(raw) = parts.headers.get(api_keys::API_KEY_HEADER) {
            let raw = raw
                .to_str()
                .map_err(|_| ApiError::Unauthorized("Malformed x-api-key header".into()))?;
            return Ok(Caller::Key(api_keys::authenticate(state, raw).await?));
        }
        Ok(Caller::User(UserToken::from_request_parts(parts, state).await?))
    }
}

impl Caller {
    fn cred(&self) -> Cred<'_> {
        match self {
            Caller::User(u) => Cred::User(&u.token),
            Caller::Key(_) => Cred::Service,
        }
    }

    /// Validates an object path for this caller. Keys need the matching scope and
    /// may only touch `<workspace_id>/...`.
    fn object_path(&self, path: &str, access: Access) -> ApiResult<String> {
        let path = validate_object_path(path)?;
        if let Caller::Key(key) = self {
            key.require_scope(if access == Access::Write { "storage:write" } else { "storage:read" })?;
            key_confine(key, path)?;
        }
        Ok(path.to_string())
    }

    /// Listing prefix: users pass it through; a key is pinned to its workspace folder.
    fn list_prefix(&self, prefix: &str) -> ApiResult<String> {
        let Caller::Key(key) = self else { return Ok(prefix.to_string()) };
        key.require_scope("storage:read")?;
        let prefix = prefix.trim_matches('/');
        if prefix.is_empty() {
            return Ok(key.workspace_id.to_string());
        }
        let prefix = validate_object_path(prefix)?;
        key_confine(key, prefix)?;
        Ok(prefix.to_string())
    }
}

/// `path` must be the key's workspace folder or something inside it.
fn key_confine(key: &ApiKeyPrincipal, path: &str) -> ApiResult<()> {
    let first = path.split('/').next().unwrap_or_default();
    if first.eq_ignore_ascii_case(&key.workspace_id.to_string()) {
        Ok(())
    } else {
        Err(ApiError::forbidden("API keys may only access objects under '<workspace_id>/'"))
    }
}

enum Cred<'a> {
    User(&'a str),
    Service,
}

fn authed(state: &AppState, req: reqwest::RequestBuilder, cred: Cred<'_>) -> ApiResult<reqwest::RequestBuilder> {
    Ok(match cred {
        Cred::User(token) => {
            let req = req.bearer_auth(token);
            match &state.config.supabase_anon_key {
                Some(k) => req.header("apikey", k),
                None => req,
            }
        }
        Cred::Service => {
            let key = state.config.supabase_service_role_key.as_deref().ok_or_else(|| {
                ApiError::ServiceUnavailable("SUPABASE_SERVICE_ROLE_KEY is not configured".into())
            })?;
            req.header("apikey", key).bearer_auth(key)
        }
    })
}

async fn json_response(resp: reqwest::Response) -> ApiResult<(StatusCode, Value)> {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = resp.bytes().await?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({ "message": String::from_utf8_lossy(&bytes) }))
    };
    if !status.is_success() {
        return Err(ApiError::Upstream { status, body });
    }
    Ok((status, body))
}

// --- Buckets ---------------------------------------------------------------

async fn list_buckets(State(state): State<AppState>, _admin: AdminClaims) -> ApiResult<Json<Value>> {
    let url = format!("{}/bucket", state.config.storage_url);
    let req = authed(&state, state.http.get(url), Cred::Service)?;
    let (_, body) = json_response(req.send().await?).await?;
    let prefix = format!("{}-", state.config.app_id);
    let own: Vec<Value> = body
        .as_array()
        .map(|all| {
            all.iter()
                .filter(|b| b["id"].as_str().is_some_and(|id| id.starts_with(&prefix)))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(Value::Array(own)))
}

#[derive(Deserialize)]
struct CreateBucket {
    name: String,
    #[serde(default)]
    public: bool,
    file_size_limit: Option<u64>,
    allowed_mime_types: Option<Vec<String>>,
}

async fn create_bucket(
    State(state): State<AppState>,
    _admin: AdminClaims,
    Json(body): Json<CreateBucket>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scoped_bucket(&state.config.app_id, &body.name)?;
    let url = format!("{}/bucket", state.config.storage_url);
    let payload = json!({
        "id": id, "name": id, "public": body.public,
        "file_size_limit": body.file_size_limit,
        "allowed_mime_types": body.allowed_mime_types,
    });
    let req = authed(&state, state.http.post(url).json(&payload), Cred::Service)?;
    json_response(req.send().await?).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "public": body.public }))))
}

#[derive(Deserialize)]
struct DeleteBucketQuery {
    #[serde(default)]
    force: bool,
}

async fn delete_bucket(
    State(state): State<AppState>,
    _admin: AdminClaims,
    Path(bucket): Path<String>,
    Query(q): Query<DeleteBucketQuery>,
) -> ApiResult<StatusCode> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let base = &state.config.storage_url;
    if q.force {
        let url = storage_url(base, &["bucket"], &id, Some("empty"))?;
        json_response(authed(&state, state.http.post(url), Cred::Service)?.send().await?).await?;
    }
    let url = storage_url(base, &["bucket"], &id, None)?;
    json_response(authed(&state, state.http.delete(url), Cred::Service)?.send().await?).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Objects ---------------------------------------------------------------

#[derive(Deserialize, Serialize)]
struct ListObjects {
    #[serde(default)]
    prefix: String,
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
    search: Option<String>,
}

fn default_limit() -> u32 {
    100
}

async fn list_objects(
    State(state): State<AppState>,
    caller: Caller,
    Path(bucket): Path<String>,
    Json(body): Json<ListObjects>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let prefix = caller.list_prefix(&body.prefix)?;
    let url = storage_url(&state.config.storage_url, &["object", "list"], &id, None)?;
    let payload = json!({
        "prefix": prefix, "limit": body.limit.min(1000), "offset": body.offset,
        "search": body.search, "sortBy": { "column": "name", "order": "asc" }
    });
    let req = authed(&state, state.http.post(url).json(&payload), caller.cred())?;
    Ok(Json(json_response(req.send().await?).await?.1))
}

#[derive(Deserialize)]
struct SignUpload {
    path: String,
    #[serde(default)]
    upsert: bool,
}

/// Returns a one-time URL the browser can PUT the file to directly (no proxying).
async fn sign_upload(
    State(state): State<AppState>,
    caller: Caller,
    Path(bucket): Path<String>,
    Json(body): Json<SignUpload>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = caller.object_path(&body.path, Access::Write)?;
    let path = path.as_str();
    let url = storage_url(&state.config.storage_url, &["object", "upload", "sign"], &id, Some(path))?;
    let mut req = state.http.post(url);
    if body.upsert {
        req = req.header("x-upsert", "true");
    }
    let req = authed(&state, req, caller.cred())?;
    let (_, resp) = json_response(req.send().await?).await?;
    let rel = resp["url"].as_str().unwrap_or_default();
    Ok(Json(json!({
        "signed_url": format!("{}/storage/v1{}", state.config.supabase_public_url, rel),
        "token": resp["token"],
        "path": path,
        "bucket": id,
    })))
}

#[derive(Deserialize, Serialize, Default)]
struct Transform {
    width: Option<u32>,
    height: Option<u32>,
    /// cover | contain | fill
    resize: Option<String>,
    quality: Option<u8>,
    /// origin | webp | avif
    format: Option<String>,
}

#[derive(Deserialize)]
struct SignDownload {
    path: String,
    #[serde(default = "default_expiry")]
    expires_in: u32,
    transform: Option<Transform>,
    /// `true` or a filename to force `Content-Disposition: attachment`.
    download: Option<Value>,
}

fn default_expiry() -> u32 {
    3600
}

/// Signed download URL, optionally with on-the-fly image transformation.
async fn sign_download(
    State(state): State<AppState>,
    caller: Caller,
    Path(bucket): Path<String>,
    Json(body): Json<SignDownload>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = caller.object_path(&body.path, Access::Read)?;
    let path = path.as_str();
    let url = storage_url(&state.config.storage_url, &["object", "sign"], &id, Some(path))?;
    let mut payload = json!({ "expiresIn": body.expires_in.clamp(1, 60 * 60 * 24 * 7) });
    if let Some(t) = &body.transform {
        payload["transform"] = serde_json::to_value(t).map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let req = authed(&state, state.http.post(url).json(&payload), caller.cred())?;
    let (_, resp) = json_response(req.send().await?).await?;
    let rel = resp["signedURL"].as_str().unwrap_or_default();
    let mut signed = format!("{}/storage/v1{}", state.config.supabase_public_url, rel);
    match &body.download {
        Some(Value::Bool(true)) => signed.push_str("&download="),
        Some(Value::String(name)) => {
            let encoded: String = reqwest::Url::parse_with_params("http://x/", [("download", name)])
                .map(|u| u.query().unwrap_or_default().to_string())
                .unwrap_or_default();
            signed.push('&');
            signed.push_str(&encoded);
        }
        _ => {}
    }
    Ok(Json(json!({ "signed_url": signed, "expires_in": body.expires_in })))
}

/// Streams an object back to the caller (for private files you don't want to sign).
async fn download_object(
    State(state): State<AppState>,
    caller: Caller,
    Path((bucket, path)): Path<(String, String)>,
) -> ApiResult<Response> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = caller.object_path(&path, Access::Read)?;
    let path = path.as_str();
    let url = storage_url(&state.config.storage_url, &["object", "authenticated"], &id, Some(path))?;
    let resp = authed(&state, state.http.get(url), caller.cred())?
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(json_response(resp).await.err().unwrap_or_else(|| ApiError::internal("storage error")));
    }
    let mut out = Response::builder().status(StatusCode::OK);
    for h in [header::CONTENT_TYPE, header::CONTENT_LENGTH, header::ETAG, header::CACHE_CONTROL, header::LAST_MODIFIED] {
        if let Some(v) = resp.headers().get(h.as_str()) {
            out = out.header(h, v.as_bytes());
        }
    }
    out.body(Body::from_stream(resp.bytes_stream()))
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// Streams the request body to Storage without buffering it in memory.
async fn upload_object(
    State(state): State<AppState>,
    method: Method,
    caller: Caller,
    Path((bucket, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = caller.object_path(&path, Access::Write)?;
    let path = path.as_str();
    let url = storage_url(&state.config.storage_url, &["object"], &id, Some(path))?;
    // PUT = upsert (replace), POST = create only.
    let mut req = if method == Method::PUT {
        state.http.put(url).header("x-upsert", "true")
    } else {
        state.http.post(url)
    };
    for h in [header::CONTENT_TYPE, header::CONTENT_LENGTH, header::CACHE_CONTROL] {
        if let Some(v) = headers.get(&h) {
            req = req.header(h.as_str(), v.as_bytes());
        }
    }
    let req = authed(&state, req, caller.cred())?
        .body(reqwest::Body::wrap_stream(body.into_data_stream()));
    let (status, resp) = json_response(req.send().await?).await?;
    Ok((status, Json(json!({ "bucket": id, "path": path, "result": resp }))))
}

#[derive(Deserialize)]
struct DeleteObjects {
    paths: Vec<String>,
}

async fn delete_objects(
    State(state): State<AppState>,
    caller: Caller,
    Path(bucket): Path<String>,
    Json(body): Json<DeleteObjects>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    if body.paths.is_empty() || body.paths.len() > 1000 {
        return Err(ApiError::bad_request("paths must contain 1-1000 entries"));
    }
    let paths = body
        .paths
        .iter()
        .map(|p| caller.object_path(p, Access::Write))
        .collect::<ApiResult<Vec<_>>>()?;
    let url = storage_url(&state.config.storage_url, &["object"], &id, None)?;
    let req = authed(
        &state,
        state.http.delete(url).json(&json!({ "prefixes": paths })),
        caller.cred(),
    )?;
    Ok(Json(json_response(req.send().await?).await?.1))
}

#[derive(Deserialize)]
struct ResumableInfo {
    bucket: String,
    path: String,
    #[serde(default)]
    upsert: bool,
}

/// Connection details for TUS resumable (multipart) uploads, e.g. with
/// `tus-js-client`. Files stream straight to Storage in 6 MB chunks. API keys get
/// the proxy endpoint (`/api/v1/storage/tus/:bucket`) instead, since their
/// credential must not be handed to Storage.
async fn resumable_upload_info(
    State(state): State<AppState>,
    caller: Caller,
    Json(body): Json<ResumableInfo>,
) -> ApiResult<impl IntoResponse> {
    let id = scoped_bucket(&state.config.app_id, &body.bucket)?;
    let path = caller.object_path(&body.path, Access::Write)?;
    let path = path.as_str();
    let user = match caller {
        Caller::User(u) => u,
        Caller::Key(_) => {
            return Ok(Json(json!({
                "endpoint": format!("/api/v1/storage/tus/{id}"),
                "protocol": "tus-1.0.0",
                "chunk_size": 6 * 1024 * 1024,
                "headers": { "x-upsert": body.upsert.to_string() },
                "auth": "send your x-api-key header on every TUS request",
                "metadata": { "bucketName": id, "objectName": path },
            })))
        }
    };
    let mut headers = json!({
        "authorization": format!("Bearer {}", user.token),
        "x-upsert": body.upsert.to_string(),
    });
    if let Some(k) = &state.config.supabase_anon_key {
        headers["apikey"] = json!(k);
    }
    Ok(Json(json!({
        "endpoint": format!("{}/storage/v1/upload/resumable", state.config.supabase_public_url),
        "protocol": "tus-1.0.0",
        "chunk_size": 6 * 1024 * 1024,
        "headers": headers,
        "metadata": { "bucketName": id, "objectName": path },
    })))
}

// --- TUS proxy -------------------------------------------------------------

const TUS_VERSION: &str = "1.0.0";
/// Response headers a TUS client needs to see.
const TUS_RESPONSE_HEADERS: [&str; 7] =
    ["upload-offset", "upload-length", "upload-expires", "tus-resumable", "tus-version", "tus-extension", "cache-control"];

impl Caller {
    /// The identity an upload URL is bound to.
    fn tus_principal(&self) -> String {
        match self {
            Caller::User(u) => format!("user:{}", u.claims.sub),
            Caller::Key(k) => format!("key:{}:{}", k.key_id, k.workspace_id),
        }
    }
}

fn tus_mac(secret: &str, app: &str, bucket: &str, upload_id: &str, principal: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(format!("tus|{app}|{bucket}|{upload_id}|{principal}").as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// `<base64url(upstream upload id)>.<hmac>` — stateless, so any replica can verify it.
pub fn tus_token(secret: &str, app: &str, bucket: &str, upload_id: &str, principal: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    format!("{}.{}", URL_SAFE_NO_PAD.encode(upload_id), tus_mac(secret, app, bucket, upload_id, principal))
}

pub fn tus_verify(secret: &str, app: &str, bucket: &str, token: &str, principal: &str) -> ApiResult<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bad = || ApiError::forbidden("Invalid upload URL for this caller");
    let (id_b64, mac) = token.split_once('.').ok_or_else(bad)?;
    let id = String::from_utf8(URL_SAFE_NO_PAD.decode(id_b64).map_err(|_| bad())?).map_err(|_| bad())?;
    let want = tus_mac(secret, app, bucket, &id, principal);
    // constant-time compare
    let ok = want.len() == mac.len() && want.bytes().zip(mac.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
    if !ok || id.is_empty() || id.contains('/') {
        return Err(bad());
    }
    Ok(id)
}

/// Parses TUS `Upload-Metadata` (`key base64,key2 base64`).
pub fn parse_tus_metadata(raw: &str) -> ApiResult<Vec<(String, String)>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut out = Vec::new();
    for pair in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once(' ').unwrap_or((pair, ""));
        let v = if v.is_empty() {
            String::new()
        } else {
            String::from_utf8(STANDARD.decode(v.trim()).map_err(|_| ApiError::bad_request("Upload-Metadata is not base64"))?)
                .map_err(|_| ApiError::bad_request("Upload-Metadata is not UTF-8"))?
        };
        out.push((k.to_string(), v));
    }
    Ok(out)
}

fn encode_tus_metadata(pairs: &[(String, String)]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    pairs.iter().map(|(k, v)| format!("{k} {}", STANDARD.encode(v))).collect::<Vec<_>>().join(",")
}

fn tus_relay(resp: reqwest::Response, location: Option<String>) -> ApiResult<Response> {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status).header("tus-resumable", TUS_VERSION);
    for h in TUS_RESPONSE_HEADERS {
        if let Some(v) = resp.headers().get(h) {
            out = out.header(h, v.as_bytes());
        }
    }
    if let Some(loc) = location {
        out = out.header(header::LOCATION, loc);
    }
    out = out.header("access-control-expose-headers", "Location, Upload-Offset, Upload-Length, Tus-Resumable, Upload-Expires");
    out.body(Body::from_stream(resp.bytes_stream())).map_err(|e| ApiError::internal(e.to_string()))
}

/// `POST /api/v1/storage/tus/:bucket` — TUS creation. `Upload-Metadata` must carry
/// `objectName` (and may carry `contentType`, `cacheControl`); the bucket comes from
/// the URL. Returns `Location: /api/v1/storage/tus/:bucket/<token>`.
async fn tus_create(
    State(state): State<AppState>,
    caller: Caller,
    Path(bucket): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let length = headers
        .get("upload-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or_else(|| ApiError::bad_request("Upload-Length header is required (deferred length is not supported)"))?;
    let meta = parse_tus_metadata(headers.get("upload-metadata").and_then(|v| v.to_str().ok()).unwrap_or_default())?;
    let object = meta
        .iter()
        .find(|(k, _)| k == "objectName")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| ApiError::bad_request("Upload-Metadata must include objectName"))?;
    let object = caller.object_path(&object, Access::Write)?;
    let mut forwarded = vec![("bucketName".to_string(), id.clone()), ("objectName".to_string(), object.clone())];
    forwarded.extend(meta.into_iter().filter(|(k, _)| k == "contentType" || k == "cacheControl"));

    let upsert = headers.get("x-upsert").and_then(|v| v.to_str().ok()).unwrap_or("false") == "true";
    let url = format!("{}/upload/resumable", state.config.storage_url);
    let req = state
        .http
        .post(url)
        .header("tus-resumable", TUS_VERSION)
        .header("upload-length", length.to_string())
        .header("upload-metadata", encode_tus_metadata(&forwarded))
        .header("x-upsert", upsert.to_string())
        .header(header::CONTENT_LENGTH, "0");
    let resp = authed(&state, req, caller.cred())?.send().await?;
    if resp.status().as_u16() != 201 {
        return Err(json_response(resp).await.err().unwrap_or_else(|| ApiError::internal("unexpected TUS response")));
    }
    let upstream = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|l| l.trim_end_matches('/').rsplit('/').next())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::internal("Storage returned no upload Location"))?
        .to_string();
    let token = tus_token(&state.config.supabase_jwt_secret, &state.config.app_id, &id, &upstream, &caller.tus_principal());
    tus_relay(resp, Some(format!("/api/v1/storage/tus/{bucket}/{token}")))
}

/// `HEAD | PATCH | DELETE /api/v1/storage/tus/:bucket/:token` — offset query, chunk
/// upload (streamed) and termination, for the caller the token was issued to.
async fn tus_forward(
    State(state): State<AppState>,
    method: Method,
    caller: Caller,
    Path((bucket, token)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Response> {
    if ![Method::HEAD, Method::PATCH, Method::DELETE].contains(&method) {
        return Err(ApiError::bad_request("TUS upload URLs accept HEAD, PATCH and DELETE"));
    }
    if let Caller::Key(k) = &caller {
        k.require_scope("storage:write")?;
    }
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let upstream = tus_verify(&state.config.supabase_jwt_secret, &state.config.app_id, &id, &token, &caller.tus_principal())?;
    let url = storage_url(&state.config.storage_url, &["upload", "resumable"], &upstream, None)?;
    let mut req = state
        .http
        .request(reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(), url)
        .header("tus-resumable", TUS_VERSION);
    for h in ["upload-offset", "content-type", "content-length", "upload-checksum"] {
        if let Some(v) = headers.get(h) {
            req = req.header(h, v.as_bytes());
        }
    }
    if method == Method::PATCH {
        req = req.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    }
    let resp = authed(&state, req, caller.cred())?.send().await?;
    tus_relay(resp, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tus_tokens_bind_upload_bucket_and_caller() {
        let t = tus_token("s3cret", "app1", "app1-docs", "dXBsb2Fk", "key:k1:ws1");
        // identical to the Go backend (go-backend/internal/httpapi/gaps_test.go)
        assert_eq!(t, "ZFhCc2IyRms.98fc9672f942b6a33d6cf9c18defbef1fc981002277e87bdd6193f5132100858");
        assert_eq!(tus_verify("s3cret", "app1", "app1-docs", &t, "key:k1:ws1").unwrap(), "dXBsb2Fk");
        assert!(tus_verify("s3cret", "app1", "app1-docs", &t, "key:k2:ws1").is_err(), "other caller");
        assert!(tus_verify("s3cret", "app1", "app1-other", &t, "key:k1:ws1").is_err(), "other bucket");
        assert!(tus_verify("other", "app1", "app1-docs", &t, "key:k1:ws1").is_err(), "other secret");
        assert!(tus_verify("s3cret", "app1", "app1-docs", "garbage", "key:k1:ws1").is_err());
        let (id, mac) = t.split_once('.').unwrap();
        assert!(tus_verify("s3cret", "app1", "app1-docs", &format!("{id}.{}", &mac[1..]), "key:k1:ws1").is_err());
    }

    #[test]
    fn tus_metadata_roundtrip() {
        let m = parse_tus_metadata("objectName ZGlyL2EucGRm,contentType YXBwbGljYXRpb24vcGRm,flag").unwrap();
        assert_eq!(m[0], ("objectName".into(), "dir/a.pdf".into()));
        assert_eq!(m[1].1, "application/pdf");
        assert_eq!(m[2], ("flag".into(), String::new()));
        assert_eq!(parse_tus_metadata(&encode_tus_metadata(&m[..2])).unwrap(), m[..2].to_vec());
        assert!(parse_tus_metadata("objectName !!!").is_err());
    }

    #[test]
    fn buckets_are_namespaced_per_app() {
        assert_eq!(scoped_bucket("app1", "avatars").unwrap(), "app1-avatars");
        assert_eq!(scoped_bucket("app1", "app1-avatars").unwrap(), "app1-avatars");
        assert!(scoped_bucket("app1", "Bad Name").is_err());
        assert!(scoped_bucket("app1", "").is_err());
    }

    #[test]
    fn object_paths_reject_traversal() {
        assert_eq!(validate_object_path("/u/1/a.png").unwrap(), "u/1/a.png");
        assert!(validate_object_path("u/../etc/passwd").is_err());
        assert!(validate_object_path("u//a").is_err());
        assert!(validate_object_path("").is_err());
    }

    fn key(ws: uuid::Uuid, scopes: &[&str]) -> Caller {
        Caller::Key(ApiKeyPrincipal {
            key_id: uuid::Uuid::nil(),
            workspace_id: ws,
            app_slug: "app1".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn api_keys_are_confined_to_their_workspace_folder() {
        let ws = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let k = key(ws, &["storage:read", "storage:write"]);
        assert!(k.object_path(&format!("{ws}/a/b.png"), Access::Write).is_ok());
        assert!(k.object_path(&format!("{other}/a.png"), Access::Read).is_err());
        assert!(k.object_path("a.png", Access::Read).is_err());
        assert!(k.object_path(&format!("{ws}/../{other}/a.png"), Access::Read).is_err(), "traversal rejected");
        assert_eq!(k.list_prefix("").unwrap(), ws.to_string());
        assert_eq!(k.list_prefix(&format!("/{ws}/docs/")).unwrap(), format!("{ws}/docs"));
        assert!(k.list_prefix(&other.to_string()).is_err());
    }

    #[test]
    fn api_key_scopes_gate_read_and_write() {
        let ws = uuid::Uuid::new_v4();
        let ro = key(ws, &["storage:read"]);
        assert!(ro.object_path(&format!("{ws}/a"), Access::Read).is_ok());
        assert!(ro.object_path(&format!("{ws}/a"), Access::Write).is_err());
        let none = key(ws, &["embeddings:read"]);
        assert!(none.list_prefix("").is_err());
        assert!(key(ws, &["*"]).object_path(&format!("{ws}/a"), Access::Write).is_ok());
    }

    #[test]
    fn storage_urls_are_percent_encoded() {
        let url = storage_url("http://kong:8000/storage/v1", &["object", "sign"], "app1-docs", Some("my dir/a#1.pdf")).unwrap();
        assert_eq!(url.as_str(), "http://kong:8000/storage/v1/object/sign/app1-docs/my%20dir/a%231.pdf");
    }
}
