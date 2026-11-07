//! Storage (buckets & objects) via the Supabase Storage API.
//!
//! * Bucket management uses the service role key and requires an admin caller.
//! * Object operations forward the caller's own JWT, so Storage's RLS policies
//!   on `storage.objects` decide access — identical to Supabase Cloud.
//! * Buckets are namespaced per SaaS (`<APP_ID>-<name>`) so ten apps can share
//!   one Storage service without seeing each other's files.
//! * Large uploads use the TUS resumable protocol (`/uploads/resumable`), and
//!   image transformations are applied through signed render URLs.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
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
    user: UserToken,
    Path(bucket): Path<String>,
    Json(body): Json<ListObjects>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let url = storage_url(&state.config.storage_url, &["object", "list"], &id, None)?;
    let payload = json!({
        "prefix": body.prefix, "limit": body.limit.min(1000), "offset": body.offset,
        "search": body.search, "sortBy": { "column": "name", "order": "asc" }
    });
    let req = authed(&state, state.http.post(url).json(&payload), Cred::User(&user.token))?;
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
    user: UserToken,
    Path(bucket): Path<String>,
    Json(body): Json<SignUpload>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = validate_object_path(&body.path)?;
    let url = storage_url(&state.config.storage_url, &["object", "upload", "sign"], &id, Some(path))?;
    let mut req = state.http.post(url);
    if body.upsert {
        req = req.header("x-upsert", "true");
    }
    let req = authed(&state, req, Cred::User(&user.token))?;
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
    user: UserToken,
    Path(bucket): Path<String>,
    Json(body): Json<SignDownload>,
) -> ApiResult<Json<Value>> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = validate_object_path(&body.path)?;
    let url = storage_url(&state.config.storage_url, &["object", "sign"], &id, Some(path))?;
    let mut payload = json!({ "expiresIn": body.expires_in.clamp(1, 60 * 60 * 24 * 7) });
    if let Some(t) = &body.transform {
        payload["transform"] = serde_json::to_value(t).map_err(|e| ApiError::internal(e.to_string()))?;
    }
    let req = authed(&state, state.http.post(url).json(&payload), Cred::User(&user.token))?;
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
    user: UserToken,
    Path((bucket, path)): Path<(String, String)>,
) -> ApiResult<Response> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = validate_object_path(&path)?;
    let url = storage_url(&state.config.storage_url, &["object", "authenticated"], &id, Some(path))?;
    let resp = authed(&state, state.http.get(url), Cred::User(&user.token))?
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
    user: UserToken,
    Path((bucket, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = scoped_bucket(&state.config.app_id, &bucket)?;
    let path = validate_object_path(&path)?;
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
    let req = authed(&state, req, Cred::User(&user.token))?
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
    user: UserToken,
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
        .map(|p| validate_object_path(p).map(str::to_string))
        .collect::<ApiResult<Vec<_>>>()?;
    let url = storage_url(&state.config.storage_url, &["object"], &id, None)?;
    let req = authed(
        &state,
        state.http.delete(url).json(&json!({ "prefixes": paths })),
        Cred::User(&user.token),
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
/// `tus-js-client`. Files stream straight to Storage in 6 MB chunks.
async fn resumable_upload_info(
    State(state): State<AppState>,
    user: UserToken,
    Json(body): Json<ResumableInfo>,
) -> ApiResult<impl IntoResponse> {
    let id = scoped_bucket(&state.config.app_id, &body.bucket)?;
    let path = validate_object_path(&body.path)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn storage_urls_are_percent_encoded() {
        let url = storage_url("http://kong:8000/storage/v1", &["object", "sign"], "app1-docs", Some("my dir/a#1.pdf")).unwrap();
        assert_eq!(url.as_str(), "http://kong:8000/storage/v1/object/sign/app1-docs/my%20dir/a%231.pdf");
    }
}
