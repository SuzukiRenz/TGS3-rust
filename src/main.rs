mod admin; mod auth; mod chatbot; mod cli; mod config; mod crypto; mod db; mod multipart; mod storage; mod telegram; mod util;

/// Format a unix timestamp (seconds) as an RFC 7231 IMF-fixdate string for the
/// Last-Modified header. OpenList/AWS SDK clients dereference LastModified on
/// HEAD responses, so this header must always be present.
fn httpdate_fmt(unix_secs: i64) -> String {
    use chrono::TimeZone;
    match chrono::Utc.timestamp_opt(unix_secs, 0).single() {
        Some(dt) => dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        None => "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
    }
}

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get as route_get, put as route_put},
    Router,
};
use chrono::Utc;
use clap::Parser;
use config::Config;
use db::Credential;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, pin::Pin, sync::Arc};
use tokio::fs;
use tracing::{error, info};
use util::{err, esc, hex, query_params, scope_bucket, scope_key, unscope_key, xml};

#[derive(Clone)]
pub struct App { pub cfg: Arc<Config>, pub client: reqwest::Client }

#[derive(Deserialize, Default)]
struct ListQ { prefix: Option<String>, delimiter: Option<String>, #[serde(rename = "max-keys")] max_keys: Option<usize> }

type BoxByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

fn empty_hash() -> String { hex(&Sha256::digest([])) }

/// Build a header value without ever panicking on unparseable input (a malicious or
/// malformed client-controlled string, e.g. an odd Content-Type, must not be able to
/// take the whole worker down via `.parse().unwrap()`).
fn hv(s: &str) -> HeaderValue { HeaderValue::from_str(s).unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")) }
fn resp_with_headers(status: StatusCode, pairs: Vec<(HeaderName, String)>) -> Response {
    let mut r = status.into_response();
    let hm = r.headers_mut();
    for (k, v) in pairs { hm.insert(k, hv(&v)); }
    r
}

/// Run a blocking DB call on the blocking pool and turn *both* failure modes (the
/// closure's own DbError, and the executor panicking/being cancelled) into a 500
/// response instead of letting `.unwrap()` propagate a panic into the request thread.
pub(crate) async fn db_call<T, F>(f: F) -> Result<T, Response>
where F: FnOnce() -> Result<T, db::DbError> + Send + 'static, T: Send + 'static {
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => { error!(%e, "database error"); Err(err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "Database error")) }
        Err(e) => { error!(%e, "database task panicked"); Err(err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "Internal error")) }
    }
}

pub async fn guard(method: &Method, uri: &Uri, h: &HeaderMap, payload_hash: &str, a: &App) -> Result<Credential, Response> {
    if !a.cfg.require_signature {
        return Ok(Credential { access_key: "anonymous".into(), secret_key: String::new(), is_root: true, bucket: None, prefix: String::new() });
    }
    let Some(access_key) = auth::extract_access_key(h) else {
        return Err(err(StatusCode::FORBIDDEN, "AccessDenied", "Missing or malformed Authorization header"));
    };
    let p = a.cfg.database_path.clone();
    let ak = access_key.clone();
    let cred = match db_call(move || db::cred_get(&p, &ak)).await { Ok(v) => v, Err(e) => return Err(e) };
    let Some(cred) = cred else { return Err(err(StatusCode::FORBIDDEN, "AccessDenied", "Unknown access key")); };
    if auth::authorize(method, uri, h, payload_hash, &a.cfg.region, &cred.access_key, &cred.secret_key, a.cfg.signature_skew_seconds) {
        Ok(cred)
    } else {
        Err(err(StatusCode::FORBIDDEN, "AccessDenied", "Invalid AWS Signature"))
    }
}

/// Resolve the raw 32-byte key to use for reading/writing an SSE-C or SSE-S3 object,
/// or None for a plaintext one. Shared by PUT/CreateMultipartUpload (parse_put_headers)
/// and GET/UploadPart (parse_get_headers) call sites below.
fn sse_write_key(sse: &crypto::SseRequest, master: Option<[u8; 32]>) -> Option<[u8; 32]> {
    match sse { crypto::SseRequest::None => None, crypto::SseRequest::S3 => master, crypto::SseRequest::Customer { key, .. } => Some(*key) }
}

// ---------------- bucket-level ----------------

async fn buckets(State(a): State<App>, h: HeaderMap, uri: Uri) -> Response {
    let cred = match guard(&Method::GET, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if !cred.is_root {
        let name = cred.bucket.clone().unwrap_or_default();
        return xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Buckets><Bucket><Name>{}</Name></Bucket></Buckets></ListAllMyBucketsResult>", esc(&name)));
    }
    let p = a.cfg.database_path.clone();
    match db_call(move || db::list_buckets(&p)).await {
        Ok(v) => xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListAllMyBucketsResult><Buckets>{}</Buckets></ListAllMyBucketsResult>", v.into_iter().map(|b| format!("<Bucket><Name>{}</Name></Bucket>", esc(&b))).collect::<String>())),
        Err(e) => e,
    }
}

async fn bucket(State(a): State<App>, h: HeaderMap, uri: Uri, Path(bucket): Path<String>, method: Method) -> Response {
    let cred = match guard(&method, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
    if bucket == a.cfg.admin_bucket {
        if !cred.is_root { return err(StatusCode::FORBIDDEN, "AccessDenied", "the admin bucket is root-key only"); }
        return StatusCode::OK.into_response();
    }
    let p = a.cfg.database_path.clone();
    let exists = if method == Method::PUT {
        db_call(move || db::ensure_bucket(&p, &bucket).map(|_| true)).await
    } else {
        db_call(move || db::bucket_exists(&p, &bucket)).await
    };
    match exists {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist"),
        Err(e) => e,
    }
}

async fn list(State(a): State<App>, h: HeaderMap, uri: Uri, Path(bucket): Path<String>, Query(q): Query<ListQ>) -> Response {
    let cred = match guard(&Method::GET, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
    let qp = query_params(&uri);
    if bucket == a.cfg.admin_bucket {
        if !cred.is_root { return err(StatusCode::FORBIDDEN, "AccessDenied", "the admin bucket is root-key only"); }
        return admin_list(&a).await;
    }
    if qp.contains_key("uploads") { return multipart::list_uploads(a, bucket).await; }
    let client_prefix = q.prefix.unwrap_or_default();
    let real_prefix = if cred.is_root { client_prefix.clone() } else { format!("{}{}", cred.prefix, client_prefix) };
    let delimiter = q.delimiter.unwrap_or_default();
    let max = q.max_keys.unwrap_or(1000).min(1000);
    let p = a.cfg.database_path.clone();
    let b2 = bucket.clone();
    match db_call(move || db::list_objects(&p, &b2, &real_prefix)).await {
        Ok(os) => {
            let mut contents = String::new();
            let mut common = std::collections::BTreeSet::new();
            for o in os.into_iter().take(max) {
                let visible_key = unscope_key(&cred, &o.key);
                if !delimiter.is_empty() {
                    if let Some(rest) = visible_key.strip_prefix(&client_prefix) {
                        if let Some(i) = rest.find(&delimiter) {
                            common.insert(format!("{}{}", client_prefix, &rest[..i + delimiter.len()]));
                            continue;
                        }
                    }
                }
                contents.push_str(&format!("<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>", esc(visible_key), util::rfc3339(o.updated_at), esc(&o.etag), o.size));
            }
            let cps = common.into_iter().map(|p| format!("<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", esc(&p))).collect::<String>();
            xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{}</Name><Prefix>{}</Prefix><MaxKeys>{}</MaxKeys><IsTruncated>false</IsTruncated>{}{}</ListBucketResult>", esc(&bucket), esc(&client_prefix), max, contents, cps))
        }
        Err(e) => e,
    }
}

async fn admin_list(a: &App) -> Response {
    let backups = admin::list_dir(&a.cfg.backup_dir).await;
    let recovers = admin::list_dir(&a.cfg.recover_dir).await;
    let mut contents = String::new();
    for (name, size, mtime) in backups { contents.push_str(&format!("<Contents><Key>backup/{}</Key><LastModified>{}</LastModified><Size>{}</Size></Contents>", esc(&name), util::rfc3339(mtime), size)); }
    for (name, size, mtime) in recovers { contents.push_str(&format!("<Contents><Key>recover/{}</Key><LastModified>{}</LastModified><Size>{}</Size></Contents>", esc(&name), util::rfc3339(mtime), size)); }
    xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>admin</Name><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>"))
}

/// Batch delete: POST /{bucket}?delete with an XML <Delete><Object><Key>...</Key></Object>...</Delete> body.
async fn delete_objects(State(a): State<App>, h: HeaderMap, uri: Uri, Path(bucket): Path<String>, body: Body) -> Response {
    use http_body_util::BodyExt;
    let qp = query_params(&uri);
    if !qp.contains_key("delete") { return err(StatusCode::BAD_REQUEST, "InvalidRequest", "expected ?delete"); }
    let bytes = match body.collect().await { Ok(b) => b.to_bytes(), Err(_) => return err(StatusCode::BAD_REQUEST, "InvalidRequest", "cannot read request body") };
    let payload_hash = hex(&Sha256::digest(&bytes));
    let cred = match guard(&Method::POST, &uri, &h, &payload_hash, &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
    #[derive(Deserialize, Default)] struct DeleteXml { #[serde(rename = "Object", default)] object: Vec<ObjXml> }
    #[derive(Deserialize)] struct ObjXml { #[serde(rename = "Key")] key: String }
    let body_str = String::from_utf8_lossy(&bytes);
    let req: DeleteXml = quick_xml::de::from_str(&body_str).unwrap_or_default();
    let mut result = String::new();
    for o in req.object {
        let real_key = match scope_key(&cred, &bucket, &o.key) { Ok(k) => k, Err(_) => continue };
        match do_delete(&a, &bucket, &real_key).await {
            Ok(_) => result.push_str(&format!("<Deleted><Key>{}</Key></Deleted>", esc(&o.key))),
            Err(msg) => result.push_str(&format!("<Error><Key>{}</Key><Message>{}</Message></Error>", esc(&o.key), esc(&msg))),
        }
    }
    xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult>{result}</DeleteResult>"))
}

/// Shared delete path: drop the DB row, then delete each chunk's Telegram message only
/// if no other (bucket,key) still references it (CopyObject's fast path can share).
async fn do_delete(a: &App, bucket: &str, key: &str) -> Result<(), String> {
    let p = a.cfg.database_path.clone();
    let (b2, k2) = (bucket.to_owned(), key.to_owned());
    let removed = match db_call(move || db::delete_object(&p, &b2, &k2)).await { Ok(v) => v, Err(_) => return Err("InternalError".into()) };
    let Some(chunks) = removed else { return Err("NoSuchKey".into()) };
    delete_chunks_messages(a, bucket, key, chunks).await;
    Ok(())
}

/// Delete the Telegram messages backing `chunks` unless another (bucket,key) still
/// references the same message (CopyObject's fast path can share messages). Used by
/// the DELETE path and by PUT-overwrite so replaced objects don't leak channel storage.
async fn delete_chunks_messages(a: &App, bucket: &str, key: &str, chunks: Vec<db::ChunkRef>) {
    let mut to_delete = Vec::new();
    for ch in &chunks {
        let p2 = a.cfg.database_path.clone();
        let (b3, k3, mid) = (bucket.to_owned(), key.to_owned(), ch.message_id);
        let still_ref = db_call(move || db::chunk_still_referenced(&p2, mid, &b3, &k3)).await.unwrap_or(true);
        if !still_ref { to_delete.push(ch.message_id); }
    }
    if !to_delete.is_empty() { telegram::delete_messages(&a.client, &a.cfg.bot_token, &a.cfg.chat_id, to_delete).await; }
}

// ---------------- object-level ----------------

async fn put(State(a): State<App>, h: HeaderMap, uri: Uri, Path((bucket, key)): Path<(String, String)>, body: Body) -> Response {
    let qp = query_params(&uri);
    if let (Some(uid), Some(pn)) = (qp.get("uploadId"), qp.get("partNumber")) {
        let Ok(pn) = pn.parse::<i64>() else { return err(StatusCode::BAD_REQUEST, "InvalidArgument", "partNumber must be an integer") };
        return multipart::upload_part(a, h, uri, uid.clone(), pn, body).await;
    }
    if h.get("x-amz-copy-source").is_some() { return copy_object(a, h, uri, bucket, key).await; }
    if bucket == a.cfg.admin_bucket { return admin_put(a, h, uri, key, body).await; }

    let sse = match crypto::parse_put_headers(&h) { Ok(v) => v, Err(e) => return err(StatusCode::BAD_REQUEST, "InvalidArgument", &e.to_string()) };
    if matches!(sse, crypto::SseRequest::S3) && a.cfg.sse_s3_master_key.is_none() {
        return err(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "SSE-S3 requested but SSE_S3_MASTER_KEY is not configured on this server");
    }
    let enc_key = sse_write_key(&sse, a.cfg.sse_s3_master_key);
    let staged = match storage::stage(body, &a.cfg, enc_key.as_ref(), a.cfg.max_object_size).await {
        Ok(s) => s,
        Err(storage::StageError::TooLarge) => return err(StatusCode::PAYLOAD_TOO_LARGE, "EntityTooLarge", "Object exceeds MAX_OBJECT_SIZE"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "Cannot stage object body"),
    };
    let cred = match guard(&Method::PUT, &uri, &h, &staged.sha256_hex, &a).await {
        Ok(c) => c,
        Err(e) => { storage::cleanup(&staged).await; return e; }
    };
    if let Err(e) = scope_bucket(&cred, &bucket) { storage::cleanup(&staged).await; return e; }
    let (real_key, real_key2) = match scope_key(&cred, &bucket, &key) { Ok(k) => (k.clone(), k), Err(e) => { storage::cleanup(&staged).await; return e; } };
    let real_key_for_meta = real_key.clone();
    let ct = h.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_owned();
    let filename = key.rsplit('/').next().unwrap_or(&key).to_owned();
    let chunks = match storage::upload(&a.client, &a.cfg, &staged.chunks, 0, &filename, &ct, true).await {
        Ok(c) => c,
        Err(e) => { error!(%e, "telegram upload failed"); return err(StatusCode::BAD_GATEWAY, "TelegramError", "Telegram upload failed"); }
    };
    let etag = staged.sha256_hex;
    let (sse_alg, sse_md5) = match &sse {
        crypto::SseRequest::None => (None, None),
        crypto::SseRequest::S3 => (Some("AES256".to_owned()), None),
        crypto::SseRequest::Customer { key_md5, .. } => (Some("AES256".to_owned()), Some(key_md5.clone())),
    };
    let o = db::ObjectMeta { bucket: bucket.clone(), key: real_key_for_meta, size: staged.total_size, content_type: ct, etag: etag.clone(), updated_at: Utc::now().timestamp(), sse_algorithm: sse_alg.clone(), sse_customer_key_md5: sse_md5 };
    let p = a.cfg.database_path.clone();
    let chunks_for_rollback = chunks.clone();
    // Capture the OLD chunk list before put_object replaces the rows, so the replaced
    // object's Telegram messages can be purged after a successful overwrite.
    let old_chunks = match db_call({ let p2 = a.cfg.database_path.clone(); let b2 = bucket.clone(); let k2 = real_key.clone(); move || db::get_chunks(&p2, &b2, &k2) }).await {
        Ok(c) => c,
        Err(_) => Vec::new(), // best-effort: overwrite still proceeds without the purge
    };
    let was_overwrite = !old_chunks.is_empty();
    match db_call(move || db::put_object(&p, &o, &chunks)).await {
        Ok(_) => {
            if was_overwrite {
                delete_chunks_messages(&a, &bucket, &real_key2, old_chunks).await;
            }
            let mut hdrs = vec![(axum::http::header::ETAG, format!("\"{etag}\""))];
            if let Some(alg) = &sse_alg { hdrs.push((HeaderName::from_static("x-amz-server-side-encryption"), alg.clone())); }
            resp_with_headers(StatusCode::OK, hdrs)
        }
        Err(e) => {
            // The Telegram messages already exist but the metadata write failed: clean
            // them up so the request doesn't leak storage on failure.
            storage::rollback_uploaded(&a.client, &a.cfg, &chunks_for_rollback).await;
            e
        }
    }
}

async fn admin_put(a: App, h: HeaderMap, uri: Uri, key: String, body: Body) -> Response {
    use http_body_util::BodyExt;
    let bytes = match body.collect().await { Ok(b) => b.to_bytes(), Err(_) => return err(StatusCode::BAD_REQUEST, "InvalidRequest", "cannot read request body") };
    let payload_hash = hex(&Sha256::digest(&bytes));
    let cred = match guard(&Method::PUT, &uri, &h, &payload_hash, &a).await { Ok(c) => c, Err(e) => return e };
    if !cred.is_root { return err(StatusCode::FORBIDDEN, "AccessDenied", "the admin bucket is root-key only"); }
    let Some(name) = key.strip_prefix("recover/") else {
        return err(StatusCode::FORBIDDEN, "AccessDenied", "admin/backup/ is written by the scheduled backup job only; use admin/recover/<file> to restore");
    };
    if name.is_empty() || name.contains('/') { return err(StatusCode::BAD_REQUEST, "InvalidArgument", "upload a single file directly under admin/recover/"); }
    if let Err(e) = fs::create_dir_all(&a.cfg.recover_dir).await { error!(%e, "mkdir recover_dir"); return err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "cannot create recover dir"); }
    let dest = a.cfg.recover_dir.join(name);
    if let Err(e) = fs::write(&dest, &bytes).await { error!(%e, "write recover upload"); return err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "cannot stage recover upload"); }
    match admin::recover_from(&a.cfg, &dest).await {
        Ok(_) => { let _ = fs::remove_file(&dest).await; StatusCode::OK.into_response() }
        Err(msg) => { let _ = fs::remove_file(&dest).await; err(StatusCode::BAD_REQUEST, "InvalidArgument", &msg) }
    }
}

async fn copy_object(a: App, h: HeaderMap, uri: Uri, dst_bucket: String, dst_key: String) -> Response {
    let cred = match guard(&Method::PUT, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &dst_bucket) { return e; }
    let real_dst_key = match scope_key(&cred, &dst_bucket, &dst_key) { Ok(k) => k, Err(e) => return e };
    let src_hdr = h.get("x-amz-copy-source").and_then(|v| v.to_str().ok()).unwrap_or("");
    let decoded = urlencoding::decode(src_hdr.trim_start_matches('/')).unwrap_or_default().into_owned();
    let mut parts = decoded.splitn(2, '/');
    let (src_bucket, src_key_client) = match (parts.next(), parts.next()) {
        (Some(b), Some(k)) if !b.is_empty() && !k.is_empty() => (b.to_owned(), k.to_owned()),
        _ => return err(StatusCode::BAD_REQUEST, "InvalidArgument", "x-amz-copy-source must look like /bucket/key"),
    };
    if let Err(e) = scope_bucket(&cred, &src_bucket) { return e; }
    let real_src_key = match scope_key(&cred, &src_bucket, &src_key_client) { Ok(k) => k, Err(e) => return e };
    let directive_replace = h.get("x-amz-metadata-directive").and_then(|v| v.to_str().ok()) == Some("REPLACE");
    let new_ct = if directive_replace { h.get("content-type").and_then(|v| v.to_str().ok()).map(|s| s.to_owned()) } else { None };
    let p = a.cfg.database_path.clone();
    let (b, k) = (src_bucket.clone(), real_src_key.clone());
    let src_meta = match db_call(move || db::get_object(&p, &b, &k)).await {
        Ok(Some(m)) => m,
        Ok(None) => return err(StatusCode::NOT_FOUND, "NoSuchKey", "source object does not exist"),
        Err(e) => return e,
    };
    if src_meta.sse_customer_key_md5.is_some() {
        return err(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "copying an SSE-C encrypted object is not supported yet; download and re-upload it instead");
    }
    let now = Utc::now().timestamp();
    let p2 = a.cfg.database_path.clone();
    match db_call(move || db::copy_object_fastpath(&p2, &src_bucket, &real_src_key, &dst_bucket, &real_dst_key, new_ct.as_deref(), now)).await {
        Ok(Some(dst)) => xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><CopyObjectResult><ETag>&quot;{}&quot;</ETag><LastModified>{}</LastModified></CopyObjectResult>", esc(&dst.etag), util::rfc3339(now))),
        Ok(None) => err(StatusCode::NOT_FOUND, "NoSuchKey", "source object does not exist"),
        Err(e) => e,
    }
}

fn parse_range(h: &HeaderMap, total: i64) -> Option<(i64, i64)> {
    let v = h.get(axum::http::header::RANGE)?.to_str().ok()?;
    let v = v.strip_prefix("bytes=")?;
    let (s, e) = v.split_once('-')?;
    if s.is_empty() {
        let suffix: i64 = e.parse().ok()?;
        if suffix <= 0 { return None; }
        return Some(((total - suffix).max(0), total - 1));
    }
    let start: i64 = s.parse().ok()?;
    let end: i64 = if e.is_empty() { total - 1 } else { e.parse().ok()? };
    if start > end || start >= total || total == 0 { return None; }
    Some((start, end.min(total - 1)))
}

fn sse_read_key(o: &db::ObjectMeta, h: &HeaderMap, master: Option<[u8; 32]>) -> Result<Option<[u8; 32]>, Response> {
    let supplied = crypto::parse_get_headers(h).map_err(|e| err(StatusCode::BAD_REQUEST, "InvalidArgument", &e.to_string()))?;
    match (&o.sse_algorithm, &o.sse_customer_key_md5, supplied) {
        (None, _, _) => Ok(None),
        (Some(_), Some(stored_md5), Some((k, supplied_md5))) => {
            if &supplied_md5 != stored_md5 { return Err(err(StatusCode::FORBIDDEN, "AccessDenied", "supplied SSE-C key does not match the object")); }
            Ok(Some(k))
        }
        (Some(_), Some(_), None) => Err(err(StatusCode::BAD_REQUEST, "InvalidRequest", "this object requires matching x-amz-server-side-encryption-customer-* headers to read")),
        (Some(_), None, _) => match master {
            Some(k) => Ok(Some(k)),
            None => Err(err(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "SSE-S3 master key not configured; cannot decrypt this object")),
        },
    }
}

async fn get(State(a): State<App>, h: HeaderMap, uri: Uri, Path((bucket, key)): Path<(String, String)>) -> Response {
    let cred = match guard(&Method::GET, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
    if bucket == a.cfg.admin_bucket {
        if !cred.is_root { return err(StatusCode::FORBIDDEN, "AccessDenied", "the admin bucket is root-key only"); }
        return admin_get(&a, &key).await;
    }
    let qp = query_params(&uri);
    let real_key = match scope_key(&cred, &bucket, &key) { Ok(k) => k, Err(e) => return e };
    if qp.contains_key("uploadId") {
        let uid = qp.get("uploadId").cloned().unwrap_or_default();
        return multipart::list_parts(a, uid).await;
    }
    let p = a.cfg.database_path.clone();
    let (b2, k2) = (bucket.clone(), real_key.clone());
    let o = match db_call(move || db::get_object(&p, &b2, &k2)).await {
        Ok(Some(o)) => o,
        Ok(None) => return err(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist"),
        Err(e) => return e,
    };
    let key_bytes = match sse_read_key(&o, &h, a.cfg.sse_s3_master_key) { Ok(v) => v, Err(e) => return e };
    let p2 = a.cfg.database_path.clone();
    let (b3, k3) = (bucket.clone(), real_key.clone());
    let chunks = match db_call(move || db::get_chunks(&p2, &b3, &k3)).await { Ok(c) => c, Err(e) => return e };
    let (start, end, partial) = match parse_range(&h, o.size) { Some((s, e)) => (s, e, true), None => (0, (o.size - 1).max(0), false) };

    let mut cum = 0i64;
    let mut streams: Vec<BoxByteStream> = Vec::new();
    // Concurrent prefetch design: each chunk's getFile + TLS handshake + response
    // head runs as a background task, bounded by DOWNLOAD_PERMITS (CONCURRENCY, de-
    // fault 6). The client still observes strict chunk order -- streams are flattened
    // in chunk order -- prefetching only moves handshake latency off the critical
    // path, so chunk N+1's connection is already up by the time chunk N finishes.
    for ch in &chunks {
        let chunk_start = cum;
        let chunk_end = cum + ch.size - 1;
        cum += ch.size;
        if o.size == 0 { break; }
        if chunk_end < start || chunk_start > end { continue; }
        let lo = (start - chunk_start).max(0);
        let hi = (end - chunk_start).min(ch.size - 1);
        // Encrypted chunks need the *whole* chunk downloaded to verify the GCM tag
        // before any of it can be trusted, so partial-range forwarding to Telegram
        // only applies to plaintext objects; the slice to the client still respects
        // [lo,hi]. Chunk size is capped at CHUNK_SIZE_BYTES, so this stays bounded.
        let need_range = key_bytes.is_none() && !(lo == 0 && hi == ch.size - 1);
        let client = a.client.clone();
        let cfg = a.cfg.clone();
        let file_id = ch.file_id.clone();
        let key_for_chunk = key_bytes;
        // Prefetch connection setup (getFile pacing + TLS + response head) in the
        // background, bounded by DOWNLOAD_PERMITS so at most CONCURRENCY chunks are
        // connecting at once -- the response-head loop below never blocks on prefetch
        // completion, so TTFB stays at chunk #1's handshake, not the last. The oneshot
        // hands the already-connected stream to the async_stream whenever the client's
        // consumption reaches this chunk. Client-visible order is unchanged: streams
        // are still flattened in chunk order.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(BoxByteStream, bool), std::io::Error>>();
        let want_range = if need_range { Some((lo as u64, hi as u64)) } else { None };
        tokio::spawn(async move {
            let permit = telegram::DOWNLOAD_PERMITS.acquire().await;
            let res = async {
                let cs = telegram::download_chunk_stream(&client, &cfg.bot_token, &file_id, want_range)
                    .await
                    .map_err(std::io::Error::other)?;
                // Coerce reqwest's stream error type (reqwest::Error) into the
                // response-stream error type (std::io::Error) box-for-box.
                let mapped = cs.stream.map(|r| r.map_err(std::io::Error::other));
                Ok::<_, std::io::Error>((Box::pin(mapped) as BoxByteStream, cs.ranged))
            };
            let out = res.await;
            drop(permit);
            let _ = ready_tx.send(out);
        });
        let s = async_stream::try_stream! {
            let (stream, ranged) = match ready_rx.await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => Err(e)?,
                Err(_) => Err(std::io::Error::other("download worker dropped"))?,
            };
            let mut stream = stream;
            if let Some(key) = key_for_chunk {
                // GCM: buffer the whole (already ranged to full chunk) body, then decrypt.
                let mut whole = Vec::new();
                while let Some(chunk) = stream.next().await {
                    whole.extend_from_slice(&chunk.map_err(std::io::Error::other)?);
                }
                let plain = crypto::decrypt_chunk(&key, &whole).map_err(std::io::Error::other)?;
                let hi_clamped = (hi as usize).min(plain.len().saturating_sub(1));
                if (lo as usize) <= hi_clamped { yield Bytes::copy_from_slice(&plain[lo as usize..=hi_clamped]); }
            } else if need_range && ranged {
                // Server honored Range (HTTP 206): stream already starts at `lo`,
                // just stop after (hi - lo + 1) bytes.
                let mut remaining = (hi - lo + 1) as u64;
                while remaining > 0 {
                    let chunk = match stream.next().await {
                        Some(c) => c.map_err(std::io::Error::other)?,
                        None => break,
                    };
                    let take = remaining.min(chunk.len() as u64) as usize;
                    yield chunk.slice(..take);
                    remaining -= take as u64;
                }
            } else if need_range {
                // Server ignored Range (HTTP 200): skip `lo` bytes client-side and stop
                // after (hi - lo + 1) bytes. Correct regardless of Telegram's behavior.
                let mut skip = lo as u64;
                let mut remaining = (hi - lo + 1) as u64;
                while remaining > 0 {
                    let chunk = match stream.next().await {
                        Some(c) => c.map_err(std::io::Error::other)?,
                        None => break,
                    };
                    let clen = chunk.len() as u64;
                    if skip >= clen { skip -= clen; continue; }
                    let take = remaining.min(clen - skip);
                    let out = chunk.slice((skip as usize)..((skip + take) as usize));
                    skip = 0;
                    remaining -= take;
                    yield out;
                }
            } else {
                while let Some(chunk) = stream.next().await {
                    yield chunk.map_err(std::io::Error::other)?;
                }
            }
        };
        streams.push(Box::pin(s));
    }
    let combined = futures_util::stream::iter(streams).flatten();
    let mut response = Body::from_stream(combined).into_response();
    *response.status_mut() = if partial { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK };
    let hm = response.headers_mut();
    hm.insert(axum::http::header::CONTENT_TYPE, hv(&o.content_type));
    hm.insert(axum::http::header::ETAG, hv(&format!("\"{}\"", o.etag)));
    hm.insert(axum::http::header::LAST_MODIFIED, hv(&httpdate_fmt(o.updated_at)));
    hm.insert(axum::http::header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if partial {
        hm.insert(axum::http::header::CONTENT_RANGE, hv(&format!("bytes {}-{}/{}", start, end, o.size)));
        hm.insert(axum::http::header::CONTENT_LENGTH, hv(&(end - start + 1).to_string()));
    } else {
        hm.insert(axum::http::header::CONTENT_LENGTH, hv(&o.size.to_string()));
    }
    if let Some(alg) = &o.sse_algorithm { hm.insert(HeaderName::from_static("x-amz-server-side-encryption"), hv(alg)); }
    response
}

async fn admin_get(a: &App, key: &str) -> Response {
    let (dir, name) = if let Some(n) = key.strip_prefix("backup/") { (&a.cfg.backup_dir, n) } else if let Some(n) = key.strip_prefix("recover/") { (&a.cfg.recover_dir, n) } else { return err(StatusCode::NOT_FOUND, "NoSuchKey", "expected admin/backup/<file> or admin/recover/<file>") };
    match fs::read(dir.join(name)).await {
        Ok(bytes) => ([(axum::http::header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "NoSuchKey", "not found"),
    }
}

async fn head(State(a): State<App>, h: HeaderMap, uri: Uri, Path((bucket, key)): Path<(String, String)>) -> Response {
    let cred = match guard(&Method::HEAD, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
    if bucket == a.cfg.admin_bucket {
        if !cred.is_root { return err(StatusCode::FORBIDDEN, "AccessDenied", "the admin bucket is root-key only"); }
        return StatusCode::OK.into_response();
    }
    let real_key = match scope_key(&cred, &bucket, &key) { Ok(k) => k, Err(e) => return e };
    let p = a.cfg.database_path.clone();
    match db_call(move || db::get_object(&p, &bucket, &real_key)).await {
        Ok(Some(o)) => {
            let mut hdrs = vec![(axum::http::header::CONTENT_LENGTH, o.size.to_string()), (axum::http::header::CONTENT_TYPE, o.content_type), (axum::http::header::ETAG, format!("\"{}\"", o.etag)), (axum::http::header::LAST_MODIFIED, httpdate_fmt(o.updated_at))];
            if let Some(alg) = &o.sse_algorithm { hdrs.push((HeaderName::from_static("x-amz-server-side-encryption"), alg.clone())); }
            resp_with_headers(StatusCode::OK, hdrs)
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist"),
        Err(e) => e,
    }
}

async fn delete_obj(State(a): State<App>, h: HeaderMap, uri: Uri, Path((bucket, key)): Path<(String, String)>) -> Response {
    let cred = match guard(&Method::DELETE, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
    if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
    let qp = query_params(&uri);
    if let Some(uid) = qp.get("uploadId") { return multipart::abort(a, uid.clone()).await; }
    if bucket == a.cfg.admin_bucket {
        if !cred.is_root { return err(StatusCode::FORBIDDEN, "AccessDenied", "the admin bucket is root-key only"); }
        let (dir, name) = if let Some(n) = key.strip_prefix("backup/") { (&a.cfg.backup_dir, n) } else if let Some(n) = key.strip_prefix("recover/") { (&a.cfg.recover_dir, n) } else { return err(StatusCode::NOT_FOUND, "NoSuchKey", "not found"); };
        return match fs::remove_file(dir.join(name)).await { Ok(_) => StatusCode::NO_CONTENT.into_response(), Err(_) => err(StatusCode::NOT_FOUND, "NoSuchKey", "not found") };
    }
    let real_key = match scope_key(&cred, &bucket, &key) { Ok(k) => k, Err(e) => return e };
    match do_delete(&a, &bucket, &real_key).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "NoSuchKey", "The specified key does not exist"),
    }
}

async fn post_object(State(a): State<App>, h: HeaderMap, uri: Uri, Path((bucket, key)): Path<(String, String)>, body: Body) -> Response {
    let qp = query_params(&uri);
    if qp.contains_key("uploads") {
        let cred = match guard(&Method::POST, &uri, &h, &empty_hash(), &a).await { Ok(c) => c, Err(e) => return e };
        if let Err(e) = scope_bucket(&cred, &bucket) { return e; }
        let real_key = match scope_key(&cred, &bucket, &key) { Ok(k) => k, Err(e) => return e };
        return multipart::create(a, cred, h, bucket, real_key, key).await;
    }
    if let Some(uid) = qp.get("uploadId") { return multipart::complete(a, h, uri, uid.clone(), body).await; }
    err(StatusCode::BAD_REQUEST, "InvalidRequest", "unsupported POST on object")
}

// ---------------- CLI / bootstrap ----------------

pub(crate) fn rand_hex(n: usize) -> String { use rand::RngCore; let mut b = vec![0u8; n]; rand::thread_rng().fill_bytes(&mut b); b.iter().map(|x| format!("{x:02x}")).collect() }

async fn bootstrap_root_key(c: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let p = c.database_path.clone();
    let count = tokio::task::spawn_blocking({ let p = p.clone(); move || db::cred_count(&p) }).await??;
    if count > 0 { return Ok(()); }
    let access_key = format!("root{}", rand_hex(10));
    let secret_key = rand_hex(30);
    let (p2, ak, sk) = (p.clone(), access_key.clone(), secret_key.clone());
    tokio::task::spawn_blocking(move || db::cred_insert(&p2, &ak, &sk, true, None, "")).await??;
    if let Some(dir) = c.database_path.parent() {
        let path = dir.join("ROOT_CREDENTIALS.txt");
        let contents = format!(
            "# tg-s3-bot root credentials (generated once on first boot)\n\
             S3_ACCESS_KEY_ID={access_key}\n\
             S3_SECRET_ACCESS_KEY={secret_key}\n\
             S3_REGION={}\n\
             \n\
             # The root key has no bucket restriction. A bucket named \"default\" was\n\
             # created automatically -- use it, or PUT any other bucket name to create it.\n\
             #\n\
             # Reserved: the \"{}\" bucket is admin-only (scheduled backups live under\n\
             # {}/backup/, restore by PUTting a file to {}/recover/). Change its name\n\
             # with the ADMIN_BUCKET env var if you need a bucket called \"{}\" for real data.\n\
             #\n\
             # To create a scoped key confined to one bucket+prefix:\n\
             #   docker compose exec tg-s3-bot tg-s3-bot credential add <bucket> --prefix <prefix>/\n\
             #   docker compose exec tg-s3-bot tg-s3-bot credential list\n\
             #   docker compose exec tg-s3-bot tg-s3-bot credential rm <access_key>\n",
            c.region, c.admin_bucket, c.admin_bucket, c.admin_bucket, c.admin_bucket
        );
        fs::write(&path, contents).await?;
        info!(path = ?path, "root access key generated on first boot; secret is in this file, not in the logs");
    }
    Ok(())
}

async fn run_credential_cmd(c: &Config, action: cli::CredAction) -> Result<(), Box<dyn std::error::Error>> {
    let p = c.database_path.clone();
    match action {
        cli::CredAction::Add { bucket, prefix } => {
            if bucket == c.admin_bucket {
                println!("refusing: '{}' is the reserved admin bucket name (ADMIN_BUCKET); scoped keys cannot be bound to it", c.admin_bucket);
                return Ok(());
            }
            let access_key = format!("key{}", rand_hex(8));
            let secret_key = rand_hex(30);
            let (p2, ak, sk, b, pr) = (p.clone(), access_key.clone(), secret_key.clone(), bucket.clone(), prefix.clone());
            tokio::task::spawn_blocking(move || db::cred_insert(&p2, &ak, &sk, false, Some(&b), &pr)).await??;
            println!("access_key: {access_key}\nsecret_key: {secret_key}\nbucket: {bucket}\nprefix: {prefix}");
        }
        cli::CredAction::List => {
            let creds = tokio::task::spawn_blocking(move || db::cred_list(&p)).await??;
            for cr in creds { println!("{}{}  bucket={:?} prefix={:?}", if cr.is_root { "[root] " } else { "" }, cr.access_key, cr.bucket, cr.prefix); }
        }
        cli::CredAction::Rm { access_key } => {
            let removed = tokio::task::spawn_blocking(move || db::cred_remove(&p, &access_key)).await??;
            println!("{}", if removed { "removed" } else { "not found (or is the root key, which cannot be removed this way)" });
        }
        cli::CredAction::Rotate { access_key } => {
            let secret_key = rand_hex(30);
            let (p2, ak, sk) = (p.clone(), access_key.clone(), secret_key.clone());
            let rotated = tokio::task::spawn_blocking(move || db::cred_rotate(&p2, &ak, &sk)).await??;
            if !rotated { println!("not found"); return Ok(()); }
            sync_root_credentials_file(c, &access_key, None, &secret_key).await;
            println!("rotated: new secret generated (access_key unchanged)\nsecret_key: {secret_key}");
        }
        cli::CredAction::Rekey { access_key } => {
            let new_access_key = if access_key.starts_with("root") { format!("root{}", rand_hex(10)) } else { format!("key{}", rand_hex(8)) };
            let secret_key = rand_hex(30);
            let (p2, ak_old, ak_new, sk) = (p.clone(), access_key.clone(), new_access_key.clone(), secret_key.clone());
            let rekeyed = tokio::task::spawn_blocking(move || db::cred_rekey(&p2, &ak_old, &ak_new, &sk)).await??;
            if !rekeyed { println!("not found"); return Ok(()); }
            sync_root_credentials_file(c, &access_key, Some(&new_access_key), &secret_key).await;
            println!("rekeyed: old credentials are gone\naccess_key: {new_access_key}\nsecret_key: {secret_key}");
        }
    }
    Ok(())
}

/// Keep /data/.../ROOT_CREDENTIALS.txt in step with root-key rotate/rekey so the
/// on-disk memo never shows a stale secret. Non-root keys leave the file untouched.
pub(crate) async fn sync_root_credentials_file(c: &Config, old_access_key: &str, new_access_key: Option<&str>, new_secret: &str) {
    let Some(dir) = c.database_path.parent() else { return };
    let path = dir.join("ROOT_CREDENTIALS.txt");
    let Ok(contents) = fs::read_to_string(&path).await else { return };
    if !contents.contains(old_access_key) { return; } // not the root key's memo
    let mut out = String::with_capacity(contents.len());
    for line in contents.lines() {
        let line = if let Some(rest) = line.strip_prefix("S3_ACCESS_KEY_ID=") {
            match new_access_key { Some(nk) if rest == old_access_key => format!("S3_ACCESS_KEY_ID={nk}"), _ => line.to_owned() }
        } else if let Some(rest) = line.strip_prefix("S3_SECRET_ACCESS_KEY=") {
            format!("S3_SECRET_ACCESS_KEY={new_secret}")
        } else { line.to_owned() };
        out.push_str(&line); out.push('\n');
    }
    let _ = fs::write(&path, out).await;
    info!(path = ?path, "ROOT_CREDENTIALS.txt updated to match rotated root key");
}

async fn show_root_key(c: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let p = c.database_path.clone();
    let creds = tokio::task::spawn_blocking(move || db::cred_list(&p)).await??;
    match creds.into_iter().find(|c| c.is_root) {
        Some(root) => println!("access_key: {}\nsecret_key: {}", root.access_key, root.secret_key),
        None => println!("no root key found"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    let cli = cli::Cli::parse();
    let c = Config::from_env()?;
    fs::create_dir_all(&c.temp_dir).await?;
    fs::create_dir_all(&c.backup_dir).await?;
    fs::create_dir_all(&c.recover_dir).await?;
    if let Some(parent) = c.database_path.parent() { fs::create_dir_all(parent).await?; }
    db::init(&c.database_path)?;
    bootstrap_root_key(&c).await?;

    match cli.cmd {
        Some(cli::Cmd::Credential { action }) => return run_credential_cmd(&c, action).await,
        Some(cli::Cmd::RootKey) => return show_root_key(&c).await,
        Some(cli::Cmd::Backup) => {
            let p = admin::backup_now(&c).await.map_err(std::io::Error::other)?;
            println!("backup written to {}", p.display());
            return Ok(());
        }
        Some(cli::Cmd::Recover { file }) => {
            admin::recover_from(&c, &PathBuf::from(file)).await.map_err(std::io::Error::other)?;
            println!("restored");
            return Ok(());
        }
        Some(cli::Cmd::Serve) | None => {}
    }

    let a = App { cfg: Arc::new(c.clone()), client: reqwest::Client::builder().build()? };
    // Orphan sweep: any stage dir left in TEMP_DIR from a crash mid-multipart is
    // garbage (nothing references it -- in-flight uploads only survive inside a
    // request handler). Safe to remove everything at boot, before serving.
    match fs::read_dir(&c.temp_dir).await {
        Ok(mut rd) => {
            let mut n = 0u32;
            while let Ok(Some(e)) = rd.next_entry().await {
                if e.path().is_dir() { let _ = fs::remove_dir_all(e.path()).await; n += 1; }
            }
            if n > 0 { info!("orphan sweep: removed {n} stale stage dirs from {}", c.temp_dir.display()); }
        }
        Err(_) => {}
    }
    tokio::spawn(admin::run_scheduler(a.cfg.clone()));
    chatbot::spawn(a.client.clone(), a.cfg.clone()); // in-chat admin CLI (no-op unless TGBOT_ADMINS is set)
    let r = Router::new()
        .route("/", route_get(buckets))
        .route("/{bucket}", route_get(list).put(bucket).head(bucket).post(delete_objects))
        .route("/{bucket}/{*key}", route_put(put).get(get).delete(delete_obj).head(head).post(post_object))
        .with_state(a);
    let l = tokio::net::TcpListener::bind(c.bind).await?;
    info!(addr = %c.bind, "tg-s3-bot started");
    axum::serve(l, r).await?;
    Ok(())
}
