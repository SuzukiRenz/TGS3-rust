use reqwest::Client;
use serde::Deserialize;
use futures_util::Stream;
use std::{path::{Path, PathBuf}, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::Semaphore;

const API_BASE: &str = "https://api.telegram.org";
const MAX_RETRIES: u32 = 5;
const DELETE_CONCURRENCY: usize = 10;

#[derive(Debug, Error)]
pub enum TgError {
    #[error("telegram request failed: {0}")] Http(String),
    #[error("telegram API error: {0}")] Api(String),
}
#[derive(Deserialize)] struct ApiResponse<T> { ok: bool, result: Option<T>, description: Option<String> }
#[derive(Deserialize)] pub struct FileInfo { pub file_path: Option<String> }

pub struct Uploaded { pub file_id: String, pub message_id: i64, pub size: i64 }

/// Telegram returns HTTP 429 with `{"parameters":{"retry_after":N}}` when rate limited.
/// Trust either the HTTP status or the body's error_code, default to 3s, cap at 60s so a
/// hostile/buggy value can't stall an upload indefinitely.
fn retry_after_secs(status: u16, body: &serde_json::Value) -> Option<u64> {
    let limited = status == 429 || body["error_code"].as_i64() == Some(429);
    if !limited { return None; }
    Some(body.get("parameters").and_then(|p| p.get("retry_after")).and_then(|v| v.as_u64()).unwrap_or(3).min(60))
}

/// Redact the bot token from an error string. reqwest's error Display includes the
/// full request URL, and the token lives in the path -- letting that reach logs or an
/// HTTP response leaks the credential.
fn scrub(token: &str, s: String) -> String { if token.is_empty() { s } else { s.replace(token, "<token>") } }

/// Extract (file_id, size) from a Telegram Message. Telegram may auto-convert
/// sendDocument/sendMediaGroup payloads with a recognizable media type: a real
/// MP4 becomes a ``video`` message, MP3 an ``audio``, GIF an ``animation`` --
/// the ``document`` field is then absent and only parsing it yields an empty
/// file_id, which bricks every later download (GET -> 500). Accept any media
/// field that carries a file_id.
fn extract_uploaded(msg: &serde_json::Value) -> Uploaded {
    let message_id = msg.get("message_id").and_then(|v| v.as_i64()).unwrap_or(0);
    for field in ["document", "video", "audio", "animation", "video_note"] {
        if let Some(doc) = msg.get(field) {
            let file_id = doc.get("file_id").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
            if !file_id.is_empty() {
                let size = doc.get("file_size").and_then(|v| v.as_i64()).unwrap_or(0);
                return Uploaded { file_id, message_id, size };
            }
        }
    }
    Uploaded { file_id: String::new(), message_id, size: 0 }
}

/// Upload a single chunk file as a Telegram document, retrying on transient network
/// errors and on 429 rate limiting (honoring `retry_after`).
pub async fn upload(client: &Client, token: &str, chat: &str, path: &Path, filename: &str, content_type: &str) -> Result<Uploaded, TgError> {
    let url = format!("{API_BASE}/bot{token}/sendDocument");
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let part = match reqwest::multipart::Part::file(path).await {
            Ok(p) => p.file_name(filename.to_owned()).mime_str(content_type).map_err(|e| TgError::Api(e.to_string()))?,
            Err(e) => return Err(TgError::Http(scrub(token, e.to_string()))),
        };
        let form = reqwest::multipart::Form::new().text("chat_id", chat.to_owned()).part("document", part);
        let resp = match client.post(&url).multipart(form).send().await {
            Ok(r) => r,
            Err(e) => {
                if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; }
                return Err(TgError::Http(scrub(token, e.to_string())));
            }
        };
        let status = resp.status().as_u16();
        let data: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => { if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; } return Err(TgError::Http(e.to_string())); }
        };
        if data["ok"].as_bool() == Some(true) {
            let msg = data.get("result").cloned().unwrap_or_default();
            return Ok(extract_uploaded(&msg));
        }
        if let Some(wait) = retry_after_secs(status, &data) {
            if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(wait)).await; continue; }
        }
        return Err(TgError::Api(data["description"].as_str().unwrap_or("unknown error").to_owned()));
    }
}

pub struct AlbumItem { pub path: PathBuf, pub filename: String }

/// sendMediaGroup: 2..=10 documents per call, result order matches input order.
/// Albums let small multipart parts (e.g. OpenList's fixed 5MB S3 parts) land as one
/// tidy channel block instead of one message per part. Each item keeps its filename,
/// so `name.part00042` styling stays visible inside the album.
pub async fn upload_album(client: &Client, token: &str, chat: &str, items: &[AlbumItem], content_type: &str) -> Result<Vec<Uploaded>, TgError> {
    debug_assert!((2..=10).contains(&items.len()), "sendMediaGroup accepts 2..=10 items");
    let url = format!("{API_BASE}/bot{token}/sendMediaGroup");
    let media_json: String = {
        let media: Vec<serde_json::Value> = items.iter().enumerate()
            .map(|(i, it)| serde_json::json!({ "type": "document", "media": format!("attach://f{i}"), "filename": it.filename }))
            .collect();
        serde_json::to_string(&media).map_err(|e| TgError::Http(e.to_string()))?
    };
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // The form is rebuilt per attempt: Part::file is consumed by send().
        let mut form = reqwest::multipart::Form::new()
            .text("chat_id", chat.to_owned())
            .text("media", media_json.clone());
        for (i, it) in items.iter().enumerate() {
            let part = match reqwest::multipart::Part::file(&it.path).await {
                Ok(p) => p.file_name(it.filename.clone()).mime_str(content_type).map_err(|e| TgError::Api(e.to_string()))?,
                Err(e) => return Err(TgError::Http(scrub(token, e.to_string()))),
            };
            form = form.part(format!("f{i}"), part);
        }
        let resp = match client.post(&url).multipart(form).send().await {
            Ok(r) => r,
            Err(e) => {
                if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; }
                return Err(TgError::Http(scrub(token, e.to_string())));
            }
        };
        let status = resp.status().as_u16();
        let data: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => { if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; } return Err(TgError::Http(e.to_string())); }
        };
        if data["ok"].as_bool() == Some(true) {
            let arr = data["result"].as_array().cloned().unwrap_or_default();
            if arr.len() != items.len() {
                return Err(TgError::Api(format!("sendMediaGroup returned {} messages for {} items", arr.len(), items.len())));
            }
            let mut out = Vec::with_capacity(items.len());
            for msg in arr {
                out.push(extract_uploaded(&msg));
            }
            return Ok(out);
        }
        if let Some(wait) = retry_after_secs(status, &data) {
            if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(wait)).await; continue; }
        }
        return Err(TgError::Api(data["description"].as_str().unwrap_or("unknown error").to_owned()));
    }
}

pub async fn file_url(client: &Client, token: &str, file_id: &str) -> Result<String, TgError> {
    let url = format!("{API_BASE}/bot{token}/getFile");
    let r: ApiResponse<FileInfo> = client.get(url).query(&[("file_id", file_id)]).send().await.map_err(|e| TgError::Http(scrub(token, e.to_string())))?.json().await.map_err(|e| TgError::Http(e.to_string()))?;
    if !r.ok { return Err(TgError::Api(r.description.unwrap_or_default())); }
    let p = r.result.and_then(|f| f.file_path).ok_or_else(|| TgError::Api("missing file_path".into()))?;
    Ok(format!("{API_BASE}/file/bot{token}/{p}"))
}

// --- concurrent download path -----------------------------------------------

/// Bounded in-flight chunk downloads. Initialized from CONCURRENCY (default 6).
/// Caps simultaneous getFile+connect operations per *and across* GET requests,
/// keeping memory and 429 pressure bounded on small VPSes.
pub static DOWNLOAD_PERMITS: once_cell::sync::Lazy<tokio::sync::Semaphore> =
    once_cell::sync::Lazy::new(|| tokio::sync::Semaphore::new(
        std::env::var("CONCURRENCY").ok().and_then(|v| v.parse::<usize>().ok()).filter(|&n| n >= 1 && n <= 32).unwrap_or(6),
    ));

/// Hot-resize the download semaphore from the chat bot's /set concurrency command.
/// Growing adds permits immediately; shrinking closes permits that will free up as
/// in-flight downloads finish (acquired permits are never force-revoked). Returns
/// the effective current limit.
pub fn set_download_permits(n: usize) -> usize {
    let n = n.clamp(1, 32);
    let sem = &*DOWNLOAD_PERMITS;
    let cur = sem.available_permits();
    if n > cur { sem.add_permits(n - cur); }
    else if n < cur { sem.forget_permits(cur - n); }
    sem.available_permits().max(0).max(1) // never report below 1; clamp safety
}

/// Global pacing gate for getFile calls across all in-flight downloads.
/// Community-measured safe rate is ~20/s; 15/s (one tick every ~67ms) leaves
/// headroom. Callers serialize on the mutex and each is released one tick apart,
/// so the gate paces regardless of concurrency. getFile responses are tiny JSON;
/// the file content itself is fetched separately and is NOT gated here.
static GET_FILE_GATE: once_cell::sync::Lazy<tokio::sync::Mutex<tokio::time::Interval>> =
    once_cell::sync::Lazy::new(|| {
        let mut iv = tokio::time::interval(Duration::from_millis(1000 / 15));
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay); // no catch-up bursts
        tokio::sync::Mutex::new(iv)
    });

/// Pace getFile calls through the global gate (15/s), retrying on 429 with the
/// server-provided `retry_after` and on transient network errors.
async fn file_url_limited(client: &Client, token: &str, file_id: &str) -> Result<String, TgError> {
    let url = format!("{API_BASE}/bot{token}/getFile");
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        GET_FILE_GATE.lock().await.tick().await; // one permit ~= one paced slot
        let resp = match client.get(&url).query(&[("file_id", file_id)]).send().await {
            Ok(r) => r,
            Err(e) => {
                if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; }
                return Err(TgError::Http(scrub(token, e.to_string())));
            }
        };
        let status = resp.status().as_u16();
        let data: serde_json::Value = resp.json().await.unwrap_or_default();
        if let Some(wait) = retry_after_secs(status, &data) {
            if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(wait)).await; continue; }
            return Err(TgError::Api(format!("getFile rate limited after {attempt} attempts")));
        }
        match serde_json::from_value::<ApiResponse<FileInfo>>(data) {
            Ok(v) if v.ok => {
                let p = v.result.and_then(|f| f.file_path).ok_or_else(|| TgError::Api("missing file_path".into()))?;
                return Ok(format!("{API_BASE}/file/bot{token}/{p}"));
            }
            Ok(v) => return Err(TgError::Api(v.description.unwrap_or_else(|| "getFile failed".into()))),
            Err(e) => {
                if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; }
                return Err(TgError::Http(e.to_string()));
            }
        }
    }
}

/// Stream one chunk from Telegram's file endpoint, retrying the initial request on
/// transient errors (once the body starts streaming we surface errors as-is -- the
/// outer GET fails the whole response, same as the sequential path did).
///
/// `range = Some((lo, hi))` asks the server for bytes [lo, hi] via the Range header.
/// Whether the Bot API file endpoint honors Range is not contractually documented, so
/// the caller gets `ranged: true` (HTTP 206 -- stream already starts at `lo`) or
/// `false` (HTTP 200 -- full body, caller must skip `lo` bytes itself). Both cases
/// are handled downstream, so correctness never depends on server behavior.
pub struct ChunkStream {
    pub stream: std::pin::Pin<Box<dyn Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>,
    /// True when the server honored the Range header (HTTP 206).
    pub ranged: bool,
}

pub async fn download_chunk_stream(
    client: &Client, token: &str, file_id: &str, range: Option<(u64, u64)>,
) -> Result<ChunkStream, TgError> {
    let url = file_url_limited(client, token, file_id).await?;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let mut req = client.get(&url);
        if let Some((lo, hi)) = range { req = req.header(axum::http::header::RANGE, format!("bytes={lo}-{hi}")); }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let ranged = resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;
                return Ok(ChunkStream { stream: Box::pin(resp.bytes_stream()), ranged });
            }
            Ok(resp) => {
                let status = resp.status().as_u16();
                // 429 on the file endpoint is rare but possible under heavy parallel load.
                if status == 429 && attempt < MAX_RETRIES {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
                return Err(TgError::Http(format!("telegram file download returned HTTP {status}")));
            }
            Err(e) => {
                if attempt < MAX_RETRIES { tokio::time::sleep(Duration::from_secs(2)).await; continue; }
                return Err(TgError::Http(scrub(token, e.to_string())));
            }
        }
    }
}

/// Delete one Telegram message, retrying on 429 / transient network errors. Best-effort:
/// if the bot lacks delete rights in the channel, or the message is already gone,
/// returns Ok(false) rather than an error -- the DB row is already gone by the time
/// this is called (that's what S3 clients observe), so a stray message left behind is
/// a cosmetic leak, not a correctness problem for the object store.
pub async fn delete_message(client: &Client, token: &str, chat: &str, message_id: i64) -> Result<bool, TgError> {
    let url = format!("{API_BASE}/bot{token}/deleteMessage");
    for attempt in 0..3u32 {
        let resp = match client.post(&url).query(&[("chat_id", chat), ("message_id", &message_id.to_string())]).send().await {
            Ok(r) => r,
            Err(e) => { if attempt + 1 < 3 { tokio::time::sleep(Duration::from_secs(1)).await; continue; } return Err(TgError::Http(scrub(token, e.to_string()))); }
        };
        let status = resp.status().as_u16();
        let data: serde_json::Value = resp.json().await.unwrap_or_default();
        if let Some(wait) = retry_after_secs(status, &data) { tokio::time::sleep(Duration::from_secs(wait)).await; continue; }
        if data["ok"].as_bool() == Some(true) { return Ok(true); }
        let desc = data["description"].as_str().unwrap_or("");
        if desc.contains("not found") { return Ok(true); }
        return Ok(false); // non-retryable application error (e.g. bot lacks delete rights)
    }
    Ok(false)
}

/// Delete several messages concurrently (bounded by a semaphore) rather than one HTTP
/// round-trip at a time -- matters for CompleteMultipartUpload aborts and DeleteObjects
/// batches, which can touch dozens of chunk messages.
pub async fn delete_messages(client: &Client, token: &str, chat: &str, message_ids: Vec<i64>) {
    let sem = Arc::new(Semaphore::new(DELETE_CONCURRENCY));
    let mut handles = Vec::with_capacity(message_ids.len());
    for mid in message_ids {
        let (client, token, chat, sem) = (client.clone(), token.to_owned(), chat.to_owned(), sem.clone());
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            let _ = delete_message(&client, &token, &chat, mid).await;
        }));
    }
    for h in handles { let _ = h.await; }
}
