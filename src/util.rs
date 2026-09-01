use crate::db::Credential;
use axum::{http::StatusCode, response::{IntoResponse, Response}};
use std::collections::BTreeMap;

pub fn esc(s: &str) -> String { s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;") }
pub fn xml(s: String) -> Response { ([(axum::http::header::CONTENT_TYPE, "application/xml")], s).into_response() }
pub fn err(code: StatusCode, code_name: &str, msg: &str) -> Response {
    let body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message></Error>", esc(code_name), esc(msg));
    (code, [(axum::http::header::CONTENT_TYPE, "application/xml")], body).into_response()
}
pub fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

/// Format a unix timestamp (seconds) as the ISO-8601 form S3 clients expect in XML
/// (`LastModified`, etc.): e.g. `2026-01-02T15:04:05.000Z`. Every S3 XML timestamp
/// in this codebase must go through here -- a bare integer or a `+00:00`-suffixed
/// `to_rfc3339()` string both fail strict client-side parsers (this is what broke
/// OpenList's ListObjectsV2 decoding). Falls back to the Unix epoch if the stored
/// timestamp is somehow out of chrono's representable range, rather than panicking.
pub fn rfc3339(unix_secs: i64) -> String {
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap())
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

pub fn query_params(uri: &axum::http::Uri) -> BTreeMap<String, String> {
    urlencoding::decode(uri.query().unwrap_or("")).map(|c| c.into_owned()).unwrap_or_default()
        .split('&').filter(|s| !s.is_empty())
        .map(|p| { let mut it = p.splitn(2, '='); (it.next().unwrap_or("").to_owned(), it.next().unwrap_or("").to_owned()) })
        .collect()
}

/// Translate a client-visible (bucket,key) into the real storage key for this
/// credential, and reject cross-scope access. Root keys pass through unchanged.
/// Scoped keys are pinned to exactly one bucket; their configured `prefix` becomes
/// the invisible root of everything they do.
pub fn scope_key<'a>(cred: &Credential, bucket: &str, key: &'a str) -> Result<String, Response> {
    if cred.is_root { return Ok(key.to_owned()); }
    match &cred.bucket {
        Some(b) if b == bucket => Ok(format!("{}{}", cred.prefix, key)),
        _ => Err(err(StatusCode::FORBIDDEN, "AccessDenied", "This access key is not authorized for this bucket")),
    }
}
pub fn scope_bucket(cred: &Credential, bucket: &str) -> Result<(), Response> {
    if cred.is_root { return Ok(()); }
    match &cred.bucket {
        Some(b) if b == bucket => Ok(()),
        _ => Err(err(StatusCode::FORBIDDEN, "AccessDenied", "This access key is not authorized for this bucket")),
    }
}
/// Strip a scoped credential's prefix back off a stored key before it's shown to the
/// client (e.g. in ListObjectsV2 results), so a scoped key sees its prefix as "/".
pub fn unscope_key<'a>(cred: &Credential, stored_key: &'a str) -> &'a str {
    if cred.is_root { return stored_key; }
    stored_key.strip_prefix(cred.prefix.as_str()).unwrap_or(stored_key)
}
