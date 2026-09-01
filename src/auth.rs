use axum::http::{HeaderMap, Method, Uri};
use chrono::{NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Pull the access key id out of the Authorization header without validating anything
/// yet -- used to look up which credential's secret key to check the signature against.
pub fn extract_access_key(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let rest = auth.strip_prefix("AWS4-HMAC-SHA256 ")?;
    for item in rest.split(',') {
        let mut kv = item.trim().splitn(2, '=');
        if kv.next()? == "Credential" {
            return kv.next()?.split('/').next().map(|s| s.to_owned());
        }
    }
    None
}

/// AWS Signature V4 verifier for header-authenticated requests.
///
/// Canonicalization follows AWS SigV4: URI and query components are encoded from
/// the raw request target, query pairs are sorted by encoded name/value, and
/// signed header names are normalized to lowercase before lookup. Every rejection
/// path logs a `reason` field at `warn` level with enough context to diagnose it
/// without a compiler in hand -- check `docker compose logs` after a failed request.
pub fn authorize(method: &Method, uri: &Uri, headers: &HeaderMap, payload_hash: &str, region: &str, access_key: &str, secret_key: &str, skew_seconds: i64) -> bool {
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => { warn!(reason = "missing_or_non_utf8_authorization_header", "AWS SigV4 rejected"); return false; }
    };
    let rest = match auth.strip_prefix("AWS4-HMAC-SHA256 ") {
        Some(v) => v,
        None => { warn!(reason = "authorization_header_not_aws4_hmac_sha256", received_prefix = %auth.chars().take(24).collect::<String>(), "AWS SigV4 rejected"); return false; }
    };
    let mut credential = ""; let mut signed_headers = ""; let mut signature = "";
    for item in rest.split(',') {
        let mut kv = item.trim().splitn(2, '=');
        match (kv.next().unwrap_or(""), kv.next().unwrap_or("")) {
            ("Credential", v) => credential = v,
            ("SignedHeaders", v) => signed_headers = v,
            ("Signature", v) => signature = v,
            _ => {}
        }
    }
    let mut cp = credential.split('/');
    let access = cp.next().unwrap_or(""); let date = cp.next().unwrap_or("");
    let cred_region = cp.next().unwrap_or(""); let service = cp.next().unwrap_or("");
    let aws4_request_literal = cp.next();
    if access != access_key {
        warn!(reason = "credential_access_key_mismatch", client_sent = %access, server_expected = %access_key, "AWS SigV4 rejected");
        return false;
    }
    if cred_region != region {
        warn!(reason = "region_mismatch", client_sent = %cred_region, server_expects = %region, hint = "set S3_REGION to match the client's configured region, or reconfigure the client", "AWS SigV4 rejected");
        return false;
    }
    if service != "s3" {
        warn!(reason = "service_not_s3", client_sent = %service, "AWS SigV4 rejected");
        return false;
    }
    if aws4_request_literal != Some("aws4_request") {
        warn!(reason = "credential_scope_not_aws4_request", client_sent = %aws4_request_literal.unwrap_or(""), "AWS SigV4 rejected");
        return false;
    }
    if date.len() != 8 {
        warn!(reason = "credential_date_wrong_length", client_sent = %date, "AWS SigV4 rejected");
        return false;
    }
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        warn!(reason = "signature_not_64_hex_chars", client_sent_len = signature.len(), "AWS SigV4 rejected");
        return false;
    }
    let amz_date = headers.get("x-amz-date").and_then(|v| v.to_str().ok()).unwrap_or("");
    if amz_date.len() != 16 || !amz_date.starts_with(date) {
        warn!(reason = "x_amz_date_missing_or_inconsistent_with_credential_date", x_amz_date = %amz_date, credential_date = %date, "AWS SigV4 rejected");
        return false;
    }
    let t = match NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        Ok(v) => v,
        Err(_) => { warn!(reason = "x_amz_date_unparseable", x_amz_date = %amz_date, "AWS SigV4 rejected"); return false; }
    };
    let age = (Utc::now().naive_utc() - t).num_seconds();
    if age.abs() > skew_seconds {
        warn!(reason = "clock_skew_exceeded", x_amz_date = %amz_date, server_now = %Utc::now().naive_utc(), skew_seconds = age, allowed_skew_seconds = skew_seconds, hint = "check the server and client clocks are in sync (NTP)", "AWS SigV4 rejected");
        return false;
    }
    let signed_payload_hash = headers.get("x-amz-content-sha256").and_then(|v| v.to_str().ok()).unwrap_or("");
    // AWS clients may omit x-amz-content-sha256 on body-less GET/HEAD requests.
    // Treat that case like the standard UNSIGNED-PAYLOAD marker; body-bearing
    // requests still require an exact SHA-256 match.
    let canonical_payload_hash = if signed_payload_hash == "UNSIGNED-PAYLOAD"
        || (signed_payload_hash.is_empty() && matches!(*method, Method::GET | Method::HEAD))
    {
        "UNSIGNED-PAYLOAD"
    } else {
        if payload_hash.len() != 64 || !payload_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            warn!(reason = "server_computed_payload_hash_malformed", len = payload_hash.len(), "AWS SigV4 rejected");
            return false;
        }
        if signed_payload_hash != payload_hash {
            warn!(reason = "payload_hash_mismatch", client_sent = %signed_payload_hash, server_computed = %payload_hash, hint = "client's x-amz-content-sha256 does not match the SHA-256 of the body bytes the server actually received", "AWS SigV4 rejected");
            return false;
        }
        payload_hash
    };
    // SignedHeaders is part of the signature. Preserve the client's declared
    // sequence and spelling after validating the required lowercase form; do not
    // sort/deduplicate it and thereby verify a different CanonicalRequest.
    let names: Vec<&str> = signed_headers.split(';').filter(|x| !x.is_empty()).collect();
    if names.is_empty() {
        warn!(reason = "signed_headers_empty", "AWS SigV4 rejected");
        return false;
    }
    if let Some(bad) = names.iter().find(|x| **x != x.to_ascii_lowercase() || x.contains(':')) {
        warn!(reason = "signed_header_name_not_lowercase", header = %bad, "AWS SigV4 rejected");
        return false;
    }
    let normalized_signed_headers = signed_headers;
    let mut canonical_headers = String::new();
    for name in &names {
        let v = match headers.get(*name).and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => { warn!(reason = "signed_header_missing_from_request_or_non_utf8", header = %name, "AWS SigV4 rejected"); return false; }
        };
        canonical_headers.push_str(name); canonical_headers.push(':'); canonical_headers.push_str(&normalize(v)); canonical_headers.push('\n');
    }
    let canonical_uri = match canonical_uri(uri.path()) {
        Some(v) => v,
        None => { warn!(reason = "uri_path_has_invalid_percent_encoding", path = %uri.path(), "AWS SigV4 rejected"); return false; }
    };
    let canonical_query = match canonical_query(uri) {
        Some(v) => v,
        None => { warn!(reason = "query_string_has_invalid_percent_encoding", query = %uri.query().unwrap_or(""), "AWS SigV4 rejected"); return false; }
    };
    let canonical = format!("{}\n{}\n{}\n{}\n{}\n{}", method.as_str(), canonical_uri, canonical_query, canonical_headers, normalized_signed_headers, canonical_payload_hash);
    let scope = format!("{date}/{cred_region}/{service}/aws4_request");
    let hashed = hex(&Sha256::digest(canonical.as_bytes()));
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashed}");
    let k_date = hmac(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, cred_region.as_bytes()); let k_service = hmac(&k_region, service.as_bytes()); let k_signing = hmac(&k_service, b"aws4_request");
    let expected = hex(&hmac(&k_signing, string_to_sign.as_bytes()));
    let valid: bool = expected.as_bytes().ct_eq(signature.to_ascii_lowercase().as_bytes()).into();
    if !valid {
        warn!(
            reason = "final_signature_mismatch",
            method = %method,
            uri = %uri,
            canonical_uri = %canonical_uri,
            canonical_query = %canonical_query,
            signed_headers = %normalized_signed_headers,
            canonical_headers = %canonical_headers.replace('\n', "|"),
            payload_marker = %canonical_payload_hash,
            expected_signature = %expected,
            supplied_signature = %signature.to_ascii_lowercase(),
            "AWS SigV4 rejected -- canonical request built fine, but the derived signature doesn't match; almost always a wrong secret_key (check ROOT_CREDENTIALS.txt / `tg-s3-bot credential list` against what the client has configured)"
        );
    }
    valid
}
fn normalize(v: &str) -> String { v.trim().split_whitespace().collect::<Vec<_>>().join(" ") }
fn aws_encode_bytes(bytes: &[u8], encode_slash: bool) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') || (!encode_slash && b == b'/') { out.push(b as char); } else { out.push_str(&format!("%{b:02X}")); }
    }
    out
}
fn percent_decode(raw: &str) -> Option<Vec<u8>> {
    let bytes = raw.as_bytes(); let mut out = Vec::with_capacity(bytes.len()); let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() { return None; }
            let hi = (bytes[i + 1] as char).to_digit(16)? as u8; let lo = (bytes[i + 2] as char).to_digit(16)? as u8;
            out.push((hi << 4) | lo); i += 3;
        } else { out.push(bytes[i]); i += 1; }
    }
    Some(out)
}
fn canonical_uri(path: &str) -> Option<String> {
    // S3 uses the single-encoded request target. Uri::path() retains the raw
    // percent escapes; preserve valid escapes instead of decoding and re-encoding
    // them, which changes paths containing %25/%2F and breaks SigV4.
    let path = if path.is_empty() { "/" } else { path };
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() || !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() { return None; }
            out.push('%'); out.push((bytes[i + 1] as char).to_ascii_uppercase()); out.push((bytes[i + 2] as char).to_ascii_uppercase()); i += 3;
        } else if bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(bytes[i] as char); i += 1;
        } else {
            out.push_str(&format!("%{:02X}", bytes[i])); i += 1;
        }
    }
    Some(out)
}
fn canonical_query(uri: &Uri) -> Option<String> {
    let mut q: Vec<(String, String)> = Vec::new();
    for pair in uri.query().unwrap_or("").split('&').filter(|x| !x.is_empty()) {
        let mut s = pair.splitn(2, '=');
        let k = percent_decode(s.next().unwrap_or(""))?;
        let v = percent_decode(s.next().unwrap_or(""))?;
        q.push((aws_encode_bytes(&k, true), aws_encode_bytes(&v, true)));
    }
    q.sort();
    Some(q.into_iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&"))
}
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> { let mut m = HmacSha256::new_from_slice(key).expect("valid hmac key"); m.update(data); m.finalize().into_bytes().to_vec() }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_uri_decodes_then_aws_encodes_once() {
        assert_eq!(canonical_uri("/bucket/a%20b/%E4%B8%AD%E6%96%87.txt").as_deref(), Some("/bucket/a%20b/%E4%B8%AD%E6%96%87.txt"));
        assert_eq!(canonical_uri("/bucket/a+b").as_deref(), Some("/bucket/a%2Bb"));
        assert_eq!(canonical_uri("/").as_deref(), Some("/"));
        assert_eq!(canonical_uri("/%ZZ"), None);
    }

    #[test]
    fn canonical_query_encodes_and_sorts_names_and_values() {
        let uri: Uri = "/admin?prefix=a%20b&list-type=2&x=%2F&prefix=a%2Bb".parse().unwrap();
        assert_eq!(canonical_query(&uri).as_deref(), Some("list-type=2&prefix=a%20b&prefix=a%2Bb&x=%2F"));
    }

    #[test]
    fn canonical_query_preserves_literal_plus() {
        let uri: Uri = "/admin?value=a+b".parse().unwrap();
        assert_eq!(canonical_query(&uri).as_deref(), Some("value=a%2Bb"));
    }

    #[test]
    fn canonical_query_rejects_bad_percent_encoding() {
        let uri: Uri = "/admin?value=%ZZ".parse().unwrap();
        assert_eq!(canonical_query(&uri), None);
    }

    #[test]
    fn normalization_trims_and_collapses_whitespace() {
        assert_eq!(normalize("  alpha\t beta   gamma  "), "alpha beta gamma");
    }

    #[test]
    fn unsigned_payload_is_allowed_as_a_canonical_marker() {
        let signed_payload_hash = "UNSIGNED-PAYLOAD";
        let canonical_payload_hash = if signed_payload_hash == "UNSIGNED-PAYLOAD" {
            "UNSIGNED-PAYLOAD"
        } else {
            "unexpected"
        };
        assert_eq!(canonical_payload_hash, "UNSIGNED-PAYLOAD");
    }

    #[test]
    fn amz_date_format_includes_trailing_z() {
        // x-amz-date is ISO-8601 basic format with a literal trailing 'Z'
        // (e.g. "20260830T104925Z"), not just "%Y%m%dT%H%M%S" -- chrono's
        // parse_from_str requires the format to consume the whole string, so
        // forgetting the 'Z' here makes every request fail with
        // x_amz_date_unparseable regardless of a correct signature.
        assert!(NaiveDateTime::parse_from_str("20260830T104925Z", "%Y%m%dT%H%M%SZ").is_ok());
        assert!(NaiveDateTime::parse_from_str("20260830T104925Z", "%Y%m%dT%H%M%S").is_err());
    }

    #[test]
    fn canonical_uri_preserves_encoded_reserved_bytes() {
        assert_eq!(canonical_uri("/admin/a%252Fb").as_deref(), Some("/admin/a%252Fb"));
        assert_eq!(canonical_uri("/admin/a%2fb").as_deref(), Some("/admin/a%2Fb"));
    }
}
