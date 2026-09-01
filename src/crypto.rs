use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD, Engine};
use md5::{Digest as _, Md5};
use rand::RngCore;
use thiserror::Error;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Design: AES-256-GCM, applied per storage chunk (each chunk is already a natural,
/// bounded-size unit -- one Telegram message, <= CHUNK_SIZE_BYTES). Each chunk is
/// encrypted independently with its own random 96-bit nonce; the on-disk/on-Telegram
/// layout is `nonce(12) || ciphertext || tag(16)`, so no separate nonce column is
/// needed in the DB. This gives real authenticated encryption (tampering with a chunk
/// fails decryption instead of silently returning garbage), and -- as a side effect --
/// removes any ordering dependency between chunks/parts: each is decrypted on its own,
/// so multipart parts can be uploaded in any order or in parallel.
///
/// Trade-off vs. the earlier CTR design: GCM's tag can only be verified over the whole
/// chunk, so a Range GET that only needs part of a boundary chunk still has to download
/// and decrypt that entire chunk (capped at CHUNK_SIZE_BYTES, so bounded and cheap) --
/// it just can't fetch a sub-range of ciphertext from Telegram for that one chunk.
/// Fully-contained chunks in a range request are unaffected either way.
#[derive(Debug, Error)]
pub enum SseError {
    #[error("invalid customer key: must be a base64-encoded 32-byte AES-256 key")]
    BadKey,
    #[error("x-amz-server-side-encryption-customer-key-MD5 does not match the supplied key")]
    KeyMd5Mismatch,
    #[error("SSE-S3 requested but SSE_S3_MASTER_KEY is not configured on this server")]
    MasterKeyNotConfigured,
    #[error("object is encrypted with SSE-C; supply matching x-amz-server-side-encryption-customer-* headers to read it")]
    MissingCustomerKey,
    #[error("cannot set both x-amz-server-side-encryption and SSE-C customer headers on the same request")]
    BothSpecified,
    #[error("chunk failed authentication: wrong key or the stored data has been tampered with")]
    TamperedOrWrongKey,
}

#[derive(Clone)]
pub enum SseRequest {
    None,
    S3,
    Customer { key: [u8; KEY_LEN], key_md5: String },
}

pub fn decode_key(b64: &str) -> Result<[u8; KEY_LEN], SseError> {
    let bytes = STANDARD.decode(b64.as_bytes()).map_err(|_| SseError::BadKey)?;
    bytes.try_into().map_err(|_| SseError::BadKey)
}
pub fn key_md5_b64(key: &[u8]) -> String { STANDARD.encode(Md5::digest(key)) }
pub fn random_key() -> [u8; KEY_LEN] { let mut k = [0u8; KEY_LEN]; rand::thread_rng().fill_bytes(&mut k); k }

/// Encrypt one whole chunk's plaintext. Returns `nonce || ciphertext || tag`.
pub fn encrypt_chunk(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("aes-gcm encryption cannot fail for valid inputs");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt+verify one whole chunk. `data` must be the full `nonce || ciphertext || tag`
/// layout produced by `encrypt_chunk`. Fails closed on any tampering or wrong key.
pub fn decrypt_chunk(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>, SseError> {
    if data.len() < NONCE_LEN + TAG_LEN { return Err(SseError::TamperedOrWrongKey); }
    let (nonce_bytes, rest) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce_bytes), rest).map_err(|_| SseError::TamperedOrWrongKey)
}

/// Parse SSE headers on a PUT / CreateMultipartUpload request.
pub fn parse_put_headers(h: &HeaderMap) -> Result<SseRequest, SseError> {
    let s3 = h.get("x-amz-server-side-encryption").is_some();
    let cust_key = h.get("x-amz-server-side-encryption-customer-key").and_then(|v| v.to_str().ok());
    let cust_md5 = h.get("x-amz-server-side-encryption-customer-key-md5").and_then(|v| v.to_str().ok());
    match (s3, cust_key, cust_md5) {
        (false, None, None) => Ok(SseRequest::None),
        (true, None, None) => Ok(SseRequest::S3),
        (false, Some(k), Some(md5)) => {
            let key = decode_key(k)?;
            if key_md5_b64(&key) != md5 { return Err(SseError::KeyMd5Mismatch); }
            Ok(SseRequest::Customer { key, key_md5: md5.to_owned() })
        }
        (true, Some(_), _) | (true, _, Some(_)) => Err(SseError::BothSpecified),
        _ => Err(SseError::BadKey),
    }
}

/// Parse SSE-C headers on a GET / HeadObject / UploadPart request.
pub fn parse_get_headers(h: &HeaderMap) -> Result<Option<([u8; KEY_LEN], String)>, SseError> {
    let cust_key = h.get("x-amz-server-side-encryption-customer-key").and_then(|v| v.to_str().ok());
    let cust_md5 = h.get("x-amz-server-side-encryption-customer-key-md5").and_then(|v| v.to_str().ok());
    match (cust_key, cust_md5) {
        (None, None) => Ok(None),
        (Some(k), Some(md5)) => {
            let key = decode_key(k)?;
            if key_md5_b64(&key) != md5 { return Err(SseError::KeyMd5Mismatch); }
            Ok(Some((key, md5.to_owned())))
        }
        _ => Err(SseError::BadKey),
    }
}
