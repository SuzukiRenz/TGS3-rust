use crate::{config::Config, crypto, telegram};
use axum::body::Body;
use http_body_util::BodyExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;

pub struct StagedChunk { pub path: PathBuf, pub plain_size: i64 }
pub struct Staged { pub chunks: Vec<StagedChunk>, pub total_size: i64, pub sha256_hex: String }

/// Per-request byte budget for one sendMediaGroup album. Telegram Bot API rejects
/// request bodies over ~50MB regardless of the 10-item album limit, so an album of
/// 18MiB parts must stop at 2 items per request. 48MiB leaves headroom for multipart
/// framing overhead (boundaries, headers, the media JSON).
const ALBUM_MAX_BYTES: i64 = 48 * 1024 * 1024;

#[derive(Debug)]
pub enum StageError { TooLarge, Read, Write }

fn chunk_dir(cfg: &Config) -> PathBuf { cfg.temp_dir.join(uuid::Uuid::new_v4().to_string()) }

async fn write_chunk(dir: &std::path::Path, idx: i64, plain: &[u8], key: Option<&[u8; crypto::KEY_LEN]>) -> Result<StagedChunk, StageError> {
    let on_disk = match key { Some(k) => crypto::encrypt_chunk(k, plain), None => plain.to_vec() };
    let path = dir.join(idx.to_string());
    fs::write(&path, &on_disk).await.map_err(|_| StageError::Write)?;
    Ok(StagedChunk { path, plain_size: plain.len() as i64 })
}

/// Read `body` fully onto local disk, splitting into `chunk_size`-byte pieces and
/// hashing the plaintext as it arrives (for the ETag / SigV4 payload hash). If `key`
/// is given, each *complete* chunk is encrypted in one AES-256-GCM operation before
/// being written to disk (see crypto.rs for why per-chunk rather than a continuous
/// stream cipher). The final, possibly-partial chunk is flushed as-is.
///
/// Used for both a regular single-shot PUT (the whole object) and each multipart
/// UploadPart independently (just that part's own bytes) -- deliberately *not*
/// shared/carried across separate UploadPart calls: S3 permits parts to be uploaded
/// concurrently and in any order, so nothing about how one part is chunked may depend
/// on another part having already arrived. This does mean the Telegram-side chunk
/// size for a multipart object tracks whatever part size the client chose, not
/// CHUNK_SIZE_BYTES, for parts smaller than that -- a deliberate trade for
/// correctness under concurrent/out-of-order uploads.
///
/// Deliberately does not touch Telegram: the SigV4 signature can only be checked once
/// the whole body has been hashed, so nothing gets pushed to the Telegram channel
/// until the caller has verified the request is authentic. Callers must delete the
/// staged files (see `cleanup`) on the auth-failure path.
pub async fn stage(mut body: Body, cfg: &Config, key: Option<&[u8; crypto::KEY_LEN]>, max_size: usize) -> Result<Staged, StageError> {
    let stage_dir = chunk_dir(cfg);
    fs::create_dir_all(&stage_dir).await.map_err(|_| StageError::Write)?;
    let mut chunks = Vec::new();
    let mut hasher = Sha256::new();
    let mut total: usize = 0;
    let mut cur_idx: i64 = 0;
    let mut buf: Vec<u8> = Vec::with_capacity(cfg.chunk_size.min(1 << 20));

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StageError::Read)?;
        let Ok(data) = frame.into_data() else { continue };
        if data.is_empty() { continue; }
        total = total.saturating_add(data.len());
        if total > max_size { return Err(StageError::TooLarge); }
        hasher.update(&data);
        buf.extend_from_slice(&data);
        while buf.len() >= cfg.chunk_size {
            let plain: Vec<u8> = buf.drain(..cfg.chunk_size).collect();
            chunks.push(write_chunk(&stage_dir, cur_idx, &plain, key).await?);
            cur_idx += 1;
        }
    }
    if !buf.is_empty() {
        chunks.push(write_chunk(&stage_dir, cur_idx, &buf, key).await?);
    }
    Ok(Staged { chunks, total_size: total as i64, sha256_hex: hex(&hasher.finalize()) })
}

pub async fn cleanup(staged: &Staged) { cleanup_chunks(&staged.chunks).await }
pub async fn cleanup_chunks(chunks: &[StagedChunk]) {
    if let Some(first) = chunks.first() {
        if let Some(dir) = first.path.parent() { let _ = fs::remove_dir_all(dir).await; }
    }
}

/// Push staged chunks to Telegram in order, only called after auth passes. Cleans up
/// local files as it goes so a large object never sits fully duplicated on disk for
/// long. `filename` is suffixed with the chunk's global position in the object
/// (`start_idx + i`) unless `single_chunk_object` is set and this is the only chunk,
/// so fragments stay identifiable in the Telegram channel.
pub async fn upload(client: &Client, cfg: &Config, chunks: &[StagedChunk], start_idx: i64, filename: &str, content_type: &str, single_chunk_object: bool) -> Result<Vec<crate::db::ChunkRef>, telegram::TgError> {
    // Single chunk: keep the plain filename (no .partNNNNN suffix).
    if single_chunk_object && chunks.len() == 1 {
        let up = telegram::upload(client, &cfg.bot_token, &cfg.chat_id, &chunks[0].path, filename, content_type).await?;
        let _ = fs::remove_file(&chunks[0].path).await;
        if let Some(dir) = chunks[0].path.parent() { let _ = fs::remove_dir(dir).await; }
        return Ok(vec![crate::db::ChunkRef { idx: start_idx, message_id: up.message_id, file_id: up.file_id, size: chunks[0].plain_size }]);
    }
    // 2..=10 chunks: one sendMediaGroup album call instead of N sendDocument calls
    // (the S3 single-shot PUT path also lands here when the body exceeded
    // CHUNK_SIZE_BYTES). A 10-item group is Telegram's album maximum, so anything
    // larger still needs batching -- see the loop below, which handles every size.
    // Additionally the whole request must stay under Telegram Bot API's per-request
    // body cap (~50MB): an album of 18MiB parts can hit it with as few as 3 items,
    // so each batch is also budgeted to ALBUM_MAX_BYTES (48MiB, leaving headroom
    // for multipart framing overhead).
    let mut out = Vec::with_capacity(chunks.len());
    // Batching: accumulate chunk refs into batches of at most 10 items AND at most
    // ALBUM_MAX_BYTES total, then upload each batch as one sendMediaGroup call.
    // `batch` holds (staged_chunk, global_idx) pairs so idx stays correct across
    // batches regardless of how the loop splits them.
    let mut batch: Vec<(&StagedChunk, i64)> = Vec::new();
    let mut batch_bytes: i64 = 0;
    let mut next_idx = start_idx;
    for ch in chunks {
        let this_idx = next_idx;
        if !batch.is_empty() && (batch.len() >= 10 || batch_bytes + ch.plain_size > ALBUM_MAX_BYTES) {
            let items: Vec<telegram::AlbumItem> = batch.iter().enumerate()
                .map(|(i, (c, idx))| telegram::AlbumItem { path: c.path.clone(), filename: format!("{filename}.part{idx:05}") })
                .collect();
            let ups = telegram::upload_album(client, &cfg.bot_token, &cfg.chat_id, &items, content_type).await?;
            for (up, (ch, idx)) in ups.into_iter().zip(batch.iter()) {
                out.push(crate::db::ChunkRef { idx: *idx, message_id: up.message_id, file_id: up.file_id, size: ch.plain_size });
                let _ = fs::remove_file(&ch.path).await;
            }
            batch.clear();
            batch_bytes = 0;
        }
        batch_bytes += ch.plain_size;
        batch.push((ch, this_idx));
        next_idx += 1;
    }
    if !batch.is_empty() {
        let items: Vec<telegram::AlbumItem> = batch.iter().enumerate()
            .map(|(i, (c, idx))| telegram::AlbumItem { path: c.path.clone(), filename: format!("{filename}.part{idx:05}") })
            .collect();
        let ups = telegram::upload_album(client, &cfg.bot_token, &cfg.chat_id, &items, content_type).await?;
        for (up, (ch, idx)) in ups.into_iter().zip(batch.iter()) {
            out.push(crate::db::ChunkRef { idx: *idx, message_id: up.message_id, file_id: up.file_id, size: ch.plain_size });
            let _ = fs::remove_file(&ch.path).await;
        }
    }
    // idx must reflect each chunk's global position; out was filled in order.
    for (i, r) in out.iter_mut().enumerate() { r.idx = start_idx + i as i64; }
    if let Some(dir) = chunks.first().and_then(|c| c.path.parent()) { let _ = fs::remove_dir(dir).await; }
    Ok(out)
}

/// Best-effort compensation: delete chunks that were already pushed to Telegram when a
/// later step (SQLite metadata write) fails, so a failed request doesn't silently leak
/// storage in the channel. Never called on the happy path.
pub async fn rollback_uploaded(client: &Client, cfg: &Config, chunks: &[crate::db::ChunkRef]) {
    let ids: Vec<i64> = chunks.iter().map(|c| c.message_id).collect();
    if !ids.is_empty() { telegram::delete_messages(client, &cfg.bot_token, &cfg.chat_id, ids).await; }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
