//! On-demand only -- never runs automatically after a multipart upload. Downloads
//! every existing chunk of an object, decrypts if needed, re-splits into
//! CHUNK_SIZE_BYTES pieces, re-encrypts if needed, uploads those, atomically swaps
//! the object's chunk list, then deletes the old Telegram messages. All-or-nothing:
//! any failure before the DB swap leaves the original object completely untouched.
use crate::{config::Config, crypto, db, storage, telegram};
use reqwest::Client;
use tokio::fs;

pub async fn consolidate_object(client: &Client, cfg: &Config, bucket: &str, key: &str) -> Result<String, String> {
    let p = cfg.database_path.clone();
    let (b, k) = (bucket.to_owned(), key.to_owned());
    let o = tokio::task::spawn_blocking(move || db::get_object(&p, &b, &k)).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?
        .ok_or_else(|| "object not found".to_string())?;
    let p = cfg.database_path.clone();
    let (b, k) = (bucket.to_owned(), key.to_owned());
    let chunks = tokio::task::spawn_blocking(move || db::get_chunks(&p, &b, &k)).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
    if chunks.len() <= 1 {
        return Ok("already a single chunk; nothing to do".into());
    }

    let key_bytes = match &o.sse_algorithm {
        None => None,
        Some(_) if o.sse_customer_key_md5.is_some() => {
            return Err("cannot auto-consolidate an SSE-C object: the customer key isn't stored server-side, so this can't decrypt it. Download and re-upload manually if you want it consolidated.".into());
        }
        Some(_) => match cfg.sse_s3_master_key {
            Some(k) => Some(k),
            None => return Err("SSE-S3 master key not configured; cannot decrypt this object".into()),
        },
    };

    // Phase 1: download every existing chunk, decrypt if needed, and re-split into
    // CHUNK_SIZE_BYTES pieces on local disk. Nothing Telegram-visible happens yet.
    let stage_dir = cfg.temp_dir.join(format!("consolidate-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&stage_dir).await.map_err(|e| e.to_string())?;
    let mut new_chunks = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(cfg.chunk_size.min(1 << 20));
    let mut cur_idx = 0i64;
    for ch in &chunks {
        let url = telegram::file_url(client, &cfg.bot_token, &ch.file_id).await.map_err(|e| e.to_string())?;
        let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            let _ = fs::remove_dir_all(&stage_dir).await;
            return Err(format!("download of chunk #{} failed: HTTP {}", ch.idx, resp.status()));
        }
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        let plain = match &key_bytes {
            Some(k) => crypto::decrypt_chunk(k, &bytes).map_err(|e| e.to_string())?,
            None => bytes.to_vec(),
        };
        buf.extend_from_slice(&plain);
        while buf.len() >= cfg.chunk_size {
            let piece: Vec<u8> = buf.drain(..cfg.chunk_size).collect();
            new_chunks.push(write_piece(&stage_dir, cur_idx, &piece, key_bytes.as_ref()).await.map_err(|e| e.to_string())?);
            cur_idx += 1;
        }
    }
    if !buf.is_empty() {
        new_chunks.push(write_piece(&stage_dir, cur_idx, &buf, key_bytes.as_ref()).await.map_err(|e| e.to_string())?);
    }

    if new_chunks.len() >= chunks.len() {
        let _ = fs::remove_dir_all(&stage_dir).await;
        return Ok(format!("no benefit: re-chunking would still be {} piece(s), not fewer than the current {}", new_chunks.len(), chunks.len()));
    }

    // Phase 2: upload the new, fewer chunks.
    let filename = key.rsplit('/').next().unwrap_or(key).to_owned();
    let single = new_chunks.len() == 1;
    let uploaded = match storage::upload(client, cfg, &new_chunks, 0, &filename, &o.content_type, single).await {
        Ok(u) => u,
        Err(e) => { storage::cleanup_chunks(&new_chunks).await; return Err(format!("Telegram upload failed: {e}")); }
    };

    // Phase 3: atomically point the object at the new chunks. Until this commits,
    // GET/HEAD still see the original chunks -- readers never observe a half state.
    let p = cfg.database_path.clone();
    let (b2, k2, up2) = (bucket.to_owned(), key.to_owned(), uploaded.clone());
    let swapped = tokio::task::spawn_blocking(move || db::swap_object_chunks(&p, &b2, &k2, &up2)).await;
    if !matches!(swapped, Ok(Ok(()))) {
        storage::rollback_uploaded(client, cfg, &uploaded).await;
        return Err("database swap failed; new chunks were rolled back and the original object is untouched".into());
    }

    // Phase 4: delete the old per-part messages, refcount-checked in case a
    // concurrent CopyObject grabbed a fast-path reference to one of them in the
    // window between listing `chunks` above and this swap committing.
    let mut to_delete = Vec::new();
    for ch in &chunks {
        let p2 = cfg.database_path.clone();
        let (b3, k3) = (bucket.to_owned(), key.to_owned());
        let mid = ch.message_id;
        let still_ref = tokio::task::spawn_blocking(move || db::chunk_still_referenced(&p2, mid, &b3, &k3)).await.ok().and_then(|r| r.ok()).unwrap_or(true);
        if !still_ref { to_delete.push(mid); }
    }
    if !to_delete.is_empty() {
        telegram::delete_messages(client, &cfg.bot_token, &cfg.chat_id, to_delete).await;
    }

    Ok(format!("consolidated {} chunk(s) -> {} chunk(s)", chunks.len(), new_chunks.len()))
}

async fn write_piece(dir: &std::path::Path, idx: i64, plain: &[u8], key: Option<&[u8; crypto::KEY_LEN]>) -> std::io::Result<storage::StagedChunk> {
    let on_disk = match key { Some(k) => crypto::encrypt_chunk(k, plain), None => plain.to_vec() };
    let path = dir.join(idx.to_string());
    fs::write(&path, &on_disk).await?;
    Ok(storage::StagedChunk { path, plain_size: plain.len() as i64 })
}
