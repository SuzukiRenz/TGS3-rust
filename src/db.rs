use rusqlite::{params, Connection};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError { #[error(transparent)] Sql(#[from] rusqlite::Error) }

/// Open a connection with WAL + busy_timeout so concurrent writers queue
/// instead of failing instantly with "database is locked" (SQLite's default
/// busy timeout is 0 -- any overlap between two write transactions errors out).
/// Every helper in this module opens a fresh short-lived connection, so the
/// timeout is what makes concurrent multipart uploads / backups safe.
pub fn open_conn(path: &Path) -> Result<Connection, DbError> {
    let c = Connection::open(path)?;
    c.busy_timeout(Duration::from_secs(10))?;
    Ok(c)
}

/// Begin an IMMEDIATE transaction: acquires the write lock up front instead of
/// upgrading from a read lock mid-transaction. With busy_timeout this makes
/// concurrent writers QUEUE instead of failing instantly with SQLITE_BUSY
/// (deferred read->write upgrades bypass busy_timeout on snapshot conflict).
pub fn imm_tx(c: &mut Connection) -> rusqlite::Result<rusqlite::Transaction<'_>> {
    c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
}

#[derive(Clone, Debug)]
pub struct ObjectMeta {
    pub bucket: String, pub key: String, pub size: i64, pub content_type: String, pub etag: String,
    pub updated_at: i64, pub sse_algorithm: Option<String>, pub sse_customer_key_md5: Option<String>,
}
#[derive(Clone, Debug)]
pub struct ChunkRef { pub idx: i64, pub message_id: i64, pub file_id: String, pub size: i64 }

#[derive(Clone, Debug)]
pub struct Credential { pub access_key: String, pub secret_key: String, pub is_root: bool, pub bucket: Option<String>, pub prefix: String }

#[derive(Clone, Debug)]
pub struct MultipartUpload {
    pub upload_id: String, pub bucket: String, pub key: String, pub content_type: String,
    pub sse_algorithm: Option<String>, pub sse_customer_key_md5: Option<String>,
    pub next_chunk_idx: i64, pub bytes_so_far: i64, pub parts_uploaded: i64,
}
#[derive(Clone, Debug)]
pub struct MultipartPart { pub part_number: i64, pub etag: String, pub size: i64, pub first_chunk_idx: i64, pub chunk_count: i64 }

pub fn init(path: &Path) -> Result<(), DbError> {
    let c = open_conn(path)?;
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.execute_batch("
        CREATE TABLE IF NOT EXISTS buckets(name TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS credentials(
            access_key TEXT PRIMARY KEY, secret_key TEXT NOT NULL, is_root INTEGER NOT NULL DEFAULT 0,
            bucket TEXT, prefix TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS objects(
            bucket TEXT NOT NULL, key TEXT NOT NULL, size INTEGER NOT NULL, content_type TEXT NOT NULL,
            etag TEXT NOT NULL, updated_at INTEGER NOT NULL,
            sse_algorithm TEXT, sse_customer_key_md5 TEXT,
            PRIMARY KEY(bucket,key));
        CREATE INDEX IF NOT EXISTS idx_objects_bucket_key ON objects(bucket,key);
        CREATE TABLE IF NOT EXISTS object_chunks(
            bucket TEXT NOT NULL, key TEXT NOT NULL, idx INTEGER NOT NULL,
            message_id INTEGER NOT NULL, file_id TEXT NOT NULL, size INTEGER NOT NULL,
            PRIMARY KEY(bucket,key,idx));
        CREATE INDEX IF NOT EXISTS idx_chunks_msg ON object_chunks(message_id);
        CREATE TABLE IF NOT EXISTS multipart_uploads(
            upload_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, key TEXT NOT NULL, content_type TEXT NOT NULL,
            sse_algorithm TEXT, sse_customer_key_md5 TEXT, next_chunk_idx INTEGER NOT NULL DEFAULT 0,
            bytes_so_far INTEGER NOT NULL DEFAULT 0, parts_uploaded INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS multipart_parts(
            upload_id TEXT NOT NULL, part_number INTEGER NOT NULL, etag TEXT NOT NULL, size INTEGER NOT NULL,
            first_chunk_idx INTEGER NOT NULL, chunk_count INTEGER NOT NULL, PRIMARY KEY(upload_id,part_number));
        CREATE TABLE IF NOT EXISTS mp_chunks(
            upload_id TEXT NOT NULL, idx INTEGER NOT NULL, part_number INTEGER NOT NULL,
            message_id INTEGER NOT NULL, file_id TEXT NOT NULL,
            size INTEGER NOT NULL, PRIMARY KEY(upload_id,idx));
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    ")?;
    // --- migration: DBs created by v1.0 lack mp_chunks.part_number (v1.1 writes 6 cols) ---
    {
        let has_pn: i64 = c.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('mp_chunks') WHERE name='part_number'",
            [], |r| r.get(0))?;
        if has_pn == 0 {
            c.execute("ALTER TABLE mp_chunks ADD COLUMN part_number INTEGER NOT NULL DEFAULT 0", [])?;
            // v1.0 stored one TG chunk per multipart part, so idx maps 1:1 to part_number.
            c.execute("UPDATE mp_chunks SET part_number = idx + 1 WHERE part_number = 0", [])?;
        }
    }
    c.execute("INSERT OR IGNORE INTO buckets(name,created_at) VALUES('default', strftime('%s','now'))", [])?;
    Ok(())
}

fn row_to_object(r: &rusqlite::Row) -> rusqlite::Result<ObjectMeta> {
    Ok(ObjectMeta {
        bucket: r.get::<_, String>(0)?, key: r.get::<_, String>(1)?, size: r.get::<_, i64>(2)?,
        content_type: r.get::<_, String>(3)?, etag: r.get::<_, String>(4)?, updated_at: r.get::<_, i64>(5)?,
        sse_algorithm: r.get::<_, Option<String>>(6)?, sse_customer_key_md5: r.get::<_, Option<String>>(7)?,
    })
}
fn row_to_chunk(r: &rusqlite::Row) -> rusqlite::Result<ChunkRef> {
    Ok(ChunkRef { idx: r.get::<_, i64>(0)?, message_id: r.get::<_, i64>(1)?, file_id: r.get::<_, String>(2)?, size: r.get::<_, i64>(3)? })
}
fn row_to_cred(r: &rusqlite::Row) -> rusqlite::Result<Credential> {
    Ok(Credential { access_key: r.get::<_, String>(0)?, secret_key: r.get::<_, String>(1)?, is_root: r.get::<_, i64>(2)? != 0, bucket: r.get::<_, Option<String>>(3)?, prefix: r.get::<_, String>(4)? })
}
fn row_to_mp(r: &rusqlite::Row) -> rusqlite::Result<MultipartUpload> {
    Ok(MultipartUpload {
        upload_id: r.get::<_, String>(0)?, bucket: r.get::<_, String>(1)?, key: r.get::<_, String>(2)?, content_type: r.get::<_, String>(3)?,
        sse_algorithm: r.get::<_, Option<String>>(4)?, sse_customer_key_md5: r.get::<_, Option<String>>(5)?,
        next_chunk_idx: r.get::<_, i64>(6)?, bytes_so_far: r.get::<_, i64>(7)?, parts_uploaded: r.get::<_, i64>(8)?,
    })
}
fn row_to_part(r: &rusqlite::Row) -> rusqlite::Result<MultipartPart> {
    Ok(MultipartPart { part_number: r.get::<_, i64>(0)?, etag: r.get::<_, String>(1)?, size: r.get::<_, i64>(2)?, first_chunk_idx: r.get::<_, i64>(3)?, chunk_count: r.get::<_, i64>(4)? })
}

// ---------- credentials ----------
pub fn cred_count(path: &Path) -> Result<i64, DbError> {
    let c = open_conn(path)?;
    let n: i64 = c.query_row("SELECT COUNT(*) FROM credentials", [], |r| r.get(0))?;
    Ok(n)
}
pub fn cred_insert(path: &Path, access_key: &str, secret_key: &str, is_root: bool, bucket: Option<&str>, prefix: &str) -> Result<(), DbError> {
    let c = open_conn(path)?;
    c.execute("INSERT INTO credentials(access_key,secret_key,is_root,bucket,prefix,created_at) VALUES(?,?,?,?,?,strftime('%s','now'))",
        params![access_key, secret_key, is_root as i64, bucket, prefix])?;
    Ok(())
}
pub fn cred_get(path: &Path, access_key: &str) -> Result<Option<Credential>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT access_key,secret_key,is_root,bucket,prefix FROM credentials WHERE access_key=?")?;
    let mut rows = stmt.query([access_key])?;
    match rows.next()? { Some(r) => Ok(Some(row_to_cred(r)?)), None => Ok(None) }
}

/// Rotate a credential's secret in place (access_key, bucket, prefix all unchanged).
/// Works for root and scoped keys alike; safe while the server is running (each
/// request re-reads the row, so the next request uses the new secret immediately).
pub fn cred_rotate(path: &Path, access_key: &str, new_secret: &str) -> Result<bool, DbError> {
    let c = open_conn(path)?;
    let n = c.execute("UPDATE credentials SET secret_key=? WHERE access_key=?", params![new_secret, access_key])?;
    Ok(n > 0)
}

/// Atomically rekey a credential: new secret AND new access_key in one transaction.
/// The old access_key disappears immediately -- clients still holding it get 403.
pub fn cred_rekey(path: &Path, old_access_key: &str, new_access_key: &str, new_secret: &str) -> Result<bool, DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    let n = tx.execute(
        "UPDATE credentials SET access_key=?, secret_key=? WHERE access_key=?",
        params![new_access_key, new_secret, old_access_key],
    )?;
    tx.commit()?;
    Ok(n > 0)
}
pub fn cred_list(path: &Path) -> Result<Vec<Credential>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT access_key,secret_key,is_root,bucket,prefix FROM credentials ORDER BY is_root DESC, access_key")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(row_to_cred(r)?); }
    Ok(out)
}
pub fn cred_remove(path: &Path, access_key: &str) -> Result<bool, DbError> {
    let c = open_conn(path)?;
    Ok(c.execute("DELETE FROM credentials WHERE access_key=? AND is_root=0", [access_key])? > 0)
}

// ---------- buckets ----------
pub fn list_buckets(path: &Path) -> Result<Vec<String>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT name FROM buckets ORDER BY name")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(r.get::<_, String>(0)?); }
    Ok(out)
}
pub fn bucket_exists(path: &Path, bucket: &str) -> Result<bool, DbError> {
    let c = open_conn(path)?;
    Ok(c.query_row("SELECT 1 FROM buckets WHERE name=?", [bucket], |_| Ok(true)).unwrap_or(false))
}
pub fn ensure_bucket(path: &Path, bucket: &str) -> Result<(), DbError> {
    let c = open_conn(path)?;
    c.execute("INSERT OR IGNORE INTO buckets(name,created_at) VALUES(?,strftime('%s','now'))", [bucket])?;
    Ok(())
}

// ---------- objects (chunked) ----------
pub fn put_object(path: &Path, o: &ObjectMeta, chunks: &[ChunkRef]) -> Result<(), DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    tx.execute("INSERT OR IGNORE INTO buckets(name,created_at) VALUES(?,strftime('%s','now'))", [&o.bucket])?;
    tx.execute("DELETE FROM object_chunks WHERE bucket=? AND key=?", params![o.bucket, o.key])?;
    tx.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?,?,?,?,?,?)",
        params![o.bucket, o.key, o.size, o.content_type, o.etag, o.updated_at, o.sse_algorithm, o.sse_customer_key_md5])?;
    for ch in chunks {
        tx.execute("INSERT INTO object_chunks VALUES(?,?,?,?,?,?)", params![o.bucket, o.key, ch.idx, ch.message_id, ch.file_id, ch.size])?;
    }
    tx.commit()?;
    Ok(())
}
pub fn get_object(path: &Path, bucket: &str, key: &str) -> Result<Option<ObjectMeta>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT bucket,key,size,content_type,etag,updated_at,sse_algorithm,sse_customer_key_md5 FROM objects WHERE bucket=? AND key=?")?;
    let mut rows = stmt.query(params![bucket, key])?;
    match rows.next()? { Some(r) => Ok(Some(row_to_object(r)?)), None => Ok(None) }
}
pub fn get_chunks(path: &Path, bucket: &str, key: &str) -> Result<Vec<ChunkRef>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT idx,message_id,file_id,size FROM object_chunks WHERE bucket=? AND key=? ORDER BY idx")?;
    let mut rows = stmt.query(params![bucket, key])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(row_to_chunk(r)?); }
    Ok(out)
}
pub fn list_objects(path: &Path, bucket: &str, prefix: &str) -> Result<Vec<ObjectMeta>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT bucket,key,size,content_type,etag,updated_at,sse_algorithm,sse_customer_key_md5 FROM objects WHERE bucket=? AND key LIKE ? ESCAPE '\\' ORDER BY key")?;
    let pat = format!("{}%", escape_like(prefix));
    let mut rows = stmt.query(params![bucket, pat])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(row_to_object(r)?); }
    Ok(out)
}
fn escape_like(s: &str) -> String { s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_") }

/// Delete an object. Returns the chunks it owned; caller must check `chunk_still_referenced`
/// for each message_id before actually deleting the Telegram message (CopyObject's fast path
/// can leave multiple keys pointing at the same underlying message).
pub fn delete_object(path: &Path, bucket: &str, key: &str) -> Result<Option<Vec<ChunkRef>>, DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    let chunks: Vec<ChunkRef> = {
        let mut stmt = tx.prepare("SELECT idx,message_id,file_id,size FROM object_chunks WHERE bucket=? AND key=?")?;
        let mut rows = stmt.query(params![bucket, key])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? { out.push(row_to_chunk(r)?); }
        out
    };
    let existed = tx.execute("DELETE FROM objects WHERE bucket=? AND key=?", params![bucket, key])? > 0;
    tx.execute("DELETE FROM object_chunks WHERE bucket=? AND key=?", params![bucket, key])?;
    tx.commit()?;
    Ok(if existed { Some(chunks) } else { None })
}
/// Replace an object's physical chunk list in one transaction (used by the
/// `consolidate` command to swap many small chunks for fewer, uniformly-sized
/// ones). Only object_chunks changes -- size/etag/content_type/sse fields on the
/// `objects` row are untouched since the logical content is identical, just its
/// physical layout. Caller uploads the new chunks to Telegram and deletes the old
/// ones itself; this only flips which rows `objects`/GET see.
pub fn swap_object_chunks(path: &Path, bucket: &str, key: &str, new_chunks: &[ChunkRef]) -> Result<(), DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    tx.execute("DELETE FROM object_chunks WHERE bucket=? AND key=?", params![bucket, key])?;
    for ch in new_chunks {
        tx.execute("INSERT INTO object_chunks VALUES(?,?,?,?,?,?)", params![bucket, key, ch.idx, ch.message_id, ch.file_id, ch.size])?;
    }
    tx.commit()?;
    Ok(())
}

pub fn chunk_still_referenced(path: &Path, message_id: i64, excluding_bucket: &str, excluding_key: &str) -> Result<bool, DbError> {
    let c = open_conn(path)?;
    Ok(c.query_row("SELECT 1 FROM object_chunks WHERE message_id=? AND NOT(bucket=? AND key=?) LIMIT 1", params![message_id, excluding_bucket, excluding_key], |_| Ok(true)).unwrap_or(false))
}

/// Metadata-only copy: duplicates the objects row and every chunk row onto a new
/// (bucket,key), reusing the same Telegram messages. Zero data movement. Only valid
/// when the source is not SSE-C encrypted (SSE-C copy needs a full decrypt/re-encrypt
/// pass, handled separately in the HTTP layer). SSE-S3 objects copy fine since every
/// object shares the same server-side master key.
pub fn copy_object_fastpath(path: &Path, src_bucket: &str, src_key: &str, dst_bucket: &str, dst_key: &str, new_content_type: Option<&str>, now: i64) -> Result<Option<ObjectMeta>, DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    let src: Option<ObjectMeta> = {
        let mut stmt = tx.prepare("SELECT bucket,key,size,content_type,etag,updated_at,sse_algorithm,sse_customer_key_md5 FROM objects WHERE bucket=? AND key=?")?;
        let mut rows = stmt.query(params![src_bucket, src_key])?;
        match rows.next()? { Some(r) => Some(row_to_object(r)?), None => None }
    };
    let Some(src) = src else { return Ok(None) };
    let dst = ObjectMeta {
        bucket: dst_bucket.into(), key: dst_key.into(), size: src.size,
        content_type: new_content_type.unwrap_or(&src.content_type).to_owned(), etag: src.etag.clone(), updated_at: now,
        sse_algorithm: src.sse_algorithm.clone(), sse_customer_key_md5: src.sse_customer_key_md5.clone(),
    };
    tx.execute("INSERT OR IGNORE INTO buckets(name,created_at) VALUES(?,strftime('%s','now'))", [dst_bucket])?;
    tx.execute("DELETE FROM object_chunks WHERE bucket=? AND key=?", params![dst_bucket, dst_key])?;
    tx.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?,?,?,?,?,?)",
        params![dst.bucket, dst.key, dst.size, dst.content_type, dst.etag, dst.updated_at, dst.sse_algorithm, dst.sse_customer_key_md5])?;
    tx.execute("INSERT INTO object_chunks SELECT ?,?,idx,message_id,file_id,size FROM object_chunks WHERE bucket=? AND key=?", params![dst_bucket, dst_key, src_bucket, src_key])?;
    tx.commit()?;
    Ok(Some(dst))
}

// ---------- multipart ----------
pub fn mp_create(path: &Path, upload_id: &str, bucket: &str, key: &str, content_type: &str, sse_algorithm: Option<&str>, sse_customer_key_md5: Option<&str>) -> Result<(), DbError> {
    let c = open_conn(path)?;
    c.execute("INSERT INTO multipart_uploads(upload_id,bucket,key,content_type,sse_algorithm,sse_customer_key_md5,next_chunk_idx,bytes_so_far,parts_uploaded,created_at) VALUES(?,?,?,?,?,?,0,0,0,strftime('%s','now'))",
        params![upload_id, bucket, key, content_type, sse_algorithm, sse_customer_key_md5])?;
    Ok(())
}
pub fn mp_get(path: &Path, upload_id: &str) -> Result<Option<MultipartUpload>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT upload_id,bucket,key,content_type,sse_algorithm,sse_customer_key_md5,next_chunk_idx,bytes_so_far,parts_uploaded FROM multipart_uploads WHERE upload_id=?")?;
    let mut rows = stmt.query([upload_id])?;
    match rows.next()? { Some(r) => Ok(Some(row_to_mp(r)?)), None => Ok(None) }
}
/// Before staging a part's body: returns the next free chunk index (chunks are still
/// disjoint per part -- ordering between parts no longer matters now that each chunk
/// carries its own GCM nonce, but chunk indices must still not collide).
pub fn mp_reserve(path: &Path, upload_id: &str, n_chunks: i64) -> Result<i64, DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    let first: i64 = tx.query_row("SELECT next_chunk_idx FROM multipart_uploads WHERE upload_id=?", [upload_id], |r| r.get(0))?;
    tx.execute("UPDATE multipart_uploads SET next_chunk_idx=next_chunk_idx+? WHERE upload_id=?", params![n_chunks, upload_id])?;
    tx.commit()?;
    Ok(first)
}
pub fn mp_insert_chunk(path: &Path, upload_id: &str, idx: i64, part_number: i64, message_id: i64, file_id: &str, size: i64) -> Result<(), DbError> {
    let c = open_conn(path)?;
    c.execute("INSERT INTO mp_chunks(upload_id,idx,part_number,message_id,file_id,size) VALUES(?,?,?,?,?,?)", params![upload_id, idx, part_number, message_id, file_id, size])?;
    Ok(())
}
/// Album mode: persist a just-staged UploadPart BEFORE returning 200 OK. Writes the
/// chunk rows (message_id=0 + file_id holding the on-disk stage path; the real
/// message_id/file_id are filled in when Complete pushes the album) and the
/// multipart_parts bookkeeping row in one transaction, replacing the old
/// mp_insert_chunk-per-chunk + mp_advance two-step.
pub fn mp_stage_part(path: &Path, upload_id: &str, part_number: i64, etag: &str, part_size: i64, rows: &[ChunkRef], staged_paths: &[String]) -> Result<(), DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    for (r, p) in rows.iter().zip(staged_paths.iter()) {
        tx.execute("INSERT INTO mp_chunks(upload_id,idx,part_number,message_id,file_id,size) VALUES(?,?,?,?,?,?)",
            params![upload_id, r.idx, part_number, r.message_id, p, r.size])?;
    }
    let first_chunk_idx = rows.first().map(|r| r.idx).unwrap_or(0);
    let chunk_count = rows.len() as i64;
    tx.execute("INSERT OR REPLACE INTO multipart_parts(upload_id,part_number,etag,size,first_chunk_idx,chunk_count) VALUES(?,?,?,?,?,?)",
        params![upload_id, part_number, etag, part_size, first_chunk_idx, chunk_count])?;
    tx.execute("UPDATE multipart_uploads SET bytes_so_far=bytes_so_far+?, parts_uploaded=parts_uploaded+1 WHERE upload_id=?",
        params![part_size, upload_id])?;
    tx.commit()?;
    Ok(())
}
/// Album mode: swap in the real Telegram identities for completed chunks whose
/// message_id is still 0 (staged on disk). `triples` is (idx, message_id, file_id).
pub fn mp_fill_album_results(path: &Path, upload_id: &str, triples: &[(i64, i64, String)]) -> Result<(), DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    for (idx, message_id, file_id) in triples {
        tx.execute("UPDATE mp_chunks SET message_id=?, file_id=? WHERE upload_id=? AND idx=? AND message_id=0",
            params![message_id, file_id, upload_id, idx])?;
    }
    tx.commit()?;
    Ok(())
}
/// Album mode: read an upload's staged chunk rows as (idx, message_id, size, stage_path,
/// part_number). Rows staged on disk carry message_id=0 and the stage path in file_id;
/// already-pushed rows (message_id>0, real file_id) are included too so Complete can
/// skip/keep them correctly -- the caller filters on part_number.
pub fn mp_get_staged_chunks_pn(path: &Path, upload_id: &str) -> Result<Vec<(i64, i64, i64, String, i64)>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT idx,message_id,size,file_id,part_number FROM mp_chunks WHERE upload_id=? ORDER BY idx")?;
    let mut rows = stmt.query([upload_id])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?));
    }
    Ok(out)
}
pub fn mp_advance(path: &Path, upload_id: &str, part_number: i64, etag: &str, part_size: i64, first_chunk_idx: i64, chunk_count: i64) -> Result<(), DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    tx.execute("UPDATE multipart_uploads SET bytes_so_far=bytes_so_far+?, parts_uploaded=parts_uploaded+1 WHERE upload_id=?", params![part_size, upload_id])?;
    tx.execute("INSERT OR REPLACE INTO multipart_parts VALUES(?,?,?,?,?,?)", params![upload_id, part_number, etag, part_size, first_chunk_idx, chunk_count])?;
    tx.commit()?;
    Ok(())
}
pub fn mp_list_parts(path: &Path, upload_id: &str) -> Result<Vec<MultipartPart>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT part_number,etag,size,first_chunk_idx,chunk_count FROM multipart_parts WHERE upload_id=? ORDER BY part_number")?;
    let mut rows = stmt.query([upload_id])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(row_to_part(r)?); }
    Ok(out)
}
/// Abort: return every staged Telegram chunk (caller deletes them from Telegram) and drop bookkeeping.
pub fn mp_abort(path: &Path, upload_id: &str) -> Result<Vec<ChunkRef>, DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    let chunks: Vec<ChunkRef> = {
        let mut stmt = tx.prepare("SELECT idx,message_id,file_id,size FROM mp_chunks WHERE upload_id=?")?;
        let mut rows = stmt.query([upload_id])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? { out.push(row_to_chunk(r)?); }
        out
    };
    tx.execute("DELETE FROM mp_chunks WHERE upload_id=?", [upload_id])?;
    tx.execute("DELETE FROM multipart_parts WHERE upload_id=?", [upload_id])?;
    tx.execute("DELETE FROM multipart_uploads WHERE upload_id=?", [upload_id])?;
    tx.commit()?;
    Ok(chunks)
}
/// Complete: move the physical chunks belonging to exactly the parts the client
/// listed (S3 permits completing with a subset of uploaded parts) into
/// object_chunks under (bucket,key), ordered by (part_number, idx) -- i.e. true
/// logical byte order -- not by upload arrival order, since parts may have been
/// uploaded concurrently or out of order. Renumbers sequentially; inserts the final
/// objects row; drops bookkeeping.
pub fn mp_complete(path: &Path, upload_id: &str, mp: &MultipartUpload, part_numbers: &[i64], total_size: i64, etag: &str, now: i64) -> Result<(), DbError> {
    let mut c = open_conn(path)?;
    let tx = imm_tx(&mut c)?;
    tx.execute("INSERT OR IGNORE INTO buckets(name,created_at) VALUES(?,strftime('%s','now'))", [&mp.bucket])?;
    tx.execute("DELETE FROM object_chunks WHERE bucket=? AND key=?", params![mp.bucket, mp.key])?;
    let placeholders = std::iter::repeat("?").take(part_numbers.len()).collect::<Vec<_>>().join(",");
    let sql = format!(
        "INSERT INTO object_chunks SELECT ?,?, ROW_NUMBER() OVER (ORDER BY part_number, idx) - 1, message_id, file_id, size \
         FROM mp_chunks WHERE upload_id=? AND part_number IN ({placeholders})"
    );
    let mut stmt = tx.prepare(&sql)?;
    let mut bind_params: Vec<&dyn rusqlite::ToSql> = vec![&mp.bucket, &mp.key, &upload_id];
    let part_number_vals: Vec<i64> = part_numbers.to_vec();
    for v in &part_number_vals { bind_params.push(v); }
    stmt.execute(bind_params.as_slice())?;
    drop(stmt);
    tx.execute("INSERT OR REPLACE INTO objects VALUES(?,?,?,?,?,?,?,?)",
        params![mp.bucket, mp.key, total_size, mp.content_type, etag, now, mp.sse_algorithm, mp.sse_customer_key_md5])?;
    tx.execute("DELETE FROM mp_chunks WHERE upload_id=?", [upload_id])?;
    tx.execute("DELETE FROM multipart_parts WHERE upload_id=?", [upload_id])?;
    tx.execute("DELETE FROM multipart_uploads WHERE upload_id=?", [upload_id])?;
    tx.commit()?;
    Ok(())
}
pub fn mp_list_uploads(path: &Path, bucket: &str) -> Result<Vec<MultipartUpload>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT upload_id,bucket,key,content_type,sse_algorithm,sse_customer_key_md5,next_chunk_idx,bytes_so_far,parts_uploaded FROM multipart_uploads WHERE bucket=? ORDER BY created_at")?;
    let mut rows = stmt.query([bucket])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(row_to_mp(r)?); }
    Ok(out)
}

// ---------- runtime settings (chat-bot tunables; survive restarts) ----------

/// Read one setting; `None` = not overridden (callers fall back to env default).
pub fn setting_get(path: &Path, key: &str) -> Result<Option<String>, DbError> {
    let c = open_conn(path)?;
    Ok(c.query_row("SELECT value FROM settings WHERE key=?", [key], |r| r.get::<_, String>(0)).ok())
}
/// Insert-or-update one setting. Validated by the caller before reaching here.
pub fn setting_set(path: &Path, key: &str, value: &str) -> Result<(), DbError> {
    let c = open_conn(path)?;
    c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [key, value])?;
    Ok(())
}
/// All overridden settings as (key, value) pairs, for /status display.
pub fn settings_list(path: &Path) -> Result<Vec<(String, String)>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT key,value FROM settings ORDER BY key")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push((r.get::<_, String>(0)?, r.get::<_, String>(1)?)); }
    Ok(out)
}

// ---------- fsck ----------

/// One physical chunk with enough context to report a problem usefully.
pub struct ChunkRefFull { pub bucket: String, pub key: String, pub idx: i64, pub file_id: String }

/// Every object_chunks row, for a DB -> Telegram consistency scan (does the stored
/// file_id still resolve?). There's no feasible reverse direction (Telegram -> DB)
/// over the Bot API: bots have no "list all messages in this channel" call.
pub fn list_all_chunks(path: &Path) -> Result<Vec<ChunkRefFull>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT bucket,key,idx,file_id FROM object_chunks ORDER BY bucket,key,idx")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(ChunkRefFull { bucket: r.get(0)?, key: r.get(1)?, idx: r.get(2)?, file_id: r.get(3)? });
    }
    Ok(out)
}

/// Multipart uploads created before `before_ts` and still open -- almost always a
/// client that crashed or gave up mid-transfer, leaving staged chunks in Telegram
/// that will never be referenced by a completed object. Caveat: this is *creation*
/// time, not last-activity time (the schema doesn't track the latter), so a
/// legitimately slow multi-hour upload could show up too -- the default 24h
/// threshold is meant to comfortably clear that case; raise --stale-hours if you
/// routinely do very large/slow uploads.
pub fn list_stale_multipart_uploads(path: &Path, before_ts: i64) -> Result<Vec<MultipartUpload>, DbError> {
    let c = open_conn(path)?;
    let mut stmt = c.prepare("SELECT upload_id,bucket,key,content_type,sse_algorithm,sse_customer_key_md5,next_chunk_idx,bytes_so_far,parts_uploaded FROM multipart_uploads WHERE created_at < ? ORDER BY created_at")?;
    let mut rows = stmt.query([before_ts])?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? { out.push(row_to_mp(r)?); }
    Ok(out)
}



pub struct Stats { pub objects: i64, pub bytes: i64, pub buckets: i64, pub keys: i64, pub mp_active: i64, pub chunks: i64 }
pub fn stats(path: &Path) -> Result<Stats, DbError> {
    let c = open_conn(path)?;
    let one = |sql: &str| -> Result<i64, DbError> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
    Ok(Stats {
        objects: one("SELECT COUNT(*) FROM objects")?,
        bytes: one("SELECT COALESCE(SUM(size),0) FROM objects")?,
        buckets: one("SELECT COUNT(*) FROM buckets")?,
        keys: one("SELECT COUNT(*) FROM credentials")?,
        mp_active: one("SELECT COUNT(*) FROM multipart_uploads")?,
        chunks: one("SELECT COUNT(*) FROM object_chunks")?,
    })
}
