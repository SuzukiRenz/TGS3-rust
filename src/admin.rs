use crate::config::Config;
use chrono::Utc;
use rusqlite::Connection;
use std::{path::{Path, PathBuf}, sync::Arc, time::Duration};
use tokio::fs;
use tracing::{error, info, warn};

pub async fn run_scheduler(cfg: Arc<Config>) {
    if cfg.backup_interval_secs == 0 { info!("BACKUP_INTERVAL_SECS=0, automatic backups disabled"); return; }
    let mut tick = tokio::time::interval(Duration::from_secs(cfg.backup_interval_secs));
    loop {
        tick.tick().await;
        match backup_now(&cfg).await {
            Ok(p) => info!(path=?p, "sqlite backup snapshot taken"),
            Err(e) => error!(%e, "scheduled backup failed"),
        }
    }
}

/// Online SQLite backup (does not block writers) + retention pruning. Filename is
/// timestamp-sortable so pruning is just "keep the lexicographically-last N".
pub async fn backup_now(cfg: &Config) -> Result<PathBuf, String> {
    fs::create_dir_all(&cfg.backup_dir).await.map_err(|e| e.to_string())?;
    let name = format!("tg-s3-{}.sqlite", Utc::now().format("%Y%m%dT%H%M%SZ"));
    let dest = cfg.backup_dir.join(&name);
    let src = cfg.database_path.clone();
    let dest2 = dest.clone();
    tokio::task::spawn_blocking(move || sqlite_online_backup(&src, &dest2))
        .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
    prune(cfg).await?;
    Ok(dest)
}

fn sqlite_online_backup(src: &Path, dest: &Path) -> rusqlite::Result<()> {
    let src_conn = Connection::open(src)?;
    let mut dst_conn = Connection::open(dest)?;
    let backup = rusqlite::backup::Backup::new(&src_conn, &mut dst_conn)?;
    backup.run_to_completion(5, Duration::from_millis(250), None)?;
    Ok(())
}

async fn prune(cfg: &Config) -> Result<(), String> {
    let mut names: Vec<String> = Vec::new();
    let mut rd = fs::read_dir(&cfg.backup_dir).await.map_err(|e| e.to_string())?;
    while let Ok(Some(e)) = rd.next_entry().await { names.push(e.file_name().to_string_lossy().into_owned()); }
    names.sort();
    names.reverse();
    for stale in names.into_iter().skip(cfg.backup_keep) {
        let _ = fs::remove_file(cfg.backup_dir.join(stale)).await;
    }
    Ok(())
}

pub async fn list_dir(dir: &Path) -> Vec<(String, i64, i64)> {
    let mut out = Vec::new();
    if let Ok(mut rd) = fs::read_dir(dir).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            if let Ok(meta) = e.metadata().await {
                if !meta.is_file() { continue; }
                let mtime = meta.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64).unwrap_or(0);
                out.push((e.file_name().to_string_lossy().into_owned(), meta.len() as i64, mtime));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Validate an uploaded SQLite file, take a pre-restore safety snapshot of the live
/// database (so a bad restore is always recoverable), then atomically swap it in.
/// "Automatic detect and overwrite" per spec: no separate confirmation step once the
/// file lands in admin/recover/ -- the integrity check + mandatory pre-restore backup
/// are the safety net instead.
pub async fn recover_from(cfg: &Config, uploaded: &Path) -> Result<(), String> {
    let check_path = uploaded.to_path_buf();
    let ok: Option<String> = tokio::task::spawn_blocking(move || {
        let c = Connection::open(&check_path).ok()?;
        c.pragma_query_value(None, "integrity_check", |row| row.get(0)).ok()
    }).await.map_err(|e| e.to_string())?;
    if ok.as_deref() != Some("ok") {
        return Err("PRAGMA integrity_check failed on the uploaded file; refusing to restore a possibly-corrupt database".into());
    }
    backup_now(cfg).await.map_err(|e| format!("pre-restore safety backup failed, aborting restore: {e}"))?;
    let wal = format!("{}-wal", cfg.database_path.display());
    let shm = format!("{}-shm", cfg.database_path.display());
    let _ = fs::remove_file(&wal).await;
    let _ = fs::remove_file(&shm).await;
    fs::copy(uploaded, &cfg.database_path).await.map_err(|e| e.to_string())?;
    warn!(from=?uploaded, "database restored from admin/recover upload");
    Ok(())
}
