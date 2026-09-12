//! In-chat admin CLI. Polls Telegram getUpdates (long poll) and serves a command
//! set to whitelisted Telegram user IDs only:
//!   /help                      -- 中文命令菜单
//!   /status                    -- 运行参数 + 存储统计
//!   /keys                      -- list credentials
//!   /rotate <access_key>       -- new secret for that key (access_key unchanged)
//!   /rekey <access_key>        -- new access_key AND secret (identity reset)
//!   /backup                    -- snapshot DB now AND send the .sqlite file to the admin
//!   /set concurrency <1-32>    -- hot-resize download parallelism (persisted)
//!   /set backup_interval <秒>  -- auto-backup cadence, 0 disables (persisted)
//!   /set backup_keep <N>       -- snapshots to retain (persisted)
//!   /set <key>                 -- show current value of one key
//! A document message with caption `/restore` (or replying /restore to a document)
//! restores that file as the live DB: integrity check -> mandatory pre-restore
//! rollback snapshot -> atomic swap. A failed check leaves the DB untouched.
//! Everything is scoped to the whitelist: non-admins get nothing at all.
use crate::{admin, db, telegram};
use serde_json::Value;
use std::time::Duration;

const API_BASE: &str = "https://api.telegram.org";

pub fn spawn(client: reqwest::Client, cfg: std::sync::Arc<crate::Config>) {
    if cfg.tgbot_admins.is_empty() {
        tracing::info!("TGBOT_ADMINS empty -- chat admin interface disabled");
        return;
    }
    let admins = cfg.tgbot_admins.clone();
    tracing::info!(admins = ?admins, "chat admin interface enabled");
    tokio::spawn(async move { poll_loop(client, cfg, admins).await });
}

async fn poll_loop(client: reqwest::Client, cfg: std::sync::Arc<crate::Config>, admins: Vec<String>) {
    let url = format!("{API_BASE}/bot{}/getUpdates", cfg.bot_token);
    let mut offset: i64 = 0;
    loop {
        // Long poll 30s; on network failure back off and retry -- the S3 server is
        // independent and must keep running regardless of this loop's health.
        let qp = [("timeout", "30"), ("offset", &offset.to_string()), ("allowed_updates", r#"["message"]"#)];
        let resp = match client.get(&url).query(&qp).timeout(Duration::from_secs(40)).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(e = %e, "chat poll failed; retrying in 15s");
                tokio::time::sleep(Duration::from_secs(15)).await;
                continue;
            }
        };
        let data: Value = match resp.json().await { Ok(v) => v, Err(_) => continue };
        let Some(updates) = data.get("result").and_then(|v| v.as_array()) else { continue };
        for u in updates {
            if let Some(id) = u.get("update_id").and_then(|v| v.as_i64()) { offset = id + 1; }
            let Some(msg) = u.get("message") else { continue };
            let Some(from_id) = msg.get("from").and_then(|f| f.get("id")).and_then(|v| v.as_i64()) else { continue };
            if !admins.contains(&from_id.to_string()) { continue; } // whitelist gate
            let chat_id = msg.get("chat").and_then(|c| c.get("id")).and_then(|v| v.as_i64()).unwrap_or(0);
            // Path 1: a document carrying a /restore caption (file sent, command attached).
            if let Some(reply) = handle_document(&cfg, &client, msg, chat_id).await {
                send(&client, &cfg.bot_token, chat_id, &reply).await;
                continue;
            }
            let Some(text) = msg.get("text").and_then(|v| v.as_str()) else { continue };
            // Path 2: plain text command. /restore with no attachment asks for the file.
            let reply = handle(&cfg, &client, chat_id, text).await;
            send(&client, &cfg.bot_token, chat_id, &reply).await;
        }
    }
}

/// If this message is a document with a `/restore` caption, run the restore flow and
/// return Some(reply). Otherwise None (fall through to text handling).
async fn handle_document(cfg: &std::sync::Arc<crate::Config>, client: &reqwest::Client, msg: &Value, chat_id: i64) -> Option<String> {
    let doc = msg.get("document")?;
    let caption = msg.get("caption").and_then(|v| v.as_str()).unwrap_or("");
    if !caption.trim_start().trim_start_matches('/').to_ascii_lowercase().starts_with("restore") { return None; }
    let Some(file_id) = doc.get("file_id").and_then(|v| v.as_str()) else {
        return Some("❌ 消息里没有可下载的文件".into());
    };
    let size = doc.get("file_size").and_then(|v| v.as_i64()).unwrap_or(0);
    if size > 512 * 1024 * 1024 {
        return Some(format!("❌ 文件过大（{}），不像合法的数据库备份", human_bytes(size)));
    }
    Some(restore_flow(cfg, client, file_id).await)
}

/// Download a Telegram document into recover_dir, then hand it to the same guarded
/// restore path the S3 API uses (integrity check + pre-restore snapshot + atomic swap).
async fn restore_flow(cfg: &std::sync::Arc<crate::Config>, client: &reqwest::Client, file_id: &str) -> String {
    let name = format!("tg-s3-restore-{}.sqlite", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
    let dest = cfg.recover_dir.join(&name);
    match download_document(client, &cfg.bot_token, file_id, &dest).await {
        Err(e) => format!("❌ 下载失败：{e}"),
        Ok(n) => {
            match admin::recover_from(cfg, &cfg.recover_dir.join(name)).await {
                Ok(_) => {
                    let _ = tokio::fs::remove_file(&dest).await; // staged copy no longer needed
                    format!("✅ 数据库已恢复（{}）。\n\n🛟 回滚点：admin 桶 backup/ 里刚生成的 *-pre-restore.sqlite，恢复前的完整状态。如异常可再发它 + /restore 回去。", human_bytes(n as i64))
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(&dest).await;
                    // recover_from is validate-first: on failure nothing was swapped, DB untouched.
                    format!("❌ 恢复已中止，数据库未做任何改动：\n{e}")
                }
            }
        }
    }
}

/// GET the file endpoint and save the body to dest. Backup DBs are small (well under
/// Telegram's 20MB bot-file download cap), so a single buffered read is fine.
async fn download_document(client: &reqwest::Client, token: &str, file_id: &str, dest: &std::path::Path) -> Result<u64, String> {
    let url = telegram::file_url(client, token, file_id).await.map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() { return Err(format!("HTTP {}", resp.status())); }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    tokio::fs::write(dest, &bytes).await.map_err(|e| e.to_string())?;
    Ok(bytes.len() as u64)
}

fn human_bytes(n: i64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64; let mut u = 0;
    while v >= 1024.0 && u < 4 { v /= 1024.0; u += 1; }
    if u == 0 { format!("{n} B") } else { format!("{v:.2} {}", U[u]) }
}

/// Map one chat message to a reply. Reuses the same DB/admin functions as the
/// container CLI so behavior is identical.
async fn handle(cfg: &std::sync::Arc<crate::Config>, client: &reqwest::Client, chat_id: i64, text: &str) -> String {
    let mut parts = text.split_whitespace();
    let cmd = parts.next().unwrap_or("").trim_start_matches('/').to_ascii_lowercase();
    let arg = parts.next().unwrap_or("").to_owned();
    let arg2 = parts.next().unwrap_or("").to_owned();
    let p = cfg.database_path.clone();
    match (cmd.as_str(), arg.as_str()) {
        ("help" | "start", _) => r#"📖 管理命令
/status -- 运行参数 + 存储统计
/keys -- 列出所有访问密钥
/rotate <access_key> -- 换密钥（保留 key 不变）
/rekey <access_key> -- 密钥对全部重置

💾 备份
/backup -- 立即备份并把 .sqlite 发给你
/restore -- 发 .sqlite 文件，说明写 /restore（或回复该文件发 /restore）
  · 恢复前自动生成回滚点，校验失败不动数据库

⚙️ 参数设置（写入数据库，重启保留）
/set concurrency <1-32> -- 下载并发数
/set backup_interval <秒> -- 自动备份间隔，0=关闭
/set backup_keep <N> -- 备份保留份数
/set <参数名> -- 查看当前值"#.to_owned(),
        ("status", _) => status(cfg).await,
        ("keys", _) => {
            match tokio::task::spawn_blocking(move || db::cred_list(&p)).await {
                Ok(Ok(creds)) => creds.iter().map(|c| {
                    format!("{}{}\n  bucket={:?} prefix={:?}", if c.is_root { "[root] " } else { "" }, c.access_key, c.bucket, c.prefix)
                }).collect::<Vec<_>>().join("\n"),
                _ => "数据库错误".into(),
            }
        }
        ("rotate", ak) if !ak.is_empty() => {
            let ak = ak.to_owned();
            let secret_key = crate::rand_hex(30);
            let (p2, sk, ak2) = (cfg.database_path.clone(), secret_key.clone(), ak.clone());
            match tokio::task::spawn_blocking(move || db::cred_rotate(&p2, &ak2, &sk)).await {
                Ok(Ok(true)) => {
                    crate::sync_root_credentials_file(cfg, &ak, None, &secret_key).await;
                    format!("✅ 已换 secret（access_key 不变）\nsecret_key: {secret_key}")
                }
                Ok(Ok(false)) => "未找到该 access_key".into(),
                _ => "数据库错误".into(),
            }
        }
        ("rekey", ak) if !ak.is_empty() => {
            let ak = ak.to_owned();
            let new_ak = if ak.starts_with("root") { format!("root{}", crate::rand_hex(10)) } else { format!("key{}", crate::rand_hex(8)) };
            let secret_key = crate::rand_hex(30);
            let (p2, nak, sk, ak2) = (cfg.database_path.clone(), new_ak.clone(), secret_key.clone(), ak.clone());
            match tokio::task::spawn_blocking(move || db::cred_rekey(&p2, &ak2, &nak, &sk)).await {
                Ok(Ok(true)) => {
                    crate::sync_root_credentials_file(cfg, &ak, Some(&new_ak), &secret_key).await;
                    format!("✅ 已全部重置（旧密钥作废）\naccess_key: {new_ak}\nsecret_key: {secret_key}")
                }
                Ok(Ok(false)) => "未找到该 access_key".into(),
                _ => "数据库错误".into(),
            }
        }
        ("backup", _) => {
            match admin::backup_now(cfg).await {
                Ok(path) => {
                    let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                    match telegram::upload(client, &cfg.bot_token, &chat_id.to_string(), &path, &name, "application/octet-stream").await {
                        Ok(_) => String::new(), // file sent; no extra text bubble needed
                        Err(e) => format!("⚠️ 备份已生成但发送失败：{e}\n文件在服务器：{}", path.display()),
                    }
                }
                Err(e) => format!("❌ 备份失败：{e}"),
            }
        }
        ("restore", _) => "请把 .sqlite 备份文件直接发给我，并在说明（caption）里写 /restore；或者先发文件，再回复那条文件消息发 /restore。".into(),
        ("set", key) if !key.is_empty() => set_setting(cfg, key, &arg2).await,
        _ => "未知命令，发 /help 看菜单".into(),
    }
}

/// `/set <key> [value]`: value empty = query. Persisted in the settings table so
/// restarts keep the override; hot-applies where the component supports it.
async fn set_setting(cfg: &std::sync::Arc<crate::Config>, key: &str, value: &str) -> String {
    let key = key.to_ascii_lowercase();
    let value = value.to_owned();
    let p = cfg.database_path.clone();
    if value.is_empty() {
        // Query: effective value = DB override or env default.
        let override_v = tokio::task::spawn_blocking({ let p = p.clone(); let k = key.clone(); move || db::setting_get(&p, &k) }).await.ok().and_then(|v| v.ok()).flatten();
        let default_v = match key.as_str() {
            "concurrency" => Some(cfg.download_concurrency.to_string()),
            "backup_interval" | "backup_interval_secs" => Some(cfg.backup_interval_secs.to_string()),
            "backup_keep" => Some(cfg.backup_keep.to_string()),
            _ => None,
        };
        let eff = override_v.clone().or(default_v);
        let src = if override_v.is_some() { "（自定义）" } else { "（默认）" };
        return match eff { Some(v) => format!("{key} = {v}{src}"), None => format!("未知参数 {key}，可用：concurrency / backup_interval / backup_keep") };
    }
    // Validate before persisting.
    let valid = match key.as_str() {
        "concurrency" => value.parse::<usize>().map(|n| (1..=32).contains(&n)).unwrap_or(false),
        "backup_interval" | "backup_interval_secs" => value.parse::<u64>().is_ok(),
        "backup_keep" => value.parse::<usize>().map(|n| (1..=365).contains(&n)).unwrap_or(false),
        _ => false,
    };
    if !valid {
        return match key.as_str() {
            "concurrency" => "concurrency 需要 1-32 的整数".into(),
            "backup_interval" | "backup_interval_secs" => "backup_interval 需要 ≥0 的秒数（0=关闭自动备份）".into(),
            "backup_keep" => "backup_keep 需要 1-365 的整数".into(),
            _ => format!("未知参数 {key}，可用：concurrency / backup_interval / backup_keep"),
        };
    }
    // Normalize alias: backup_interval -> backup_interval_secs row.
    let row_key = if key == "backup_interval" { "backup_interval_secs".to_owned() } else { key.clone() };
    let dbp = cfg.database_path.clone();
    let (rk, v2) = (row_key.clone(), value.clone());
    let written = tokio::task::spawn_blocking(move || db::setting_set(&dbp, &rk, &v2)).await;
    if !matches!(written, Ok(Ok(()))) { return "数据库错误，设置未保存".into(); }
    // Hot-apply.
    match key.as_str() {
        "concurrency" => {
            let n: usize = value.parse().unwrap_or(0);
            let eff = telegram::set_download_permits(n);
            format!("✅ concurrency = {value}（立即生效，当前许可 {eff}；已持久化，重启保留）")
        }
        "backup_interval" | "backup_interval_secs" => {
            let s: u64 = value.parse().unwrap_or(0);
            let human = if s == 0 { "自动备份已关闭".to_owned() } else { format!("每 {} 秒备份一次（约 {:.1} 小时）", s, s as f64 / 3600.0) };
            format!("✅ backup_interval = {s}，{human}；调度器下一轮起按新间隔运行")
        }
        "backup_keep" => format!("✅ backup_keep = {value}（下一轮备份起生效；已持久化，重启保留）"),
        _ => unreachable!(),
    }
}

async fn status(cfg: &std::sync::Arc<crate::Config>) -> String {
    let p = cfg.database_path.clone();
    let (stats, overrides, backups) = tokio::join!(
        tokio::task::spawn_blocking({ let p = p.clone(); move || db::stats(&p) }),
        tokio::task::spawn_blocking({ let p = p.clone(); move || db::settings_list(&p) }),
        admin::list_dir(&cfg.backup_dir),
    );
    let s = stats.ok().and_then(|r| r.ok());
    let ov: Vec<(String, String)> = overrides.ok().and_then(|r| r.ok()).unwrap_or_default();
    let n_backups = backups.len();
    let latest = backups.last().map(|(n, sz, _)| format!("{n}（{}）", human_bytes(*sz as i64))).unwrap_or_else(|| "无".into());
    let ov_line = if ov.is_empty() { "无（全部使用默认值）".to_owned() } else {
        ov.iter().map(|(k, v)| format!("  {k} = {v}")).collect::<Vec<_>>().join("\n")
    };
    let (concur_eff, interval_eff, keep_eff) = {
        let get = |k: &str| ov.iter().find(|(k2, _)| k2 == k).map(|(_, v)| v.clone());
        (get("concurrency"), get("backup_interval_secs"), get("backup_keep"))
    };
    format!(
        "📊 存储统计\n  对象 {} 个 / {}\n  分片 {} 条\n  桶 {} 个，密钥 {} 把\n  进行中分片上传 {}\n\n⚙️ 运行参数\n  下载并发：{}{}\n  备份间隔：{}{}\n  备份保留：{}{}\n  自定义项：\n{}\n\n💾 备份\n  现有 {} 份，最新：{}",
        s.as_ref().map(|s| s.objects).unwrap_or(0), human_bytes(s.as_ref().map(|s| s.bytes).unwrap_or(0)),
        s.as_ref().map(|s| s.chunks).unwrap_or(0),
        s.as_ref().map(|s| s.buckets).unwrap_or(0), s.as_ref().map(|s| s.keys).unwrap_or(0),
        s.as_ref().map(|s| s.mp_active).unwrap_or(0),
        concur_eff.clone().unwrap_or_else(|| cfg.download_concurrency.to_string()), if concur_eff.is_some() { "（自定义）" } else { "（默认）" },
        interval_eff.clone().unwrap_or_else(|| cfg.backup_interval_secs.to_string()), if interval_eff.is_some() { "（自定义）" } else { "（默认）" },
        keep_eff.clone().unwrap_or_else(|| cfg.backup_keep.to_string()), if keep_eff.is_some() { "（自定义）" } else { "（默认）" },
        ov_line, n_backups, latest,
    )
}

async fn send(client: &reqwest::Client, token: &str, chat_id: i64, text: &str) {
    if text.is_empty() { return; }
    // 4096 chars is Telegram's hard per-message limit; truncate defensively.
    // Truncate by char count, not byte offset -- these replies are Chinese (UTF-8
    // multi-byte), so a raw byte slice can land mid-character and panic. Telegram's
    // limit is 4096 UTF-16 code units; capping at 3800 chars stays comfortably under
    // that for any mix of BMP/astral characters.
    let text = if text.chars().count() > 3800 {
        let mut t: String = text.chars().take(3800).collect();
        t.push('…');
        t
    } else {
        text.to_owned()
    };
    let url = format!("{API_BASE}/bot{token}/sendMessage");
    let body = serde_json::json!({ "chat_id": chat_id, "text": text });
    if let Err(e) = client.post(&url).json(&body).send().await {
        tracing::warn!(e = %e, "chat reply failed");
    }
}
