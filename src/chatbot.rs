//! In-chat admin CLI. Polls Telegram getUpdates (long poll) and serves a tiny
//! command set to whitelisted Telegram user IDs only:
//!   /help                 -- command list
//!   /keys                 -- list credentials
//!   /rotate <access_key>  -- new secret for that key (access_key unchanged)
//!   /rekey <access_key>   -- new access_key AND secret (identity reset)
//!   /backup               -- take a SQLite backup snapshot now
//! Everything is scoped to the whitelist: a non-admin (or a group the bot happens
//! to sit in) gets nothing -- no reply, no error, no leak. Send with Markdown
//! disabled: secrets are plain hex and Telegram entities would garble them.
use crate::{admin, cli, db};
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
            let Some(text) = msg.get("text").and_then(|v| v.as_str()) else { continue };
            let chat_id = msg.get("chat").and_then(|c| c.get("id")).and_then(|v| v.as_i64()).unwrap_or(0);
            let reply = handle(&cfg, text).await;
            send(&client, &cfg.bot_token, chat_id, &reply).await;
        }
    }
}

/// Map one chat message to a reply. Kept deliberately narrow: only these five
/// commands; anything else returns help. Reuses the same DB/admin functions as
/// the container CLI so behavior is identical.
async fn handle(cfg: &std::sync::Arc<crate::Config>, text: &str) -> String {
    let mut parts = text.split_whitespace();
    let cmd = parts.next().unwrap_or("").trim_start_matches('/').to_ascii_lowercase();
    let arg = parts.next().unwrap_or("").to_owned();
    let p = cfg.database_path.clone();
    match (cmd.as_str(), arg.as_str()) {
        ("help" | "start", _) => "commands:\n/keys -- list credentials\n/rotate <access_key> -- new secret, same access_key\n/rekey <access_key> -- new access_key + secret\n/backup -- snapshot DB now".into(),
        ("keys", _) => {
            match tokio::task::spawn_blocking(move || db::cred_list(&p)).await {
                Ok(Ok(creds)) => creds.iter().map(|c| {
                    format!("{}{}\n  bucket={:?} prefix={:?}", if c.is_root { "[root] " } else { "" }, c.access_key, c.bucket, c.prefix)
                }).collect::<Vec<_>>().join("\n"),
                _ => "database error".into(),
            }
        }
        ("rotate", ak) if !ak.is_empty() => {
            let ak = ak.to_owned();
            let secret_key = crate::rand_hex(30);
            let (p2, sk, ak2) = (cfg.database_path.clone(), secret_key.clone(), ak.clone());
            match tokio::task::spawn_blocking(move || db::cred_rotate(&p2, &ak2, &sk)).await {
                Ok(Ok(true)) => {
                    crate::sync_root_credentials_file(cfg, &ak, None, &secret_key).await;
                    format!("rotated (access_key unchanged)\nsecret_key: {secret_key}")
                }
                Ok(Ok(false)) => "not found".into(),
                _ => "database error".into(),
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
                    format!("rekeyed (old credentials gone)\naccess_key: {new_ak}\nsecret_key: {secret_key}")
                }
                Ok(Ok(false)) => "not found".into(),
                _ => "database error".into(),
            }
        }
        ("backup", _) => match admin::backup_now(cfg).await {
            Ok(path) => format!("backup written: {}", path.display()),
            Err(e) => format!("backup failed: {e}"),
        },
        _ => "unknown command -- /help".into(),
    }
}

async fn send(client: &reqwest::Client, token: &str, chat_id: i64, text: &str) {
    // 4096 chars is Telegram's hard per-message limit; truncate defensively.
    let text = if text.len() > 4000 { format!("{}…", &text[..4000]) } else { text.to_owned() };
    let url = format!("{API_BASE}/bot{token}/sendMessage");
    let body = serde_json::json!({ "chat_id": chat_id, "text": text });
    if let Err(e) = client.post(&url).json(&body).send().await {
        tracing::warn!(e = %e, "chat reply failed");
    }
}

// keep cli import referenced for parity with the container CLI (help text source)
#[allow(unused)]
fn _parity() { let _ = std::any::type_name::<cli::CredAction>(); }
