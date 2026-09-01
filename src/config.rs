use std::{env, net::SocketAddr, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError { #[error("missing environment variable: {0}")] Missing(String), #[error("invalid environment variable {0}: {1}")] Invalid(String, String) }

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub bot_token: String,
    pub chat_id: String,
    pub database_path: PathBuf,
    pub temp_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub recover_dir: PathBuf,
    pub region: String,
    pub max_object_size: usize,
    /// A single object PUT is split into Telegram messages no larger than this.
    /// Public Bot API caps: 50MB upload, 20MB download. Default stays safely under
    /// the 20MB *download* cap since that's the tighter of the two.
    pub chunk_size: usize,
    pub require_signature: bool,
    pub signature_skew_seconds: i64,
    pub sse_s3_master_key: Option<[u8; 32]>,
    /// Root-owned virtual bucket name used for admin/backup and admin/recover.
    pub admin_bucket: String,
    /// How often the background job takes a fresh SQLite backup snapshot. 0 disables it.
    pub backup_interval_secs: u64,
    /// How many backup snapshots to retain (oldest pruned first).
    pub backup_keep: usize,
    /// Telegram user IDs (as strings) allowed to run admin commands by chatting with
    /// the bot (/help, /keys, /rotate, /rekey, /backup). Empty list = chat interface
    /// fully disabled; the bot then only talks the S3 protocol.
    pub tgbot_admins: Vec<String>,
    /// Concurrent chunk downloads per GET request. Telegram Bot API has no stated
    /// per-connection bandwidth limit; downloads are latency-bound (one getFile +
    /// one HTTPS fetch per chunk, all sequential by default). This caps how many
    /// chunks of one object are fetched in parallel. Each worker buffers roughly
    /// one network frame at a time, so memory stays low even at higher values.
    pub download_concurrency: usize,
}
fn required(name: &str) -> Result<String, ConfigError> { env::var(name).map_err(|_| ConfigError::Missing(name.into())) }
fn optional(name: &str, default: &str) -> String { env::var(name).unwrap_or_else(|_| default.into()) }
fn flag(name: &str, default: bool) -> Result<bool, ConfigError> { optional(name, if default {"true"} else {"false"}).parse().map_err(|e| ConfigError::Invalid(name.into(), format!("{e}"))) }
fn number<T: std::str::FromStr>(name: &str, default: &str) -> Result<T, ConfigError> where T::Err: std::fmt::Display { optional(name, default).parse().map_err(|e| ConfigError::Invalid(name.into(), format!("{e}"))) }

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let data_dir = PathBuf::from(optional("DATA_DIR", "/data"));
        let sse_s3_master_key = match env::var("SSE_S3_MASTER_KEY") {
            Ok(v) if !v.is_empty() => {
                let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v.as_bytes())
                    .map_err(|e| ConfigError::Invalid("SSE_S3_MASTER_KEY".into(), format!("{e}")))?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| ConfigError::Invalid("SSE_S3_MASTER_KEY".into(), "must decode to exactly 32 bytes".into()))?;
                Some(arr)
            }
            _ => None,
        };
        Ok(Self {
            bind: optional("BIND_ADDR", "0.0.0.0:8090").parse().map_err(|e| ConfigError::Invalid("BIND_ADDR".into(), format!("{e}")))?,
            bot_token: required("TELEGRAM_BOT_TOKEN")?,
            chat_id: required("TELEGRAM_CHAT_ID")?,
            database_path: PathBuf::from(optional("DATABASE_PATH", &data_dir.join("tg-s3.db").to_string_lossy())),
            temp_dir: PathBuf::from(optional("TEMP_DIR", &data_dir.join("tmp").to_string_lossy())),
            backup_dir: PathBuf::from(optional("BACKUP_DIR", &data_dir.join("admin/backup").to_string_lossy())),
            recover_dir: PathBuf::from(optional("RECOVER_DIR", &data_dir.join("admin/recover").to_string_lossy())),
            region: optional("S3_REGION", "us-east-1"),
            max_object_size: number("MAX_OBJECT_SIZE", "5497558138880")?, // 5 TiB ceiling; real limit is disk+SQLite bookkeeping
            chunk_size: number("CHUNK_SIZE_BYTES", "18874368")?, // 18 MiB, safely under Bot API's 20MB download cap
            require_signature: flag("S3_REQUIRE_SIGNATURE", true)?,
            signature_skew_seconds: number("S3_SIGNATURE_SKEW_SECONDS", "900")?,
            sse_s3_master_key,
            admin_bucket: optional("ADMIN_BUCKET", "admin"),
            backup_interval_secs: number("BACKUP_INTERVAL_SECS", "21600")?, // 6h
            backup_keep: number("BACKUP_KEEP", "14")?,
            download_concurrency: number("CONCURRENCY", "6")?, // parallel chunk downloads per GET
            tgbot_admins: {
                let raw = env::var("TGBOT_ADMINS").unwrap_or_default();
                raw.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect::<Vec<_>>()
            }, // Telegram user IDs allowed to run admin CLI commands in chat; empty disables the chat bot entirely
        })
    }
}
