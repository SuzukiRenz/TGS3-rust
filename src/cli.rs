use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tg-s3-bot", about = "Telegram-backed S3-compatible storage gateway")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run the HTTP server (default when no subcommand is given).
    Serve,
    /// Manage scoped access keys. Run via `docker exec -it <container> tg-s3-bot credential ...`.
    Credential {
        #[command(subcommand)]
        action: CredAction,
    },
    /// Show the auto-generated root key (also written to $DATA_DIR/ROOT_CREDENTIALS.txt).
    RootKey,
    /// Take an immediate SQLite backup snapshot into admin/backup/.
    Backup,
    /// Validate and restore a SQLite file as the live database. Same safety checks as
    /// PUTting it to admin/recover/ over the S3 API (integrity check + auto pre-restore
    /// safety snapshot).
    Recover {
        /// Path to a .sqlite file, e.g. a downloaded admin/backup/ snapshot.
        file: String,
    },
    /// Consistency scan: verify every stored chunk's Telegram message/file is still
    /// retrievable, and report multipart uploads abandoned mid-transfer. Read-only
    /// unless --abort-stale is given. Calls Telegram's getFile once per chunk, paced
    /// the same as normal downloads -- can take a while on a large store.
    Fsck {
        /// Multipart uploads with no activity older than this are reported as stale.
        #[arg(long, default_value_t = 24)]
        stale_hours: i64,
        /// Also abort (delete) the stale uploads found, freeing their Telegram chunks.
        #[arg(long)]
        abort_stale: bool,
    },
    /// On-demand only: re-chunk a multipart-assembled object into fewer, uniform
    /// CHUNK_SIZE_BYTES pieces (downloads + re-uploads it once). Never runs
    /// automatically -- multipart objects otherwise keep whatever part size the S3
    /// client chose to use.
    Consolidate {
        bucket: String,
        key: String,
    },
}

#[derive(Subcommand)]
pub enum CredAction {
    /// Create a scoped key whose root path is (bucket, prefix). All requests signed
    /// with this key are confined to that bucket and to keys under that prefix.
    Add {
        bucket: String,
        #[arg(long, default_value = "")]
        prefix: String,
    },
    List,
    /// Root keys cannot be removed this way (delete $DATABASE_PATH's credentials row
    /// manually if you really mean to, after taking a backup).
    Rm { access_key: String },
    /// Generate a new secret for an existing key (root included). access_key, bucket
    /// and prefix stay the same; the old secret stops working immediately. Safe to run
    /// while the server is up -- every request re-reads the credentials row.
    Rotate { access_key: String },
    /// Full identity reset: new access_key AND new secret for an existing key (root
    /// included). Bucket scope/prefix are kept. Old credentials are gone at once.
    Rekey { access_key: String },
}
