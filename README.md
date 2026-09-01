# tg-s3-bot

Telegram Bot-backed, S3-compatible object storage gateway written in Rust. It has no web administration panel: configuration is supplied through environment variables, `.env`, or the terminal.

**Current release scope**

- AWS Signature Version 4 header authentication for ordinary signed requests; request bodies are consumed incrementally and never buffered as one in-memory `Bytes` value.
- `ListBuckets`, bucket create/head, `ListObjects` and `ListObjectsV2` with prefix/delimiter, `PutObject`, `GetObject`, `HeadObject`, and `DeleteObject`.
- SQLite WAL metadata index; each object maps to a Telegram `file_id`.
- Telegram Bot API upload/download, configurable with `TELEGRAM_API_BASE` for a Local Bot API Server.
- XML S3 errors, ETag, content type, content length, request-body limit, and basic path-style routing. PUT writes chunks to `TEMP_DIR` while hashing, then Telegram download responses are forwarded as a streaming HTTP body.
- Dockerfile and Compose deployment with a persistent data volume and dropped Linux capabilities.

The gateway stores one uploaded object as one Telegram document. Telegram's Bot API limits therefore apply; use a Local Bot API Server if your deployment needs larger files. Multipart upload, ranged GET, CopyObject, DeleteObjects, tagging, lifecycle, and presigned URLs are deliberately not advertised as implemented yet.

## Quick start

```sh
cp .env.example .env
# Fill TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY.
mkdir -p data
# The image runs as UID 10001:
chown -R 10001:10001 data
docker compose up -d --build
```

Example AWS CLI calls (the client signs requests with SigV4):

```sh
aws --endpoint-url http://127.0.0.1:8090 s3api list-buckets
aws --endpoint-url http://127.0.0.1:8090 s3api put-object --bucket demo --key hello.txt --body ./hello.txt
aws --endpoint-url http://127.0.0.1:8090 s3api head-object --bucket demo --key hello.txt
aws --endpoint-url http://127.0.0.1:8090 s3api get-object --bucket demo --key hello.txt ./downloaded.txt
aws --endpoint-url http://127.0.0.1:8090 s3api delete-object --bucket demo --key hello.txt
```

The gateway uses path-style URLs (`/<bucket>/<key>`). Keep the endpoint behind TLS and a reverse proxy in production.

## Environment

- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`: required Telegram credentials/target.
- `TELEGRAM_API_BASE`: defaults to `https://api.telegram.org`.
- `DATABASE_PATH`, `TEMP_DIR`: persistent SQLite and temporary-file paths.
- `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_REGION`: required S3 identity and signing region.
- `S3_REQUIRE_SIGNATURE`: defaults to `true`; only set `false` for isolated development.
- `S3_SIGNATURE_SKEW_SECONDS`: accepted `x-amz-date` clock skew, default 900.
- `MAX_OBJECT_SIZE`: maximum request/object size in bytes.

Secrets are never printed by the application. Do not commit `.env`, SQLite files, Telegram sessions, or production logs.

## Architecture

```text
S3 client -- SigV4 --> Axum router --> SQLite object index
                                      |
                                      +--> Telegram Bot API --> channel/supergroup
```

SQLite keeps bucket/object metadata, Telegram `file_id`, ETag, content type, and timestamps. Telegram keeps the payload.

## Validation

Local validation should include:

```sh
cargo fmt --check
cargo check
cargo test
```

The repository does not require a local Docker daemon for source validation. The supplied Dockerfile performs a reproducible Rust release build and the Compose file persists `/data`.

## Security and operational notes

- Use a private Telegram channel/supergroup and restrict the bot's permissions to what is required.
- Put this service behind HTTPS, rate limiting, and an upstream request-size limit.
- Back up the SQLite database together with its WAL/checkpoint state; Telegram payloads remain in the target chat.
- Rotate any credentials that have ever been exposed outside your secret store.

## v0.2: multi-tenant, chunked streaming, backup/restore, encryption

### What changed
- **Storage model**: an object is now an ordered list of Telegram messages ("chunks"),
  not one message. PUT streams the body to local disk (needed so the SigV4 signature
  can be checked before anything reaches Telegram), splitting it into `CHUNK_SIZE_BYTES`
  pieces (default 18 MiB, safely under the public Bot API's 20MB download cap), then
  uploads each chunk in order once auth passes. GET reassembles them, and Range requests
  only fetch the chunks (and byte ranges within boundary chunks) that are actually needed.
- **Multipart Upload** (CreateMultipartUpload / UploadPart / CompleteMultipartUpload /
  AbortMultipartUpload / ListParts / ListMultipartUploads) reuses the same chunk engine:
  each client-supplied part is itself staged and chunked the same way a regular PUT is.
- **CopyObject**: metadata-only when the source isn't SSE-C (reuses the same Telegram
  messages, zero data transfer). SSE-C source copies aren't implemented yet (501).
- **DeleteObjects** (batch delete) and synchronized deletion: deleting an object now
  also deletes its Telegram message(s), with reference counting so a CopyObject-shared
  chunk isn't deleted out from under another key.
- **SSE-C / SSE-S3**: AES-256-CTR, not AES-GCM. CTR is byte-seekable with zero
  ciphertext overhead, which is what makes efficient Range GET possible on encrypted
  objects. Trade-off: confidentiality without cryptographic tamper-detection (the
  SHA-256 ETag still catches accidental corruption, not deliberate tampering).
- **Multi-tenant credentials**: `credentials` table holds a root key (full access) and
  any number of scoped keys, each pinned to one `(bucket, prefix)` "root path". Managed
  via CLI subcommands (`tg-s3-bot credential add|list|rm`), run through `docker exec`.
- **Backup / restore**: a background job takes online SQLite snapshots into
  `admin/backup/` on a schedule (`BACKUP_INTERVAL_SECS`, `BACKUP_KEEP`), reachable
  through the S3 API itself (root key only). Uploading a file to `admin/recover/`
  validates it (`PRAGMA integrity_check`), takes a safety snapshot of the live DB, and
  swaps it in.
- **Docker**: only `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` are required. A root S3
  key is generated on first boot and written to `$DATA_DIR/ROOT_CREDENTIALS.txt` inside
  the persisted volume (never to logs).

### Known simplifications (read before relying on this in production)
- Encrypted multipart uploads must have parts uploaded in strictly increasing
  `PartNumber` order (real S3 allows any order) -- needed so the CTR keystream offset
  for each part is well-defined without buffering the whole upload.
- CopyObject on an SSE-C source object returns 501; only plaintext and SSE-S3 objects
  can be copied today.
- Presigned URLs are still not implemented (rejected, same as before).
- This patch could not be compiled in the sandbox that produced it (only rustc 1.75
  was installable there; the crate targets 1.88 for edition2024 transitive deps). It
  has been reviewed by hand but **not** by `cargo check` -- run that first and send back
  any errors.

### CLI
```
docker compose exec tg-s3-bot tg-s3-bot root-key                       # show root key
docker compose exec tg-s3-bot tg-s3-bot credential add mybucket --prefix team-a/
docker compose exec tg-s3-bot tg-s3-bot credential list
docker compose exec tg-s3-bot tg-s3-bot credential rm <access_key>
docker compose exec tg-s3-bot tg-s3-bot backup                          # manual snapshot
docker compose exec tg-s3-bot tg-s3-bot recover /data/admin/backup/tg-s3-....sqlite
```

## v1.1: Last-Modified, album uploads, multipart fixes, concurrent downloads

- **Last-Modified on HEAD/GET**: OpenList's S3 driver dereferences `LastModified` on
  HEAD responses and crashes without it; both methods now always send it.
- **Album uploads (sendMediaGroup)**: multipart parts staged on disk during upload are
  pushed to the channel as one album per up to 10 parts on `CompleteMultipartUpload`,
  instead of one message per part. Cuts channel spam and API calls ~10x; small direct
  PUTs (single chunk) still send one plain message. Failed album sends roll back
  already-sent parts. Orphaned part temp files from a crashed upload are cleaned at
  startup.
- **mp_chunks schema fix**: `part_number` column migration + explicit column names in
  chunk INSERTs (the upstream v1.1 assumed positional column order, which corrupted
  every multipart upload).
- **Concurrent chunk downloads (GET)**: chunk fetches are now pipelined -- each chunk's
  `getFile` + TLS handshake + response head runs in a background task, so chunk N+1's
  connection is already established while chunk N is still streaming. Client-visible
  byte order is unchanged; only latency is hidden. Bounded by `CONCURRENCY`
  (default 6 simultaneous connections), with a global getFile pacing gate (~15
  req/s, safely under the community-measured ~20/s limit) and automatic retry with
  server-provided `retry_after` on 429. Range requests request the byte range from
  the file endpoint and fall back to client-side skipping if the server ignores
  the Range header -- correctness never depends on server behavior.

### New environment variable
- `CONCURRENCY`: max simultaneous chunk download connections per GET, 1..=32, default 6.
  Each connection buffers at network-frame granularity, so memory stays low even at 32.
  4-6 is the sweet spot on small VPSes; higher values mainly help very high-latency links.

---

# tg-s3-bot 中文说明

用 Rust 写的、以 Telegram Bot 为后端的 S3 兼容对象存储网关。没有 Web 管理面板：
配置全部通过环境变量 / `.env` / 命令行提供。

**已实现功能**

- AWS Signature V4 请求头签名认证；请求体流式处理，不在内存中整体缓冲。
- ListBuckets、建桶/查桶、ListObjects(V2)（前缀/分隔符）、PutObject、GetObject、
  HeadObject、DeleteObject、CopyObject、DeleteObjects（批量删）。
- Multipart Upload 全套（Create/UploadPart/Complete/Abort/ListParts/ListMultipartUploads）。
- SSE-C / SSE-S3 服务端加密（AES-256-CTR，可按字节寻址，Range GET 友好）。
- 多租户凭证：root key + 任意多个绑定到 `(bucket, prefix)` 的 scoped key，CLI 管理。
- SQLite WAL 元数据索引 + 定时在线备份（`admin/backup/`，通过 S3 API 读取），
  恢复文件上传到 `admin/recover/` 自动校验并热切换。
- 相册上传：multipart 分片在 complete 时按 ≤10 片一组用 sendMediaGroup 发成相册块，
  频道不再被切片消息刷屏。
- 并发分片下载：GET 时各分片的 getFile+TLS 握手后台流水线预取，
  大文件读取显著提速（见下文 `CONCURRENCY`）。

**关键限制**（来自 Telegram Bot API，非本网关限制）：
单文件上传 50MB / 单文件下载 20MB，所以默认 18MB 分片；官方频控为同频道约 20 条/分钟。
自建 Local Bot API Server 可解除（`TELEGRAM_API_BASE`），但要注意内存占用。

## 快速开始

```sh
cp .env.example .env
# 填写 TELEGRAM_BOT_TOKEN、TELEGRAM_CHAT_ID、S3_ACCESS_KEY_ID、S3_SECRET_ACCESS_KEY
mkdir -p data
chown -R 10001:10001 data   # 镜像内以 UID 10001 运行
docker compose up -d --build
```

AWS CLI 示例（客户端自动 SigV4 签名）：

```sh
aws --endpoint-url http://127.0.0.1:8090 s3api list-buckets
aws --endpoint-url http://127.0.0.1:8090 s3api put-object --bucket demo --key hello.txt --body ./hello.txt
aws --endpoint-url http://127.0.0.1:8090 s3api get-object --bucket demo --key hello.txt ./downloaded.txt
```

路径风格 URL（`/<bucket>/<key>`），生产环境请置于 TLS 反代之后。

## 环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | 必填，Bot 凭证与目标频道 | — |
| `TELEGRAM_API_BASE` | Bot API 地址（可指自建 Local Bot API Server） | `https://api.telegram.org` |
| `DATABASE_PATH` / `TEMP_DIR` | SQLite 与分片暂存路径 | `$DATA_DIR` 下 |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | 首次启动自动生成 root key，见容器内 `/data/ROOT_CREDENTIALS.txt` | 自动生成 |
| `S3_REGION` | 签名 region | `us-east-1` |
| `S3_REQUIRE_SIGNATURE` | 强制签名校验，勿在生产关闭 | `true` |
| `S3_SIGNATURE_SKEW_SECONDS` | `x-amz-date` 允许时钟偏移 | `900` |
| `MAX_OBJECT_SIZE` | 单对象大小上限（字节） | 5 TiB |
| `CHUNK_SIZE_BYTES` | 单条 Telegram 消息的分片大小（须 < 20MB 下载上限） | 18 MiB |
| `CONCURRENCY` | **单次 GET 并发下载分片的连接数（1..=32）** | `6` |
| `BACKUP_INTERVAL_SECS` / `BACKUP_KEEP` | 备份周期 / 保留份数 | `21600` / `14` |

### CONCURRENCY 调参建议

- 下载是**延迟瓶颈**而非带宽瓶颈：每片要一次 getFile + 一次 HTTPS 拉流，
  串行时每片都付一次完整往返延迟。并发预取把这些延迟藏进前一片的下载时间里。
- 4~6 适合绝大多数 VPS；高延迟链路可试 8~10；不建议超过 12（ getFile 全局限速
  ~15 次/秒会成为天花板，再高只会多占内存不吃到速度）。
- 加密对象（SSE-C/S3）单片需整片下载验签后才解密，并发对它同样有效。

## 架构

```text
S3 客户端 --SigV4--> Axum 路由 --> SQLite 元数据
                                  |
                                  +--> Telegram Bot API --> 频道（分片=消息）
```

SQLite 存桶/对象元数据、Telegram file_id、ETag、时间戳等；Telegram 频道存数据本体。
删除对象会同步删除对应 Telegram 消息（引用计数保护 CopyObject 共享的分片）。

## 安全与运维建议

- 用私有频道/超级群，Bot 只授予必要权限。
- 服务置于 HTTPS、限流和请求体大小限制之后。
- 备份 SQLite（连同 WAL/checkpoint）；Telegram 频道里的数据本身就是冷备份。
- 凭证一旦暴露立即轮换。泄露的 Bot token 可通过 @BotFather /revoke 重置。

## CLI

```
docker compose exec tg-s3-bot tg-s3-bot root-key                       # 查看 root key
docker compose exec tg-s3-bot tg-s3-bot credential add mybucket --prefix team-a/
docker compose exec tg-s3-bot tg-s3-bot credential list
docker compose exec tg-s3-bot tg-s3-bot credential rm <access_key>
docker compose exec tg-s3-bot tg-s3-bot backup                          # 手动快照
docker compose exec tg-s3-bot tg-s3-bot recover /data/admin/backup/tg-s3-....sqlite
```
