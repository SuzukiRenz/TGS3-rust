# TGS3 SigV4 compatibility patch

This package contains a minimal source patch for the `tg-s3` project.

## Fixed

- Parse the raw query string without converting `+` into a space.
- Percent-decode each query component once, then apply AWS SigV4 RFC 3986 encoding.
- Sort query parameters by their encoded key and value.
- Decode and re-encode the request path consistently for the canonical URI.
- Normalize and validate signed header names before canonicalization.
- Compare hexadecimal signatures case-insensitively after validating their format.
- Reject malformed percent escapes instead of silently signing a different request.
- Add unit tests covering URI encoding, query ordering, literal plus signs, malformed escapes, and header whitespace.

## Validation

Validated with Rust 1.88 in a Docker builder on aarch64:

- `cargo fmt`: passed
- `cargo check`: passed
- `cargo test`: passed, 5 tests
- `cargo clippy --all-targets`: completed with existing non-fatal warnings
- Docker build of the original release Dockerfile: passed

The existing warnings are unrelated unused fields/functions and Clippy style advisories in the pre-existing code. They were not expanded into unrelated refactoring.

## Scope and limitations

This patch does not claim full S3 compatibility. The current project still has the previously documented limitations around Multipart Upload, Range GET, CopyObject, DeleteObjects, Tagging, and Lifecycle unless separately implemented in the source tree.

No production configuration, credentials, database, Telegram session, or runtime data is included in this package.

## Manual deployment note

After reviewing and committing the source, rebuild and deploy the image manually. Then reconfigure or verify OpenList with Path Style and the same TGS3 region, followed by a temporary-object test:

`ListObjectsV2 -> PUT -> HEAD -> full GET/hash -> DELETE`
