# Improvements — decisions on record

This file records decisions from code reviews that should not be
re-litigated. Items that named a concrete change have been applied; see
git history (test renames, check-script renames, the multi-backend feature,
the two documentation lines below). What remains here is either a rejected
alternative or a change deliberately deferred to a future point in the
deployment lifecycle.

## 1. Config and caching — homelab-scope review

A dedicated scan (scoped explicitly to homelab / small-private-cluster use,
not enterprise) reviewed every commonly-requested optimization angle. Its
finding: the codebase's existing "not yet" decisions hold up under scrutiny.
Recorded here so the reasoning isn't re-litigated:

- **DEK-unwrap cache — skip.** `Keyring::unwrap`'s AES path (HKDF-expand +
  AES-256-GCM decrypt of a 32-byte DEK) costs microseconds, dominated by the
  request's own I/O. Only the RSA-4096-OAEP path (~1-2ms) costs real CPU,
  and that's the write-only-ingestion-node case, not a homelab read hot
  path. A cache buys little and adds real invalidation risk across key
  rotation and `S3A_BIND_PATHS` changes.
- **Footer-cache default (1024) — skip, document only.** Comfortably covers
  a homelab's concurrently-hot multipart set. Documented in
  `docs/USER-GUIDE.md`'s `S3A_FOOTER_CACHE` row instead of a code change.
- **Backend connection pooling — already done.** `hyper_util`'s legacy
  client is built once in `ProxyState` and reused; no gap.
- **Missing S3 operations — already deliberate.** Only `UploadPartCopy` and
  `SelectObjectContent` return 501, and no homelab-relevant client
  (rclone, restic, Nextcloud, Borgbackup, aws-cli) needs either.
- **Key-export command — skip.** `s3armor keygen` prints one key at a time; there's
  no "export all active+rotated keys" command. The operator's own env file
  or compose file already is the backup. Adding an export path would
  partially undo the existing hardening that redacts secrets from `Config`'s
  `Debug` output, for marginal convenience. Documented in
  `docs/USER-GUIDE.md` "Backups" instead.

## 2. `${VAR}` interpolation in `config.toml` — considered, rejected

The `config.toml` loader deliberately does not support `${VAR}`-style
environment interpolation inside the file. The existing precedence rule —
environment variable overrides file value, which overrides default —
already answers "how do I avoid duplicating a value between the file and
the environment": put the value that varies per-deployment (secrets,
endpoints) in the environment, and the value that stays constant across
deployments in the file. Interpolation would add a second substitution
mechanism doing the same job with more moving parts.
