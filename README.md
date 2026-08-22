# s3armor

*Client-side encryption proxy for S3, forged in Rust.*

A small, fast client-side encryption proxy for S3-compatible storage
(Hetzner Object Storage, MinIO, AWS, Ceph RGW). "Server-side encryption"
leaves the key with the storage operator. This proxy makes the ciphertext
the only thing the operator ever sees.

Built for a homelab or a small private cluster: one static binary, flat
environment-variable or `config.toml` configuration, no external database,
no control plane. Point your S3 client at s3armor instead of your bucket,
and every object your client writes becomes ciphertext before it ever
leaves your network.

## Why

Storage-side encryption protects your data from a stranger who steals a
disk. It does nothing against the storage operator itself, or anyone who
can subpoena, breach, or misconfigure their account. Client-side
encryption closes that gap: the key never leaves your control, so the
operator holds ciphertext and nothing else.

## Features

- **Drop-in S3 proxy** — SigV4 request re-signing, so existing S3 clients
  (aws-cli, rclone, restic, Nextcloud, Borgbackup) work unmodified.
- **Authenticated encryption per object** — AES-256-GCM or XChaCha20-Poly1305,
  picked automatically for the CPU it runs on.
- **Streaming multipart** — large uploads encrypt part-by-part, no
  whole-object buffering.
- **Key rotation and write-only nodes** — rotate the active key without
  re-encrypting existing objects; run an ingestion-only node that can
  encrypt but never decrypt.
- **TLS, metrics, rate limiting** — built in, no reverse proxy required.

## Quickstart

```sh
# 1. Generate a master key. Back this up now — it's the only way to read
#    your data, and there is no recovery path if it's lost.
openssl rand -base64 32
# <base64 key printed here>

# 2. Point it at a backend.
export S3A_BACKEND_ENDPOINT=https://fsn1.your-objectstorage.com
export S3A_BACKEND_ACCESS_KEY=...
export S3A_BACKEND_SECRET_KEY=...
export S3A_KEY_ACTIVE=K1
export S3A_KEY_K1=<the base64 line openssl printed>

# 3. Preflight the backend before pointing production traffic at it.
s3armor check --bucket my-bucket

# 4. Run.
s3armor serve
```

Prefer a config file over exporting variables? See
[`docs/USER-GUIDE.md`](docs/USER-GUIDE.md) for the full `config.toml`
reference, every `S3A_*` variable, TLS, metrics, and rate limiting.

## The wallet warning

The master key is the data. If you lose it, encrypted objects are noise —
the storage provider cannot help you. Store the key in a password manager
before you store a single object.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design and how it works.
- [`docs/USER-GUIDE.md`](docs/USER-GUIDE.md) — install, configure, operate.
- [`docs/DEVELOPER-GUIDE.md`](docs/DEVELOPER-GUIDE.md) — build, test, contribute.

Contributing: run `pre-commit install --install-hooks` once per clone —
see [`docs/DEVELOPER-GUIDE.md`](docs/DEVELOPER-GUIDE.md) for the full
contributor guide.

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
