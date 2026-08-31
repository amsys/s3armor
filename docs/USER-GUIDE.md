# s3armor user guide

This guide is for the operator who runs s3armor. It covers install,
configuration, key handling, and daily operation. It does not cover the
internal design. For design and internals, see
[`ARCHITECTURE.md`](ARCHITECTURE.md).

s3armor sits between your S3 client (Nextcloud, Stalwart, rclone, restic,
s3cmd, aws-cli) and your S3-compatible storage (Hetzner Object Storage,
MinIO, AWS, Ceph RGW). It encrypts every object before it reaches storage.
The storage operator sees only ciphertext.

## 1. Install

s3armor ships as one static binary, `s3armor`. The binary has one Docker
image and one set of subcommands. There is no separate binary per tool.

### 1.1 Docker

```sh
docker pull ghcr.io/amsys/s3armor:0.1
```

The image entrypoint is `s3armor`. The default command is `serve`. Run any
other subcommand by naming it:

```sh
docker run --rm ghcr.io/amsys/s3armor:0.1 check --bucket my-bucket
```

A `-debug` build tag adds a profiling endpoint (see
[Metrics](#6-metrics), below). Do not run the `-debug` image in
production.

### 1.2 Proxmox LXC / bare systemd

The same static binary runs with no container runtime. Build it with
`cargo build --release` (produces `target/release/s3armor`), put it on the
LXC, add one env file, and add a small systemd unit:

```ini
# /etc/systemd/system/s3armor.service
[Service]
DynamicUser=yes
EnvironmentFile=/etc/s3armor/env
LoadCredential=master_key:/etc/s3armor/master.key
Environment=S3A_KEY_ACTIVE=K1
Environment=S3A_KEY_K1_FILE=%d/master_key
ExecStart=/usr/local/bin/s3armor serve
Restart=on-failure
```

`LoadCredential` alone only stages the key file under
`$CREDENTIALS_DIRECTORY` (`%d`) — the two `Environment=` lines are what
point `s3armor` at it; a unit with `LoadCredential` but no matching
`S3A_KEY_<NAME>_FILE` fails at startup with no key material configured.

Give the env file mode `0600`. It holds secrets, same as a Docker secret
mount, just in one file instead of one file per secret.

### 1.3 Shell completions

```sh
s3armor completions bash > /etc/bash_completion.d/s3armor
s3armor completions zsh  > "${fpath[1]}/_s3armor"
s3armor completions fish > ~/.config/fish/completions/s3armor.fish
```

## 2. Quickstart

Four steps: generate a key, point at a backend, preflight, run.

### Step 1 — generate a master key

```sh
openssl rand -base64 32
```

Set the output as `S3A_KEY_K1` (name must be `[A-Z0-9]+`), and
`S3A_KEY_ACTIVE=K1` to match:

```
S3A_KEY_ACTIVE=K1
S3A_KEY_K1=base64...
```

**The key is the only way to read your data. Back it up before you do
anything else** — a password manager, or another safe place. There is no
recovery path. See [Key generation and rotation](#4-key-generation-and-rotation).

### Step 2 — point at a backend

```sh
export S3A_BACKEND_ENDPOINT=https://fsn1.your-objectstorage.com
export S3A_BACKEND_ACCESS_KEY=...
export S3A_BACKEND_SECRET_KEY=...
export S3A_KEY_ACTIVE=K1
export S3A_KEY_K1=<the base64 line openssl printed>
```

Key names are matched case-sensitively. They must match `[A-Z0-9]+`.
`S3A_KEY_ACTIVE`'s value and the `S3A_KEY_<NAME>` suffix must agree
exactly, including case, or the proxy refuses to start.

You also need at least one client credential — the access key and secret
that your S3 client (Nextcloud, rclone, and so on) will use to talk to
the proxy:

```sh
export S3A_CLIENT_NEXTCLOUD_ACCESS_KEY=nextcloud
export S3A_CLIENT_NEXTCLOUD_SECRET_KEY=some-secret-you-pick
```

The proxy re-signs every request to the backend with the backend
credentials above. Client credentials only authenticate the client to
the proxy; they are never sent upstream.

### Step 3 — preflight the backend

```sh
s3armor check --bucket my-bucket
```

Run this before you point production traffic at a new backend. See
[The preflight check](#10-the-preflight-check-s3armor-check).

### Step 4 — run

```sh
s3armor serve
```

The proxy listens on `S3A_LISTEN` (default `0.0.0.0:8080`) and serves the
S3 API on that address. Point your S3 client at it with the client
credentials from step 2.

### Minimal docker-compose example

```yaml
services:
  s3armor:
    image: ghcr.io/amsys/s3armor:0.1
    ports: ["8080:8080"]
    environment:
      S3A_BACKEND_ENDPOINT: https://fsn1.your-objectstorage.com
      S3A_BACKEND_REGION: fsn1
      S3A_BACKEND_ACCESS_KEY: ${HETZNER_ACCESS_KEY}
      S3A_BACKEND_SECRET_KEY_FILE: /run/secrets/backend_secret
      S3A_CLIENT_NEXTCLOUD_ACCESS_KEY: nextcloud
      S3A_CLIENT_NEXTCLOUD_SECRET_KEY_FILE: /run/secrets/nc_secret
      S3A_KEY_ACTIVE: K1
      S3A_KEY_K1_FILE: /run/secrets/master_key
    secrets: [backend_secret, nc_secret, master_key]
secrets:
  backend_secret: {file: ./secrets/backend_secret}
  nc_secret: {file: ./secrets/nc_secret}
  master_key: {file: ./secrets/master_key}
```

This compose file is a complete, working system definition. There is no
other config file to write, unless you choose the optional TOML file
described below.

### Startup, health, and shutdown

At startup, missing or contradictory configuration is a fatal error. The
error message names the exact variable at fault, for example a missing
`S3A_BACKEND_ENDPOINT` or both `S3A_KEY_K1` and `S3A_KEY_K1_FILE` set at
once.

The proxy serves two unauthenticated endpoints for container health
checks:

- `GET /health` — liveness. Returns `503` while the proxy is draining
  (see below), otherwise `200`.
- `GET /ready` — readiness. Confirms the backend is reachable.

For containers without a shell, `s3armor health-probe` dials `/health`
itself and exits `0`/`1` accordingly — this is what the Docker image's
`HEALTHCHECK` runs. It reads `S3A_LISTEN` for the target port.

On `SIGTERM` or `SIGINT`, the proxy starts draining: `/health` starts
returning `503`, and the proxy finishes in-flight requests and exits. It
deliberately keeps *accepting* new connections during the drain — an
accept loop that stopped the instant the signal fired would make that
`503` unobservable, since every new probe connection would be refused
instead of answered. The drain window is bounded by `S3A_TIMEOUT_REQUEST`
(default 300 seconds) — give your orchestrator at least that much time
before it sends `SIGKILL`.

## 3. Configuration reference

Every setting is an environment variable with an exact, flat name. There
is no nesting and no `__` separator. Run `s3armor config` at any time to
print every effective value together with where it came from
(`default`, `env`, or a file path) — secrets are always printed redacted.
This is the fastest way to answer "why is my setting being ignored."

### 3.1 Secrets and the `_FILE` pattern

Every variable that carries a secret also accepts a `_FILE` sibling that
reads the same value from a file instead. This is the recommended
pattern for Docker, Podman, and Kubernetes secret mounts — the secret
never appears in `docker inspect`, process listings, or shell history.

The secret-bearing variables are:

- `S3A_BACKEND_SECRET_KEY` (and `S3A_BACKEND_<NAME>_SECRET_KEY` for a
  named backend — see [3.2a](#32a-multiple-backends))
- `S3A_CLIENT_<NAME>_SECRET_KEY`
- `S3A_KEY_<NAME>` (every key except the special name `ACTIVE`)
- `S3A_RSA_KEY`

(`S3A_RSA_PUBLIC` is not on this list — it is a public key, safe to log
and to place directly in `config.toml`.)

Setting both the plain variable and its `_FILE` sibling at the same time
is a fatal startup error. Set only one. Every one of these also works as
a `*_file` key in `config.toml` (`secret_key_file`, `key_file`,
`rsa_key_file`, ...) — see [3.3](#33-optional-configuration-file).

### 3.2 Full variable reference

| Variable | Meaning | Default |
|---|---|---|
| `S3A_LISTEN` | S3 API listen address | `0.0.0.0:8080` |
| `S3A_LOG` | tracing filter / log level | `info` |
| `S3A_LOG_FORMAT` | `text` or `json` | `text` |
| `S3A_BACKEND_ENDPOINT` | backend S3 URL | required |
| `S3A_BACKEND_REGION` | SigV4 region used to re-sign requests to the backend | `us-east-1` |
| `S3A_BACKEND_ACCESS_KEY` | backend access key | required |
| `S3A_BACKEND_SECRET_KEY` / `_FILE` | backend secret key | required |
| `S3A_TIMEOUT_CONNECT` | backend dial timeout, seconds | `10` |
| `S3A_TIMEOUT_REQUEST` | timeout from connect through response headers; also bounds the graceful-drain window on shutdown | `300` |
| `S3A_CLIENT_<NAME>_ACCESS_KEY` | inbound access key for one client; `<NAME>` matches `[A-Z0-9]+` | none |
| `S3A_CLIENT_<NAME>_SECRET_KEY` / `_FILE` | inbound secret key for that client | none |
| `S3A_CLIENT_<NAME>_BACKEND` | which backend this client's requests go to — a name from [3.2a](#32a-multiple-backends), case-insensitive | `DEFAULT` |
| `S3A_CHUNK_SIZE` | plaintext chunk size for new objects, bytes (valid range 65536–8388608) | `1048576` (1 MiB) |
| `S3A_ALG` | data algorithm: `auto`, `aes-gcm`, or `xchacha20-poly1305`. `auto` picks AES-GCM when the CPU has AES hardware, else XChaCha20-Poly1305 | `auto` |
| `S3A_KEY_ACTIVE` | name of the key used for new writes. Case-sensitive; must exactly match an `S3A_KEY_<NAME>` suffix, or the special value `RSA` to select the RSA key | required |
| `S3A_KEY_<NAME>` / `_FILE` | a 32-byte master key, base64-encoded. Configure as many as you like; keys other than the active one stay available for decrypting older objects during rotation | at least the active one required |
| `S3A_RSA_KEY` / `_FILE` | RSA private key, PEM. Configures a read-and-write node | none |
| `S3A_RSA_PUBLIC` / `_FILE` | RSA public key, PEM. Configures a write-only ingestion node: it can encrypt but never decrypt | none |
| `S3A_MP_TTL` | multipart session time-to-live, measured from the part's last activity. Accepts `24h`, `90m`, or a bare seconds count | `24h` |
| `S3A_FOOTER_CACHE` | number of entries in the multipart footer LRU cache (minimum 1). Raise only past 1024 concurrently-hot multipart uploads | `1024` |
| `S3A_METRICS` | Prometheus listen address, e.g. `0.0.0.0:9090`. A separate, **unauthenticated** listener. Unset turns metrics off | unset (off) |
| `S3A_TLS_CERT` | filesystem path to a PEM certificate chain. Unset means plain HTTP | unset |
| `S3A_TLS_KEY` | filesystem path to a PEM private key. Must be set together with `S3A_TLS_CERT`, or neither — one alone is a fatal startup error | unset |
| `S3A_AUTH_FAIL_LIMIT` | failed SigV4 attempts per source IP per minute before further attempts get `429 SlowDown`. `0` disables the limit. Source IP is the TCP peer only — see [Rate limiting](#7-rate-limiting) | `60` |
| `S3A_BIND_PATHS` | `off`, `on`, or `strict`. Binds the wrapped data key (and, for RSA, the OAEP label) to the object's bucket and key. See [Path binding modes](#8-path-binding-modes) | `off` |

Only `S3A_BACKEND_ENDPOINT`, `S3A_BACKEND_ACCESS_KEY`,
`S3A_BACKEND_SECRET_KEY` (or their named-backend equivalents, see next
section), and `S3A_KEY_ACTIVE` plus its matching key have no built-in
default. Every other variable works unset — including a deployment with
no clients configured yet, though such a deployment rejects every
request until at least one exists.

### 3.2a Multiple backends

One deployment can talk to more than one upstream S3. Which backend a
request reaches is decided entirely by which client credential signed
it — there is no per-bucket or per-path routing.

The plain `S3A_BACKEND_*` variables from the table above configure the
implicit backend named `DEFAULT`. Any number of additional backends can
be named explicitly:

```sh
export S3A_BACKEND_WASABI_ENDPOINT=https://s3.eu-central-2.wasabisys.com
export S3A_BACKEND_WASABI_REGION=eu-central-2
export S3A_BACKEND_WASABI_ACCESS_KEY=...
export S3A_BACKEND_WASABI_SECRET_KEY=...
```

`<NAME>` follows the same rule as a client name: `[A-Z0-9]+`, matched
case-insensitively (`wasabi`, `WASABI`, and `Wasabi` are the same
backend). `S3A_BACKEND_<NAME>_REGION` defaults to `us-east-1`, same as
`DEFAULT`'s.

Point a client at a non-default backend with `S3A_CLIENT_<NAME>_BACKEND`:

```sh
export S3A_CLIENT_OFFSITE_ACCESS_KEY=offsite
export S3A_CLIENT_OFFSITE_SECRET_KEY=some-secret-you-pick
export S3A_CLIENT_OFFSITE_BACKEND=wasabi
```

A client with no `_BACKEND` set uses `DEFAULT`. A client naming a
backend that isn't configured is a fatal startup error that lists every
backend name that *is* configured — the intent is that a typo here is a
one-command diagnosis, not a mystery 500 the first time that client
sends a request.

The encryption keyring is shared across every backend — the same master
keys wrap and unwrap objects regardless of which backend holds them, so
copying an object between backends never makes it undecryptable. Run
`s3armor config` to see, in one place, which client routes to which backend
and that backend's endpoint.

Every tool that talks to exactly one backend per run (`s3armor check`,
`s3armor rewrap`, `s3armor rebind`, and `s3armor bench --backend-tier`)
takes the same `--backend <NAME>` flag. The flag is optional when only
one backend is configured, and required — with the same "list every
configured name" error — once a second backend exists.

### 3.3 Optional configuration file

Environment variables are always enough on their own. If you prefer a
file — for example on an LXC with no compose file to hold the
non-secret settings — you may also give s3armor an optional TOML file.

Pass its path with `--config <path>`, for example `s3armor serve --config
/etc/s3armor/config.toml`. If you do not pass `--config`, s3armor looks for
`./s3armor.toml`, then `/etc/s3armor/config.toml`. If neither exists, s3armor runs
on environment variables and built-in defaults alone.

Precedence, highest first: **environment variable**, then **file
value**, then **built-in default**. An environment variable always wins
over the same setting in the file.

TOML keys are grouped into tables that map onto the flat environment
names. For example:

```toml
# /etc/s3armor/config.toml
[backend]                    # the implicit DEFAULT backend
endpoint = "https://fsn1.your-objectstorage.com"
region = "fsn1"

[backends.wasabi]            # an additional, named backend
endpoint = "https://s3.eu-central-2.wasabisys.com"
region = "eu-central-2"
access_key = "..."
secret_key_file = "/run/secrets/wasabi_secret"

[clients.nextcloud]
access_key = "nextcloud"     # no `backend` -> routes to DEFAULT

[clients.offsite]
access_key = "offsite"
backend = "wasabi"

[keys]
active = "K1"
```

`[backend] endpoint` maps to `S3A_BACKEND_ENDPOINT`. `[backends.wasabi]
endpoint` maps to `S3A_BACKEND_WASABI_ENDPOINT`. `[clients.nextcloud]
access_key` maps to `S3A_CLIENT_NEXTCLOUD_ACCESS_KEY`. `[keys] active`
maps to `S3A_KEY_ACTIVE`.

**Secrets are never allowed inline in the TOML file.** Any key from the
secret list in [3.1](#31-secrets-and-the-_file-pattern) — a backend
secret key, a client secret key, a master key, an RSA key — is rejected
if it appears directly in the file. s3armor refuses to start and names the
offending key. Secrets must come from an environment variable, or from a
`*_file` key in the file (`secret_key_file`, `key_file`,
`rsa_key_file`, ...) pointing at a mounted secret — same idea as the
env-side `_FILE` pattern, just written as its own TOML key rather than a
suffix. The example above's `[backends.wasabi] secret_key_file` is one;
`S3A_CLIENT_NEXTCLOUD_SECRET_KEY` and `S3A_KEY_K1` still come from the
environment or an env-side `_FILE` mount, since this file doesn't set
them at all — a config file can be complete and shareable without a
single secret in it.

## 4. Key generation and rotation

### 4.1 Back up the master key

The master key is the only thing standing between your ciphertext and
noise. There is no recovery path. If you lose the key, every object it
protects is unreadable forever. The storage provider cannot help you —
they only ever held ciphertext.

Read this warning every time you make a key. Store the key in a password
manager, or another safe place, **before** you write a single object with
it.

```sh
openssl rand -base64 32
```

prints a 32-byte AES key as one base64 line — set it as `S3A_KEY_<NAME>`
(Quickstart, Step 1). There's no separate command to look up the key id it maps
to: `s3armor` derives it internally from the key bytes and stamps it on every
object it encrypts, so you don't need it up front. For a paper or offline
backup, feed the same random bytes through any BIP39 tool you trust
(`openssl rand -hex 32` first if the tool wants hex rather than base64).

For a write-only ingestion node, generate an RSA-4096 keypair instead:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Set `S3A_RSA_KEY_FILE=private.pem` (keep private, full read/write node) or
`S3A_RSA_PUBLIC_FILE=public.pem` (safe to distribute, write-only node —
see docs/ARCHITECTURE.md "Keys and wrap"). Never let both files exist on the same
node unless it's meant to read.

### 4.2 Rotating keys

Add a new key alongside the old one, then flip which key is active:

```sh
S3A_KEY_ACTIVE=K2026
S3A_KEY_K2026_FILE=/run/secrets/k2026
S3A_KEY_K2025_FILE=/run/secrets/k2025   # kept so old objects still decrypt
```

New writes use the active key. Reads pick whichever key made the
object, by its key id. Nothing else changes.

To re-wrap existing objects under the new active key — metadata-only,
no data movement, since only the wrapped key changes, not the object
data — run:

```sh
s3armor rewrap --bucket my-bucket
```

Useful flags:

- `--prefix <p>` — only objects under this key prefix.
- `--workers <n>` — parallel workers (default 4).
- `--checkpoint <file>` — an append-only file of already-rewrapped keys,
  so the run is resumable after an interruption.
- `--dry-run` — report what would happen; write nothing.

Once you are sure every object you care about is rewrapped, you may
retire the old key by removing its `S3A_KEY_<NAME>` variable.

### 4.3 Path binding migration

If you turn on `S3A_BIND_PATHS`, existing objects written before the
switch need a metadata-only pass to gain their binding. See
[Path binding modes](#8-path-binding-modes) for when this is needed.

```sh
s3armor rebind --bucket my-bucket
```

Same flags as `rewrap` (`--prefix`, `--workers`, `--checkpoint`,
`--dry-run`), plus:

- `--from-bucket <old-name>` — try the named bucket's binding for
  objects that do not unwrap under the current bucket or an empty
  binding. Use this after restoring a bucket under a new name.

`s3armor rebind` always re-wraps under the currently active key. If you want
key rotation and path-binding migration as two separate, auditable
steps, run `s3armor rewrap` first, then `s3armor rebind`.

## 5. TLS

By default the proxy speaks plain HTTP. Set both `S3A_TLS_CERT` and
`S3A_TLS_KEY` to filesystem paths of PEM files (a certificate chain and
its private key) to terminate TLS directly on the S3 listener — useful
for a bare LXC with no reverse proxy in front of it.

Setting only one of the two variables is a fatal startup error naming
the variable you forgot. Set both, or set neither.

Most container deployments are better served by a TLS-terminating
reverse proxy (Caddy, nginx, Traefik) or a private network in front of
plain HTTP, which is why plain HTTP stays the default.

## 6. Metrics

Set `S3A_METRICS` to an address, for example `0.0.0.0:9090`, to serve
Prometheus text exposition on `/metrics` at that address. This listener
is separate from the S3 port and off by default.

**This listener has no authentication of any kind.** Never expose it on
a public interface. Restrict it to a private network or a loopback
address only.

This warning matters even more for a `-debug` image. The `-debug` build
adds a profiling endpoint on the same metrics listener. A flamegraph
names internal functions and shows their timing — it is more sensitive
than a plain counter. Never run a `-debug` image with its metrics port
reachable beyond a private interface, and never publish it.

## 7. Rate limiting

`S3A_AUTH_FAIL_LIMIT` (default `60`) caps failed SigV4 authentication
attempts per source IP per minute. Once a source IP goes over the
limit, further attempts from it get `429 SlowDown` without even being
checked. Set it to `0` to disable the limit.

Source IP means the TCP peer address only. `X-Forwarded-For` is never
trusted, because a client can set it to anything. If s3armor sits behind a
reverse proxy, every client's traffic arrives from the same peer
address — the proxy's own address — so the limit collapses onto one
IP shared by everyone. **Set `S3A_AUTH_FAIL_LIMIT=0` when s3armor sits
behind a reverse proxy**, or a single client's failed logins can lock
out every other client.

## 8. Path binding modes

`S3A_BIND_PATHS` binds each object's wrapped data key to its bucket and
object key. This detects an object swap by an attacker who has write
access to your backend storage: without binding, swapping two encrypted
objects' bytes on the backend goes undetected on read (the ciphertext
still decrypts, just as the wrong object). With binding, the swapped
object fails to decrypt instead of silently returning wrong data.

Three modes, not a plain on/off, because turning this on must not break
every object written before the feature existed:

- **`off`** (default) — no binding. Today's behavior. Every object,
  old or new, reads normally.
- **`on`** — new writes get the binding. Reads try the bound form
  first, then fall back to the unbound form. Safe to turn on
  immediately, on an existing bucket, with no migration step first —
  nothing becomes unreadable, and new writes start gaining the
  protection right away.
- **`strict`** — binding is required, with no fallback. An object
  without the binding fails to read. This is the retirement switch:
  turn it on only after every object in the bucket has been migrated
  with `s3armor rebind` (see [4.3](#43-path-binding-migration)). Turning
  on `strict` before migrating makes every not-yet-migrated object
  unreadable.

Migration cost: turning on `on` costs nothing up front. Reaching
`strict` costs one `s3armor rebind` pass over the whole bucket — a
metadata-only operation, so no object data moves, but every object
needs to be visited once.

Path binding does not detect a rollback to an older, still-authentic
version of an object in any mode. Use your backend's own bucket
versioning to guard against that.

## 9. Supported S3 operations

The proxy only intercepts operations where bytes or sizes change under
encryption. Everything else — bucket listing, ACLs, lifecycle rules,
versioning, tagging, policy — passes straight through to the backend
and gets the backend's own, correct response.

| Operation | Support |
|---|---|
| PutObject | Full. Streaming encrypt; `aws-chunked` request bodies decoded and their chunk signatures verified. |
| GetObject | Full. Routes to v1 or plain-passthrough handling as needed; every chunk is verified before any byte reaches the client. Range requests return proper `206` responses. |
| HeadObject | Full. Reports the correct plaintext size. |
| CreateMultipartUpload / UploadPart / CompleteMultipartUpload / AbortMultipartUpload | Full. Retrying `CompleteMultipartUpload` is safe — it returns the cached response. |
| ListParts | Full passthrough. Reported part sizes are ciphertext sizes — see [Known limits](#11-known-limits). |
| CopyObject | Supported for most sources. |
| UploadPartCopy | **501 Not Implemented.** Ciphertext cannot be re-chunked on the backend side. |
| GetObject with `?partNumber` | **501 Not Implemented.** Fetch the whole object instead. |
| GetObjectAttributes | Full passthrough. Reported size and ETag are ciphertext — see [Known limits](#11-known-limits). |
| DeleteObject / DeleteObjects | Full passthrough. |
| ListBuckets / ListObjectsV2 | Full passthrough. Reported sizes are ciphertext sizes — see [Known limits](#11-known-limits). |
| Bucket sub-resources (ACLs, lifecycle, versioning, tagging, policy, CORS) | Full passthrough, including CORS preflight (`OPTIONS`), answered from the backend's own bucket configuration. |
| Presigned URLs (query-string SigV4) | Full support. |
| SelectObjectContent | **501 Not Implemented.** |

If a client sends an operation not in this table, the proxy passes it
through verbatim and returns the backend's own response.

## 10. The preflight check (`s3armor check`)

`s3armor check` is a preflight and health probe for a backend. Run it with
the same environment as `serve`, before you cut real traffic over to a
new backend:

```sh
s3armor check --bucket my-bucket
```

It confirms, in order: the endpoint is reachable and its TLS is sound
(warning loudly if you configured plain `http://`), your credentials
authenticate, a small put/get/delete round-trip works, your encryption
metadata survives a PUT-then-HEAD cycle intact, there is enough
metadata headroom for your key type, multipart uploads with a small
final part are accepted, ranged GET works, CopyObject preserves user
metadata, and checksum trailers behave as expected. It prints a verdict:
compatible, degraded (naming what breaks), or incompatible.

**Exit code reflects only `incompatible`.** `compatible` and `degraded`
both exit `0` — a `degraded` backend still works, just with a named
caveat, so it does not fail the command. Only `incompatible` exits `1`.
A script gating a deploy on `s3armor check && deploy` passes through a
`degraded` warning; read the printed verdict, not just the exit code, if
that distinction matters to you.

**`s3armor check` writes and deletes real objects in the bucket you point
it at.** Every probe object it creates is deleted before the command
exits, but it is still live traffic against a live bucket. Never point
`s3armor check` at a production bucket you care about — use a scratch
bucket, or run it against a new backend before any real data lands
there.

## 10a. Tuning with `s3armor bench`

`s3armor bench` measures local crypto and backend throughput on the host
CPU, and recommends a `S3A_ALG`/`S3A_CHUNK_SIZE` block for it:

```sh
s3armor bench --write-config
```

Paste the printed block into your environment or `config.toml`. Run it
once per deployment target — a low-power ARM NAS and a modern amd64 box
pick different AES-GCM-vs-XChaCha20 tradeoffs, which is why `S3A_ALG`
defaults to `auto` rather than a fixed choice.

## 11. Known limits

These are current, deliberate limits an operator should plan around:

- **No virtual-hosted-style addressing.** Only path-style bucket
  addressing (`https://host/bucket/key`) is supported. Configure your
  client accordingly.
- **List operations report ciphertext sizes**, not plaintext sizes.
  `ListObjectsV2` and similar operations show the size of the encrypted
  object on the backend, which is slightly larger than the original
  file (plus a fixed overhead per multipart object). Applications that
  read sizes from list results, rather than from `HeadObject`, will see
  the larger number.
- **ETag on PUT, HEAD, and GET reflects ciphertext**, unless the client
  sent a checksum header on the PUT. If the client sends `Content-MD5`
  on upload, the proxy verifies it and all three operations agree on
  that plaintext ETag. Modern SDKs default to a different checksum
  scheme (`x-amz-checksum-crc32`) instead of `Content-MD5` — aws-cli v2,
  boto3, and rclone all do this — and in that case you get the
  ciphertext ETag everywhere, which is still consistent across PUT,
  HEAD, and GET, just not equal to a plaintext MD5. A plaintext
  `Content-MD5` cannot be produced after the fact mid-stream, so there
  is no way to add one after upload.

## 12. Backups

**Back up your master key** — the value or file behind your active
`S3A_KEY_<NAME>` — before you store anything with it. Store the backup
somewhere separate from the backend it protects: a password manager, a
BIP39 paper backup (any BIP39 tool, fed the same 32 random bytes), or
both.

Losing the master key makes every object it encrypted permanently
unrecoverable. There is no recovery path, and the storage provider
cannot help you — they only ever held ciphertext, never the key.

Back up your whole env or compose file, not only the active key. Rotated
keys stay in `S3A_KEY_<NAME>` only long enough to decrypt older objects,
and losing one of those is just as unrecoverable as losing the active
key.

## 13. Further reading

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — design and internals: how
  encryption, key wrapping, and multipart handling work under the hood.
