# Architecture

This document is the design record for s3armor. It states what the proxy
does, why it is built this way, and which designs were rejected and must not
be re-litigated. Code comments cite this document by section name, for
example `docs/ARCHITECTURE.md "Data: chunked AEAD"`.

This document covers design and mechanism, not step-by-step operator
instructions — those live in the user guide.

---

## Purpose and threat model

s3armor is a client-side encryption proxy for S3-compatible storage. It sits
between an application that speaks S3 (Nextcloud, Stalwart, restic, rclone,
s3cmd, aws-cli) and a backend (Hetzner Object Storage, MinIO, AWS, Ceph RGW).

S3 "server-side encryption" (SSE) leaves the encryption key with the storage
operator. The operator can read every object at will. SSE protects against a
stolen disk. It does not protect against the operator itself, or against
anyone who gains access to the operator's systems. This proxy changes that.
The proxy holds the key. The backend never sees plaintext, and never sees
the key. Ciphertext is the only thing the storage operator ever sees.

### Threat model

**In scope.** An attacker who can read and write the backend directly
(a hostile or compromised storage operator, or anyone with stolen backend
credentials):

- Cannot read plaintext of any v1 object. AEAD keys never reach the backend.
- Cannot forge or silently modify a v1 object. Every v1 chunk is
  authenticated. A tampered chunk fails verification before any plaintext
  reaches the client.
- Can swap two encrypted objects (copy `a`'s ciphertext and metadata onto
  `b`'s key) in the default configuration. This is undetectable unless
  `S3A_BIND_PATHS` is enabled ("Path binding").
- Can roll an object back to an older, authentic version. No mode detects
  this. Backend bucket versioning is the mitigation, not this proxy.
- Can delete objects, or deny service. Encryption does not defend
  availability.

**Out of scope.** A compromised proxy host: the proxy holds keys and
plaintext in memory while serving a request, by necessity. An attacker with
code execution or memory access on the proxy host can read both. A
compromised client: this proxy authenticates itself as one more S3 client
seat with valid credentials; it does not defend against a legitimate,
malicious caller.  A network attacker without backend credentials: SigV4
authentication and TLS are the existing defenses, unchanged in nature from a
standard S3 deployment.

---

## Goals and non-goals

### Goals

1. Transparent S3 encryption for real clients: Nextcloud, Stalwart,
   rclone/restic, s3cmd/aws-cli.
2. All data is authenticated (AEAD). The proxy verifies every chunk
   before it reaches the client. There is no integrity on/off switch.
3. Low, bounded memory per stream. The proxy runs in a small container or a
   256 MiB Proxmox LXC.
4. Minimal configuration. A docker-compose file can be the complete system
   definition. A config file is optional, never required.
5. Key handling is a first-class feature: generate, fingerprint, back up
   ("wallet"), rotate. The proxy gives a loud, unmissable "store this key
   safely" warning.
6. Profiling-friendly build and runtime from day one.
7. Benchmarks (`s3armor bench`) that recommend settings, and a user-launched
   backend conformance probe (`s3armor check`).

### Non-goals (v1)

- Full S3 API emulation. An operation this proxy does not intercept passes
  through verbatim. Nothing is faked: no invented XML, no fabricated
  `SelectObjectContent` results.
- Multi-replica high availability for in-flight multipart uploads. The
  proxy runs as a single instance.
- KMS, Vault, or Tink integration. Keys come from files or environment
  variables. The key-id scheme leaves room to add a KMS backend later.
- Object-key (filename) encryption. It would break List and prefix
  semantics. Nextcloud's primary-storage keys are already opaque
  `urn:oid:` values, so filename encryption gains nothing there.
- SigV2, `SelectObjectContent`, S3 Object Lambda, and acceleration
  endpoints.

---

## Architecture: re-signing streaming reverse proxy

The proxy does not model the S3 API as a typed, per-operation interface. It
is an HTTP reverse proxy with SigV4 re-signing. It intercepts only the
operations where the byte stream or its size changes; every other operation
passes through untouched.

```
S3 client ──► hyper server (path-style; virtual-host = later Host rewrite)
               │ verify client SigV4 — incl. payload hash & aws-chunked
               │ chunk signatures; presigned query auth supported
               │ strip client auth + Content-MD5 + x-amz-checksum-* headers
               ▼
        ┌─ interceptor? ──────────────────────────────┐
        │ yes:                                        │ no:
        │  PutObject        → encrypt stream (v1)     │  pass request through
        │  GetObject        → decrypt v1, ranges      │  verbatim (headers
        │  HeadObject       → plaintext size fixup    │  filtered), body
        │  CreateMultipart  → mint DEK, set metadata  │  streamed, backend's
        │  UploadPart       → encrypt part (indep.)   │  own XML returned
        │  CompleteMultipart→ append footer, complete │  untouched
        │  AbortMultipart   → drop session            │
        │  CopyObject       → see "S3 operation       │
        │                      matrix (v1)"           │
        └──────────────┬──────────────────────────────┘
                       ▼
              re-sign with backend credentials (aws-sigv4)
                       ▼
              hyper client (pooled, rustls) ──► backend S3
```

Consequences:

- `ListBuckets`, `ListObjectsV2`, `DeleteObject(s)`, every bucket
  sub-resource, ACLs, lifecycle, versioning, tagging, policy — all pass
  through and return the backend's own correct XML. There is no bucket
  handler tree in this proxy to get that XML wrong.
- New backend features work without a proxy release, because the proxy does
  not model them.
- The interceptor list is the complete, auditable crypto surface. Anyone
  reviewing this proxy for correctness needs to read only that list.

Multi-backend: a client entry may pin a `backend` by name. An unpinned
client always resolves to `DEFAULT` — never a random or "first configured"
choice — so a deployment with only named backends fails at load rather
than guessing. A CORS preflight carries no client identity to resolve a
backend from at all ("S3 operation matrix (v1)"); that one case falls back to `DEFAULT` if
configured, else whichever backend sorts first. One connection pool per
backend, shared across requests.

Concurrency: one task per connection, `Body`-to-`Body` streaming
transforms. The proxy buffers a full object only on the explicit small-object
fast path (objects that fit in one chunk); every other path streams.

---

## Cryptographic design (format v1)

### Keys and wrap

Two key providers exist, named by `s3a-kek` in object metadata:

- **`aes`** — a 32-byte master key. The proxy wraps each object's DEK with
  AES-256-GCM, using a random 12-byte nonce and AAD = `"s3a1-kek" ‖ key_id`.
  The wrap is authenticated: a tampered wrapped DEK fails to unwrap instead
  of silently producing garbage.
  - KEK = HKDF-SHA256(master_key, info=`"s3a/v1/kek"`).
  - key_id = hex(first 8 bytes of HKDF(master_key, info=`"s3a/v1/kid"`)).
    The KEK and the key id use separate HKDF `info` strings, so they stay in
    different domains: a published key id reveals nothing about the KEK. The
    id gives no offline advantage in any case, because the master key is 32
    random bytes and cannot be guessed.
- **`rsa`** — kept for write-only ingestion nodes. The proxy wraps the DEK
  with RSA-OAEP-SHA256. key_id = hex(first 8 bytes of SHA-256 of the SPKI
  DER encoding); a hash is safe here because the public key is not secret.
  - A write-only node holds only the public key. It can encrypt (wrap DEKs)
    but can never decrypt. `GetObject` on an encrypted object returns an
    explicit `KeyNotAvailable` error ("Write-only (RSA) nodes cannot serve
    GETs"). A compromised ingestion node leaks nothing at rest.
  - A read/full node holds the private key; the public key is derived from
    it.
  - A 4096-bit wrap produces a 512-byte wrapped DEK, about 684 base64
    characters — well inside the 2 KB user-metadata limit. `s3armor check`
    probes this limit against the configured backend.

### Data: chunked AEAD

Two algorithm ids exist: `1` = AES-256-GCM, `2` = XChaCha20-Poly1305.
`s3armor bench` measures both on the host CPU; the default is chosen by CPU
feature detection unless pinned by configuration.

The proxy splits plaintext into fixed `chunk_size` chunks (default 1 MiB,
configurable from 64 KiB to 8 MiB). Each chunk becomes one frame:

```
frame = nonce ‖ AEAD(key=DEK, nonce, aad, chunk)
      = nonce(12|24) ‖ ciphertext ‖ tag(16)
aad   = "s3a1" ‖ alg_id(u8) ‖ part_number(u32 LE) ‖ chunk_index(u64 LE) ‖ last_flag(u8)
```

- Each chunk gets a fresh random nonce, stored in-band. A retried or
  parallel-encrypted part can never reuse a (key, nonce) pair. This one
  property removes an entire class of shared-keystream multipart failures:
  retried, duplicate, and out-of-order parts are safe by construction.
- `chunk_index` in the AAD stops chunk reordering. `last_flag` stops
  truncation. `part_number` (0 for single-part objects) stops splicing
  chunks from one part into another.
- Size math is exact and invertible:
  `ciphertext_len = plaintext_len + n_chunks × (nonce_len + 16)`. `GetObject`
  and `HeadObject` report the exact plaintext `Content-Length` from this
  formula. A range request maps a plaintext byte range to the covering
  ciphertext chunks, verifies their tags, trims to the requested range, and
  returns a real `206` with `Content-Range`.
- Integrity is always on. Every chunk is verified before the proxy releases
  it to the client. There is no mode that skips verification.

**Invariant — do not simplify the release order.** A streaming decoder must
verify a frame's AEAD tag *before* handing that frame's plaintext to the
HTTP response body. Releasing a frame first and checking it after is not an
equivalent reordering: once bytes reach the client, a failed check
afterward cannot un-send them — and because `Content-Length` is set up
front, the HTTP layer stops polling the body once all bytes are written, so
an error sent after the last byte is never observed by the client. Any
streaming decoder in this codebase must verify each frame before releasing
it, and a test must assert that a corrupted stream makes the request fail,
not merely that the output differs from the correct plaintext (a corrupted
stream almost always differs from the correct plaintext regardless of
whether the check ran).

### Object metadata v1

Every value below is known before the upload body starts. This makes a
self-copy-at-Complete pattern structurally impossible here, not merely
avoided.

| `x-amz-meta-` key | value |
|---|---|
| `s3a-v` | `1` — the format version |
| `s3a-alg` | `1` / `2` |
| `s3a-kek` | `aes` / `rsa` |
| `s3a-kid` | key id, 16 hex characters |
| `s3a-dek` | base64(nonce ‖ wrapped DEK ‖ tag), or base64(RSA-OAEP blob) |
| `s3a-chunk` | chunk size in bytes |
| `s3a-mp` | `1`, only on multipart objects — marks that a footer exists |
| `s3a-emd5` | optional: AEAD(DEK, MD5(plaintext)) — see "ETag policy" |

Decrypt routing order on read: `s3a-v=1` present → v1 path. Else →
passthrough (a pre-existing plaintext object). An unrecognized `s3a-kid`
returns an explicit `KeyNotAvailable` error, never a silent failure. The
proxy strips exactly the `s3a-*` metadata set from every response it
returns to the client — and, symmetrically, from every incoming request
before forwarding: a client cannot set its own `x-amz-meta-s3a-*` value
(`headers::strip_for_backend`), so a forged `s3a-mp` on a plain PUT can
never route a later GET/HEAD of that object into the wrong decrypt path.

### Multipart v1

Each part is encrypted as an **independent** chunked stream under the
session DEK, with `part_number` in every frame's AAD. Parts encrypt in
parallel, retry safely (a retry gets fresh random nonces and simply
overwrites its predecessor on the backend), and can arrive in any order.
There is no shared keystream, no ordering channel, no parking, and no
reorder buffer.

Session state held per upload: `{DEK, algorithm, chunk_size, per-part
plaintext sizes, part ETags}` — a few hundred bytes, held in memory. The
session TTL is measured from **last activity**, not creation, and is swept
by a task that actually runs.

**Footer part.** At `CompleteMultipartUpload`, the proxy uploads an
encrypted, authenticated record: `{version, (client part number, plaintext
size) per part, total plaintext size, optional plaintext MD5}`, plus a
fixed 16-byte trailer (`magic ‖ footer_len`). Part numbers are recorded, not
only sizes, because client part numbers can be non-contiguous (1, 5, 9 is
legal S3) and position alone cannot stand in for them.

The footer cannot always be appended as one more part. S3 requires every
part except the last to be at least 5 MiB. Appending the footer as an
extra final part would turn the client's real final part — usually well
under 5 MiB — into a middle part, and the backend would reject the whole
upload. The fix: the proxy buffers every sub-5-MiB part's ciphertext by
part number (capped, lowest part number evicted first once the cap is
hit), because a legal `CompleteMultipartUpload` can name any previously
uploaded part as the last one, not just the highest part number ever seen
— an unreferenced part is simply discarded by real S3. A part re-uploaded
at 5 MiB or larger clears its own buffer entry. At Complete: if the
client's actual final part is still buffered, the proxy re-uploads it
merged with the sealed footer under the same part number — no extra part,
no size problem; if it is not buffered but is itself at least 5 MiB, the
footer goes up as its own part; if it is not buffered and still under 5
MiB (evicted by the cap), Complete is rejected with `InvalidPart` rather
than letting the backend reject the whole upload with an opaque
`EntityTooSmall`. Either way a successful Complete's raw byte stream is
identical: every part's ciphertext, then the footer frame, then the
trailer.

- `HeadObject`, sequential `GetObject`, and ranged `GetObject` on multipart
  objects resolve sizes with one ranged read of the footer (the last 16
  bytes, then the footer itself), cached in a small LRU.
- **Complete is safe to retry.** SDKs retry `CompleteMultipartUpload`. The
  session is not deleted at Complete; it is marked completed with the
  response cached, and expires only by TTL. A retried Complete returns the
  cached response.
- **Part-list validation.** The proxy compares the client's submitted part
  list against its own recorded ETags and returns `InvalidPart` on any
  mismatch.

### Path binding

`S3A_BIND_PATHS` adds `bucket ‖ object_key` to the DEK-wrap AAD (data
chunks stay path-free), and, for an RSA KEK, as the OAEP label (as
`hex(SHA-256(binding))`, since an OAEP label must be valid text and an
object key may not be).

This detects an object-swap by an attacker with backend write access. A
plain server-side copy that overwrites object `b`'s ciphertext and metadata
with object `a`'s decrypts cleanly when binding is off — both objects carry
an empty binding, so `b`'s DEK-unwrap step authenticates `a`'s wrapped DEK
without complaint. With binding on, `a`'s wrapped DEK carries an AAD that
names `a`; unwrapping it while serving path `b` fails AEAD authentication
instead of silently returning the wrong object.

The setting is three-valued, not boolean:
`S3A_BIND_PATHS=off|on|strict` (default `off`). A plain on/off switch would
be unsafe to flip on an existing bucket: every object wrapped before the
feature existed has an empty binding, and requiring a match would make all
of them unreadable the moment the flag changes.

- `off` — wrap and unwrap with an empty binding. This is the default,
  matching pre-binding behavior.
- `on` — wrap bound; unwrap tries the bound AAD first, then falls back to
  the empty one. Safe to enable on an existing bucket with no prerequisite
  step. Nothing becomes unreadable, and new writes start gaining the
  protection immediately.
- `strict` — wrap and unwrap bound only, with no fallback. This is the
  retirement switch: without it, an unbound object is indistinguishable
  from a bound one that an attacker swapped, so "bound" gives no real
  guarantee until every object has actually been rebound.

Costs: an out-of-band copy, or a bucket rename used to restore data, needs
`s3armor rebind` (a metadata-only rewrap under the object's current path, with
a `--from-bucket` fallback for the renamed-bucket case). `CopyObject`
becomes a rewrap interceptor (unwrap under the source binding, re-wrap
under the destination binding) instead of pure passthrough whenever the
mode is not `off`. Rollback to an older authentic version is undetected in
every mode; backend bucket versioning is the mitigation.

### Zeroization

No `Debug` or `Display` implementation in this proxy prints key material;
logs carry key **ids** only. `Keyring` and `Config` each have a
manual `Debug` implementation that redacts or omits key and secret bytes.

There is no DEK cache. Unwrapping a DEK costs about 1 microsecond for
AES-GCM. A DEK cache keyed by object name rather than by content is a known
source of data-corruption bugs when an object is overwritten and the cache
goes stale, so this design avoids one outright rather than build it and
then have to fix it. If RSA unwrap latency (which is in the low
milliseconds) ever matters on a read-heavy node, the design allows a cache
keyed by the wrapped DEK bytes themselves — content-addressed, so it cannot
go stale the way a key-plus-object-name cache would — bounded, TTL'd, and
zeroizing on eviction. Build that only once a benchmark demands it.

`zeroize` is used at exactly three sites: the `MasterKey` type derives
`ZeroizeOnDrop`; the HKDF-derived KEK copy is zeroized immediately after
the cipher is built from it; and a multipart session's DEK is zeroized on
`Drop`. Every other DEK in the system — the one a PUT or multipart-create
mints, the one key resolution returns, the copy each streaming encryptor or
decryptor holds for the life of one request body — is a bare 32-byte array
with no zeroizing wrapper. These are short-lived stack values on a hot
path, not persistent state, unlike `Config`, which holds secrets for the
whole life of the process and does get the `Debug`-redaction treatment
above. A blanket zeroizing sweep across the whole crypto surface would be
real code for no measured reduction in exposure, so it stays a documented
gap. Revisit it only when a specific threat — core dumps of a long-lived
process, or swap-without-encryption — drives which values actually need
it.

---

## Key handling

The operator-facing "how to use it" steps live in the user guide. This
section covers the mechanism.

Key material is generated with `openssl`, not a dedicated subcommand —
`openssl rand -base64 32` for the 32-byte AES master key,
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096` for the
OAEP keypair (write-only nodes). The key is the data: store a copy
somewhere safe before writing anything with it; if it's lost, the objects
are noise the storage provider cannot help recover. `s3armor` never computes
or displays a key id up front — it derives one internally from the key
bytes (`MasterKey::key_id`/`RsaKek::key_id`, `crates/s3armor-format/src/v1/wrap.rs`)
and stamps it on every object as it encrypts, so the operator never needs
to know it in advance.

Key sources, in precedence order:

1. `S3A_KEY_<NAME>_FILE=/run/secrets/master.key` — a file path (the Docker
   or Podman secret convention).
2. `S3A_KEY_<NAME>=base64…` — the key given directly as an environment
   variable.

The optional `config.toml` adds no third form. A `[keys]` entry such as
`K1_file = "/run/secrets/master_key"` lowers to `S3A_KEY_K1_FILE` before
`Config` reads it, and inline key material in the file is rejected
("Configuration model").

Rotation uses key ids and needs no data movement:

```
S3A_KEY_ACTIVE=K2026
S3A_KEY_K2026_FILE=/run/secrets/k2026
S3A_KEY_K2025_FILE=/run/secrets/k2025    # read-only, decrypts old objects
```

Every write uses the active key. Every read selects its key by the
object's stored `s3a-kid`. `s3armor rewrap` re-wraps DEKs across a bucket,
metadata-only — the DEK itself never changes, so no object data moves. It
runs with parallel workers, a checkpoint file for resumability, and a
`--dry-run` mode.

---

## S3 operation matrix (v1)

| Operation | Handling |
|---|---|
| `PutObject` | intercepted: streaming encrypt; aws-chunked decoded with chunk signatures verified; plaintext-MD5 ETag when available ("ETag policy") |
| `GetObject` | intercepted: v1 / passthrough routing; every chunk verified before release; Range → `206` + `Content-Range` under both routings |
| `HeadObject` | intercepted: plaintext size fixup (v1 math / footer read) |
| Create/Upload/Complete/Abort multipart | intercepted ("Multipart v1"); Complete is safe to retry; part list is validated |
| `ListParts` | passthrough — the backend's own XML; part sizes are ciphertext sizes, same caveat as "List sizes are ciphertext sizes" |
| `CopyObject` | passthrough by default for a v1 source (metadata copies with the object; ciphertext is not path-bound), plus one diagnostic `HEAD` against the source issued directly to the backend before the copy. With `BIND_PATHS` enabled, a v1 source instead goes through a thin DEK-rewrap interceptor, still one server-side copy. `metadata-directive: REPLACE` against an encrypted source is rejected, since it would drop the `s3a-*` metadata and orphan the object. `x-amz-copy-source-if-match`/`-if-none-match` are translated from the plaintext ETag the client was handed to the backend's stored ETag, same as `If-Match`/`If-None-Match` on GET/HEAD ("ETag policy"); `-if-modified-since`/`-if-unmodified-since` are left as-is, since they compare `Last-Modified`, which this proxy never rewrites. |
| `UploadPartCopy` | `501`, in v1: ciphertext cannot be re-chunked server-side |
| `GetObject?partNumber` | `501` — fetching one part of an already completed object is not supported in v1; fetch the whole object instead |
| `GetObjectAttributes` | passthrough — the backend's own XML; reported size and ETag are ciphertext, same caveat as "List sizes are ciphertext sizes" |
| `DeleteObject(s)`, `ListBuckets`, `ListObjectsV2`, all bucket sub-resources, ACLs, policy, lifecycle, versioning, tagging | passthrough — the backend's own XML |
| `SelectObjectContent` | `501 NotImplemented` — honest, rather than fabricating results over ciphertext |
| Presigned URLs (query SigV4) | verified |
| CORS preflight (`OPTIONS`) | answered from the backend's bucket CORS configuration, before auth |

Client authentication: full SigV4, with correct AWS canonicalization,
including payload hash and aws-chunked per-chunk signatures, constant-time
comparisons, and a ±15 minute clock-skew allowance. Auth-failure rate
limiting is a small in-memory token bucket per source IP; if not
configured, it is simply absent — there is no phantom configuration
section that looks like it does something and does not. Checksum headers
and trailers (`x-amz-checksum-*`, `Content-MD5`) are stripped from the
inbound request rather than validated, because modern SDKs default to
sending a checksum that would never match ciphertext. The `Dechunker`
parses `x-amz-checksum-*` trailer lines into an accessible structure, but
nothing outside its own tests currently reads that value — a trailing
checksum is parsed and then discarded, never compared against anything.
`Content-MD5` is different: it genuinely is consumed, verified against the
streamed plaintext when the client sends it ("ETag policy").

### ETag policy

A consistent, single ETag policy across PUT, HEAD, and GET.

- **PUT.** When the client sends `Content-MD5`, the proxy verifies it
  against the streamed plaintext, returns it as the ETag, and stores it
  AEAD-encrypted under the object's DEK as `s3a-emd5` (encrypted, so the
  storage operator gets no content-guessing oracle from it). The proxy
  cannot compute a plaintext MD5 itself and offer the same guarantee for
  clients that omit `Content-MD5`: `s3a-emd5` has to ship as an
  `x-amz-meta-*` *request* header, sent before the first body byte, while a
  self-computed digest is only final after the whole body has streamed —
  there is no point in the PUT where a proxy-computed digest could still
  reach those headers. Without a client-supplied `Content-MD5` (true of
  every checksum-header SDK: aws-cli v2, boto3, rclone), there is no
  `s3a-emd5`, and PUT, HEAD, and GET all return the *ciphertext* ETag
  instead — consistent with each other, if not with the plaintext. See
  "A single-part PUT's plaintext ETag is only available with a
  client-supplied Content-MD5" for the two alternatives considered and
  rejected.
- **HEAD/GET.** When `s3a-emd5` exists, the proxy decrypts it and returns
  the same plaintext ETag. PUT, HEAD, and GET always agree on whichever
  ETag they are using.
- **Multipart.** S3 multipart ETags were never content MD5s in the first
  place. The proxy returns the backend's own Complete ETag, unchanged — no
  self-copy invalidates it. The footer's own `md5` field exists
  in the format but has no writer anywhere in the code today: writing it
  would need a streamed digest threaded through the per-part encryptor,
  and nothing currently does that. No client-visible ETag regresses from
  this gap, since multipart ETags were never claimed to be content MD5s.
- **List.** Backend (ciphertext) ETags, documented as such. Fixing this
  would cost a HEAD per listed object; no target client needs it.
- **If-Match / If-None-Match on GET/HEAD.** The proxy intercepts these
  rather than forwarding them. It resolves the effective ETag (plaintext
  via `s3a-emd5` for a v1 single-part object, the backend's own ETag
  otherwise) and answers `304`/`412` itself. Forwarding them verbatim would
  compare the client's plaintext-ETag conditional against the backend's
  ciphertext ETag, which would never match. A bare `If-Match: *` or
  `If-None-Match: *` is existence-based, not content-based, and is left for
  the backend to answer directly. `If-Modified-Since` and
  `If-Unmodified-Since` are forwarded verbatim, since they compare
  `Last-Modified`, which this proxy never rewrites. Conditional **writes**
  (a non-`*` `If-Match` on PUT or DELETE) are not resolved — no target
  client is known to send one.

---

## Crate choices

| Concern | Crate | Why |
|---|---|---|
| Runtime | tokio | default async runtime |
| HTTP server | hyper 1 + tower | raw request/response streaming control, no web framework |
| HTTP client | hyper-util pooled client, rustls | streaming bodies, per-backend connection pools |
| Outbound signing | aws-sigv4 (smithy) | maintained, correct canonicalization |
| Inbound verification | own module, against AWS test vectors | no mature server-side SigV4 verifier crate exists; the canonicalizer is shared with the outbound signer's tests |
| AEAD | aes-gcm, chacha20poly1305 (RustCrypto) | hardware-accelerated, no C toolchain dependency |
| RSA | rsa (RustCrypto, OAEP) | write-only cluster support |
| KDF / hash / MAC | hkdf, sha2, hmac, md5 | key derivation and the plaintext-MD5 ETag path |
| Key hygiene | zeroize, subtle | `ZeroizeOnDrop` on the master key, the HKDF-derived KEK copy, and the multipart session DEK only — not every DEK in flight ("Zeroization") |
| Config | toml + a small custom env loader | exact flat env names, the `_FILE` convention; the optional `config.toml` lowers to the same flat names ("Configuration model") |
| CLI | clap (derive) | subcommands |
| Logging | tracing + tracing-subscriber | spans double as profiling markers |
| Metrics | a small hand-rolled Prometheus text exporter | six counters and one gauge is simpler than a registry crate for this surface ("Observability") |
| Sessions | dashmap | small per-upload state plus a TTL sweep |
| Errors | thiserror (library code), anyhow (binary code) | one error-to-S3-XML mapper module |
| Tests | cargo-nextest, proptest, testcontainers (MinIO), criterion, cargo-fuzz | |

Rejected: `aws-sdk-s3` for the backend client (a typed API fights
passthrough); routing frameworks modeled on multi-layer dispatch (here, one
match function covers method, path, and query); `openssl`/`ring`; and
reflective, generically-nested configuration loading (hundreds of lines of
map-and-assert code inviting dead keys and env variables that silently
never work, versus the flat, exhaustively-named loader this project uses
instead).

---

## Configuration model

Configuration loads in precedence order: environment variables, then an
optional `config.toml` file, then built-in defaults. A value set by
environment variable always wins over the same value in the file; a value
in the file always wins over the built-in default.

Secrets are never read from the TOML file. Backend and client secret keys,
master keys, and RSA private keys come only from an environment variable
directly, or from the `_FILE` convention — a variable like
`S3A_BACKEND_SECRET_KEY_FILE` naming a mounted secret file. This applies
even when a config file is in use: the file may hold everything else, but
never a secret value.

`s3armor config` prints the effective configuration and, for each value, its
source: `default`, `file`, or `env`. This turns "why is my setting being
ignored" into a one-command diagnosis.

One deployment can configure any number of backends (`S3A_BACKEND_*` for
the implicit `DEFAULT` backend, `S3A_BACKEND_<NAME>_*` for named ones),
and each client credential resolves to exactly one of them via
`S3A_CLIENT_<NAME>_BACKEND` (default `DEFAULT`) — `sigv4::verify`
resolves a request's client identity, and `proxy::forward` is the single
point downstream where that identity's backend is dereferenced and
signed against. There is no per-bucket or per-path routing: the client
credential is the only input. The encryption keyring is global, not
per-backend, so an object copied between backends stays decryptable.

The full per-variable reference — every `S3A_*` name, its default, and
what it controls — lives in the user guide. This section is the model, not
the table.

---

## Repository layout

```
s3armor/
├── AGENTS.md                 # orientation; the ASD-STE100 rule lives here only
├── README.md                 # quickstart
├── docs/
│   └── ARCHITECTURE.md       # this document
├── LICENSE
├── Cargo.toml                # workspace
├── crates/
│   ├── s3armor-format/           # pure: v1 framing, footer, DEK wrap, metadata
│   │                         # codec, size math. No tokio, no HTTP.
│   │                         # Fuzzable, benchable — the entire
│   │                         # security-review surface.
│   │   ├── src/
│   │   │   └── v1/           # v1 framing, footer, metadata, wrap, multipart
│   │   ├── fuzz/             # frame and footer decoders
│   │   └── benches/          # criterion: encrypt/decrypt × algorithm × chunk size
│   └── s3armor/                  # binary
│       ├── src/
│       │   ├── main.rs       # clap: serve|check|bench|rewrap|rebind|config|health-probe
│       │   ├── sigv4/        # verify (inbound) + resign (outbound), shared canonicalizer
│       │   ├── proxy/        # passthrough engine, header filters, error→XML mapper, metrics
│       │   ├── intercept/    # put.rs, get.rs, head.rs, mpu.rs, copy.rs
│       │   ├── keys.rs       # keyring, kid/fingerprint lookup, zeroizing
│       │   ├── tools/        # check.rs, bench.rs, rewrap.rs
│       │   └── config.rs     # flat env loader
│       ├── fuzz/              # SigV4 header parser, aws-chunked decoder targets
│       └── tests/            # integration (testcontainers/MinIO)
├── Containerfile
├── docker-compose.yml         # demo: MinIO + s3armor; doubles as a config reference
├── docker-compose.e2e.yml     # + Nextcloud + Stalwart smoke (local-only, see
│                              # "End-to-end smoke test")
├── deny.toml
├── scripts/                   # *-check.sh acceptance scripts, per area
└── .github/workflows/ci.yml
```

Two crates. `s3armor-format` is the entire auditable crypto surface: no tokio,
no HTTP, so fuzzing and criterion benchmarks never link the networking
stack. This split is the one abstraction in the tree that earns its keep.

---

## Testing strategy

Unit tests and property tests in `s3armor-format` cover round-trips, size-math
inversion, and range-slice-equals-full-decrypt-slice properties. Edge
lengths (empty, 1 byte, one chunk, chunk boundary plus one, multi-chunk,
footer variants) are exercised by round-trip and boundary tests that prove
encrypt-then-decrypt is self-consistent — deterministic properties of the
format, not recorded, byte-exact golden vectors. A silent drift in the
wire format that both encoder and decoder agreed on would still pass every
one of these tests while breaking compatibility with data written under
the old layout; there is no golden-vector suite to catch that class of
regression today.

A corruption suite flips every distinct byte-region class — nonce,
ciphertext, tag, metadata/AAD inputs, footer, wrapped DEK, swapped part,
swapped chunk, truncation — and asserts that decryption fails before any
plaintext is released, with the correct error class.

### Benchmarks (`s3armor bench`)

Structured output (a human-readable table, or `--json`), in three tiers:

- **Local** (no network): AES-256-GCM versus XChaCha20-Poly1305 across
  chunk sizes from 64 KiB to 8 MiB on the host CPU, reporting throughput
  and recommending an (algorithm, chunk_size) pair. This tier is a single
  timed pass per combination — a picker, not a precision instrument. The
  precision instrument is the separate criterion benchmark suite
  (`cargo bench`), which is not wired to this tier or to
  `--write-config`.
- **Backend** (`--backend`): time-to-first-byte, sustained upload and
  download throughput across a size ladder, a multipart part-size sweep,
  and concurrency discovery through a ramp-then-bisection search. Probes
  never persist data — every probe follows an upload-then-abort pattern,
  and any temporary object lives under a UUID prefix that is always
  cleaned up.
- **Proxy** (`--proxy`, against a running instance): a proxy-versus-direct
  efficiency ratio per size class, with a SHA-256 verification step. Memory
  is read from the proxy's own metrics endpoint, not sampled from the
  benchmark tool's own process.
- `--write-config` emits a ready-to-use environment block with the
  recommended settings from whichever tier ran. `s3armor bench` is
  operator-invoked; no CI job runs any tier automatically or asserts a
  threshold from it.

### Backend conformance check (`s3armor check`)

A preflight tool, run by the operator with the same configuration `serve`
would use:

```
s3armor check
  ✓ endpoint reachable, TLS ok (chain, expiry); loud warning on http://
  ✓ auth valid (HeadBucket), clock skew vs backend Date
  ✓ put/get/delete round-trip (1 KiB)
  ✓ user metadata persisted intact (s3a-* survives PUT→HEAD)      ← critical
  ✓ metadata size headroom (≥ 2 KB user metadata)
  ✓ multipart: create/upload×2/complete; SMALL FINAL PART accepted ← footer!
  ✓ ranged GET honored (bytes=5-9 → 206)
  ✓ CopyObject preserves user metadata (passthrough-copy soundness)
  ✓ checksum trailer behavior with CRC32-on SDK
  → verdict: compatible / degraded (what breaks) / incompatible
```

Each probe maps to a specific format or protocol requirement. A failure
names the consequence, not just the failed step.

### Integration tests

Integration tests run against a real MinIO instance via testcontainers,
using `aws-sdk-rust` as the client. They cover round-trips, ranges,
multipart (parallel parts, retried parts, duplicate parts, non-contiguous
part numbers, a retried Complete, abort, and restart-loss), passthrough
operations, presigned URLs, and checksum stripping against a modern SDK.
These tests fail — they never skip — when Docker is unavailable.

### SigV4 conformance

The AWS-published SigV4 test vector suite runs against both the inbound
verifier and the outbound re-signer, alongside key shapes known to cause
403s (space, `~`, `+`, `*`, parentheses) as permanent regression cases.

### Fuzz-target policy

Fuzz targets exist for the v1 frame decoder, the v1 footer decoder, the
aws-chunked decoder, and the SigV4 header parser. All four run as short CI
smoke jobs. Untrusted client input — an aws-chunked body, a SigV4 header, a
stored object's metadata — always gets a fuzz target before it gets a
hand-written parser; both `Dechunker` and the SigV4 verifier were built
with this in mind from the start rather than retrofitted. There is
deliberately no committed fuzz corpus: corpus and crash-artifact
directories are excluded from version control, since they are
regenerable. Add a committed corpus only if fuzzing finds a durable
regression worth pinning down permanently.

### End-to-end smoke test

A docker-compose stack (`docker-compose.e2e.yml`) runs Nextcloud as
primary storage and Stalwart as a blob store against the proxy. This is
the acceptance test for the actual product promise: it does not exercise
the proxy's internals, it exercises whether a real client application
works correctly against it. No job in CI runs this automatically; it is
local-only, run by hand via `scripts/e2e-check.sh`.

### Coverage

`cargo llvm-cov` gates the build at 80% line coverage. `main.rs` and the
`tools/check.rs`/`tools/bench.rs` binary-level surface are excluded from
this gate, because they are validated by the acceptance scripts in
`scripts/` ("Deployment"), not by Rust unit tests.

---

## Profiling support

Profiling is built in, not bolted on:

- A `profiling` Cargo profile inherits from `release`, keeps debug symbols,
  and uses thin LTO, so `perf` and flamegraphs get real stack traces.
  Frame-pointer generation is a rustc codegen flag
  (`-C force-frame-pointers=yes`), set through `RUSTFLAGS` in the
  Containerfile's debug build stage — there is no equivalent Cargo profile
  key for it. The release image ships stripped; a separate `-debug` image
  tag ships with symbols.
- `tracing` spans wrap every pipeline stage — verify, dechunk, encrypt,
  upload — so span timings localize latency without attaching a profiler
  at all.
- Two feature flags are off by default: `pprof` (a flamegraph endpoint on
  the metrics port, built in) is available; `console` (tokio-console) and
  `dhat` (heap profiling) remain unbuilt, since no measurement has asked
  for them yet.
- The allocator is the system allocator by default, which keeps
  valgrind/heaptrack usable; `jemalloc` is an opt-in feature, and
  `s3armor bench` reports whether it measurably helps.
- Hot-path discipline: `bytes::Bytes` end-to-end, in-place encryption, one
  reusable frame buffer per stream, and no per-read allocation.
- criterion covers micro-benchmarks; `s3armor bench` covers macro-benchmarks.
  Both emit JSON, diffable per commit.

---

## Deployment

**Docker.** A multi-stage build: a `rust:alpine` (musl) builder stage,
producing a static binary, onto a distroless base image (nonroot user; a
`debug-nonroot` variant for the `-debug` target). The image carries a CA
bundle, a `HEALTHCHECK` running the binary's own `health-probe`
subcommand, and an entrypoint that runs the binary directly with `serve`
as the default command — so `docker run <image> rewrap` and `… check`
work as one-off invocations of the same image, not separate binaries.
There is one binary. `check`, `bench`, and `rewrap` are subcommands of
it, never shipped as sibling binaries into a production image.

**Proxmox LXC.** The same static musl binary runs with no container
runtime at all: one binary, one environment file sourced by systemd, and a
short systemd unit (`DynamicUser=yes`, `LoadCredential=` for secret
material). This fits comfortably inside a 256 MiB LXC. The Docker build
exports the binary as a build artifact; there is no separate build path
for the LXC case.

**CI.** `fmt`, `clippy -D warnings`, `nextest`, the coverage gate
("Coverage"), `cargo-deny`, the fuzz smoke jobs ("Fuzz-target policy"),
integration tests against a MinIO testcontainer, and a `docker build` step
that runs `--version`
against the produced image. CI builds and verifies an image; it does not
publish one. There is no tag-triggered registry push and no release
automation job.

Acceptance scripts under `scripts/` (`passthrough-check.sh` through
`lifecycle-check.sh`, eleven in all)
are shell-level checks run against a real built binary and a real backend
(MinIO or, for `e2e-rgw-check.sh`, a local Ceph RGW container). They exist because some
properties — a graceful shutdown sequence, a health endpoint's behavior
under load, an image's actual `HEALTHCHECK` wiring — are only observable
against the real process and the real container, not against a Rust test
harness standing in for it.

---

## Observability

`/health` reports liveness. `/ready` reports whether the backend is
reachable, by signing and sending a real request through the same
forwarding machinery the proxy uses for client traffic. Both endpoints are
unauthenticated and bypass all other middleware.

**Two-phase graceful drain.** On SIGTERM or SIGINT, `/health` must start
returning `503` immediately, so that an external health check or load
balancer can observe the drain in progress. This requires the accept loop
to *keep accepting new connections* through the whole drain window — a
probe connection sent after drain has started must still get a real `503`
response, not a connection refusal. An initial implementation set a
draining flag and immediately stopped the accept loop; the intended effect
("stop accepting, then wait for in-flight requests to finish") instead made
the `503` response unobservable, because every probe connection after that
point was refused outright rather than answered. The correct sequence
folds the "exit once idle" check into the same accept loop — each loop
iteration races `listener.accept()` against a shutdown check, rather than
running a separate accept phase followed by a separate wait phase. A
future "cleanup" that returns to the simpler stop-then-wait shape breaks
this observability property, even though it looks like a harmless
simplification. Only after the drain window elapses, or every in-flight
request completes, does the process actually exit.

Metrics are optional Prometheus text exposition, one hand-rolled registry
with no per-bucket or per-key labels. The full metric set:

| Name | Kind | Meaning |
|---|---|---|
| `s3armor_auth_failures_total` | counter | SigV4 verification failures (the reason is in the accompanying log line, not broken out per-reason here) |
| `s3armor_auth_rate_limited_total` | counter | requests rejected by the auth-failure rate limiter before SigV4 verification even ran |
| `s3armor_chunk_verify_failures_total` | counter | AEAD chunk verification failures — alert on any nonzero value |
| `s3armor_mpu_sessions_created_total` | counter | multipart sessions created |
| `s3armor_mpu_sessions_active` | gauge | multipart sessions currently open |
| `s3armor_footer_cache_hits_total` / `s3armor_footer_cache_misses_total` | counter | multipart footer LRU cache hits and misses |

This is deliberately six counters and a gauge, not a per-operation,
per-status, duration-histogram registry. Upgrade to that only once
duration percentiles or per-operation labels are actually wanted; today
they would be pure overhead with no consumer.

Every request carries a correlation id, both in logs and in the S3 error
response's `RequestId` field. There is exactly one error-to-S3-XML mapper
module in the whole proxy.

---

## Rejected designs

These were considered and rejected. Do not re-litigate them without new
information that changes the tradeoff.

- **Compression before encryption.** The compression ratio leaks
  information about plaintext content (a CRIME-class weakness), and the
  proxy's target payloads are mostly already-incompressible data anyway.
- **Filename or object-key encryption.** It would break List and prefix
  semantics, and every client's assumptions about object paths. Nextcloud's
  own primary-storage keys are already opaque `urn:oid:` values, so this
  would protect nothing there.
- **A DEK cache.** A cache keyed by object name rather than by content
  risks staleness bugs when an object is overwritten. Unwrapping a DEK
  costs about 1 microsecond. Revisit only as a content-addressed cache
  (keyed by wrapped-DEK bytes) if RSA read-node latency is measurably a
  problem.
- **KMS or Vault integration in v1.** Self-contained keys are the point of
  this design. The key-id scheme leaves room to add this later without a
  format change.
- **io_uring or a similar alternative async runtime.** tokio plus AES-NI
  saturates the target network links first; the runtime is not the
  bottleneck.
- **Configurable, switchable integrity modes (off/lax/hybrid/strict).**
  Integrity is not optional in this design. AEAD verification costs
  approximately nothing next to network I/O.
- **Size-guessing size-correction logic, an unconsumed security-
  configuration section, SigV2, several redundant chunked-decoder
  implementations, or a large delegating backend interface.** All would be
  dead code, phantom protection, or structurally replaced by the design in
  "Architecture: re-signing streaming reverse proxy".
- **A post-PUT metadata self-copy, or a single-part trailing footer, to
  manufacture a plaintext ETag without a client-supplied `Content-MD5`.**
  See "A single-part PUT's plaintext ETag is only available with a
  client-supplied Content-MD5" for the full reasoning; both were rejected
  as disproportionate to the gap they would close.

---

## Known limits and caveats

### List sizes are ciphertext sizes

Sizes are the plaintext size plus about 0.002% plus the footer. Fixing
`ListObjectsV2` to report exact plaintext sizes would cost a HEAD or
footer read per listed object, so it is not done. Nextcloud gets its size
statistics from its own database or from HEAD requests, so the impact
there is negligible.

### Ciphertext is not bound to the object path in default mode

An attacker with backend **write** access can swap two encrypted objects
undetectably in the default configuration (cannot forge or modify content
— AEAD still holds). The same attacker could simply delete everything
instead, so this is a narrow addition to an already-serious access level.
`S3A_BIND_PATHS` ("Path binding") closes the swap, at the cost of needing
`s3armor rebind` for same-name restores. Rollback to an older, authentic
version is undetected in every mode; backend bucket versioning is the
mitigation.

### Multipart sessions are RAM, single instance

A restart loses in-flight uploads. Clients retry; already-completed
objects are unaffected, and a retried Complete is safe within the session
TTL. Snapshotting session state to disk is a possible future option if
LXC operators need it; nothing today builds it.

### Write-only (RSA) nodes cannot serve GETs

A write-only node returns `KeyNotAvailable` for any encrypted object by
design ("Keys and wrap"). A deployment must route reads to a node holding
the private key. `s3armor config` prints a node's capability (read+write or
write-only) at startup, so a misrouted cluster is diagnosable from one
log line.

### UNSIGNED-PAYLOAD to the backend over TLS

The plaintext hash of ciphertext being produced on the fly is unknowable
in advance, and buffering the whole body to compute a hash first would
defeat streaming. TLS to the backend is therefore effectively mandatory
for this proxy to give any real protection; `s3armor check` warns loudly
against a plain `http://` backend endpoint.

### `UploadPartCopy` returns 501

This may affect an exotic client doing server-side multipart assembly of
already-encrypted objects. Neither Nextcloud nor Stalwart uses it.
Revisit only if a real client needs it.

### Hetzner (Ceph RGW) specifics

Path-style access works; there are per-bucket request-rate class limits
around 750 req/s; the user-metadata cap is 2 KB (v1 typically uses under
400 bytes, and an RSA wrap around 700 bytes, both comfortably inside the
limit); a small final multipart part is accepted, which the footer
tail-merge design ("Multipart v1") depends on. All of this is probed by
`s3armor check`, not assumed.

### Clock skew

SigV4 enforces a ±15 minute allowance. An LXC deployment needs working
NTP; `s3armor check` compares the local clock against the backend's own
`Date` header.

### An LXC's systemd-sourced environment file holds secrets in one file

Mode `0600` plus `LoadCredential` mitigates this. The Docker `_FILE`
convention (one secret per mounted file) remains the recommended approach
everywhere it is available. This is systemd sourcing an environment file
into the process's environment before the binary starts — not the binary
itself reading this file; the optional `config.toml` never holds secrets
("Configuration model").

### A single-part PUT's plaintext ETag is only available with a client-supplied Content-MD5

Every SDK that instead defaults to `x-amz-checksum-crc32` (aws-cli v2,
boto3, rclone) gets the backend's ciphertext ETag on PUT, HEAD, and GET —
consistent with each other, not with the plaintext ("ETag policy"). This is a
physical constraint: the plaintext MD5 is only known once the whole body
has streamed, but `s3a-emd5` must ship in request headers sent before the
first body byte, so a self-computed digest has nowhere to land on the
same request. Two alternatives were considered and rejected: a post-PUT
metadata self-copy to attach a just-computed `s3a-emd5` after the fact (a
full server-side ciphertext copy on every such PUT, with real cost against
Hetzner or Ceph, and it would change the object's backend ETag and
`Last-Modified` as a side effect); and a trailing footer on single-part
objects, mirroring multipart's existing footer (architecturally the
right shape, since it is written after the data, when a streamed digest
would actually be available — but a v1 format change touching size math,
HEAD's fixup, and ranged reads, for objects written from that point
forward only). Revisit if a target client needs a plaintext ETag without
sending `Content-MD5`.

### Multipart's footer `md5` field is always empty

Same root cause as "A single-part PUT's plaintext ETag is only available
with a client-supplied Content-MD5": nothing wires a streamed digest
through to the footer writer, so the field has no producer anywhere in
the tree. This is lower priority than that gap, because multipart ETags
were never claimed to be content MD5s — no client-visible ETag regresses
from this field being empty. It is a dead field, not a broken promise,
until something is built to fill it.

---
