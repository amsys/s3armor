# s3armor — Developer Guide

This guide is for contributors. It explains the repository layout, the
build and test commands, the real-backend check scripts, fuzzing,
coverage, end-to-end testing, the supply-chain policy, and the commit
conventions.

For what the proxy does and why, read
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md). For install and operation, read
[`docs/USER-GUIDE.md`](USER-GUIDE.md). Read `AGENTS.md` in the repo root
before you change format, crypto, or the S3 operation matrix — it records
decisions this project already made, so you do not re-litigate them.

## 1. Repository layout

The workspace has two crates.

```
crates/s3armor-format/   pure crypto and framing. No tokio. No http.
crates/s3armor/          the binary: proxy, SigV4, interception, tools, config.
```

`s3armor-format` does not depend on `s3armor`. Keep it that way. It is the crate
you fuzz, bench, and audit on its own.

### `crates/s3armor-format/src`

| Module | What it does |
|---|---|
| `v1/frame.rs` | Seals and opens one v1 AEAD frame. |
| `v1/footer.rs` | Encodes and decodes the multipart footer trailer (part sizes, total plaintext size). |
| `v1/meta.rs` | v1 object metadata, including the sealed plaintext-MD5 side channel (`emd5`). |
| `v1/multipart.rs` | Multipart size math (part sizing, part-count limits). |
| `v1/wrap.rs` | Wraps and unwraps the per-object data-encryption key (DEK) under a master key or an RSA key. |

The crate has one cargo feature, `test-util`. It exposes
`RsaKek::generate` for tests. The feature is off by default: production
keys come from `openssl`, never from the proxy. The `s3armor` crate
enables it in `[dev-dependencies]` only, so the feature never reaches
the release binary.

### `crates/s3armor/src`

| Module | What it does |
|---|---|
| `main.rs` | The CLI: argument parsing, and the `serve` accept loop with its signal handling. |
| `config.rs` | The flat environment-variable config loader. |
| `chunked.rs` | The single aws-chunked decoder. It dechunks and verifies each chunk's signature before releasing its bytes. |
| `keys.rs` | The keyring: key id to master key, plus which key new writes use. |
| `mpu.rs` | In-memory multipart-upload session state, with an active TTL sweeper. |
| `ratelimit.rs` | Per-source-IP token-bucket rate limiting for signature-verification failures. |
| `tls.rs` | Loads the TLS listener certificate and key, and the loopback client verifier the health probe uses. |
| `sigv4/` (`canonical.rs`, `verify.rs`, `sign.rs`, `time.rs`) | One canonicalizer, shared by inbound signature verification and outbound re-signing. |
| `proxy/` (`mod.rs`, `route.rs`, `client.rs`, `body.rs`, `headers.rs`, `error.rs`, `metrics.rs`) | The re-signing streaming reverse proxy: verify the client's signature, rewrite only what must change, re-sign for the backend, stream both ways. |
| `intercept/` (`put.rs`, `get.rs`, `head.rs`, `copy.rs`, `mpu.rs`, `footer.rs`, `conditional.rs`) | Encrypts on write and decrypts on read for Put/Get/Head/Copy/multipart. Everything else stays plain passthrough. |
| `tools/` (`check.rs`, `bench.rs`, `rewrap.rs`, `list.rs`) | The CLI subcommands: backend preflight check, benchmarks, and key-rotation rewrap. Key generation is `openssl`, not a subcommand — docs/USER-GUIDE.md "Key generation and rotation". |

## 2. Build, format, and lint

The workspace uses Rust edition 2021 and targets Rust 1.97 as its minimum
supported version (`Cargo.toml`'s `[workspace.package]`, mirrored in
`clippy.toml`'s `msrv`).

```sh
cargo build --workspace
cargo fmt --all -- --check                        # cargo fmt --all to apply
cargo clippy --workspace --all-targets --locked -- -D warnings
```

`rustfmt.toml` sets only two things: edition 2021 and Unix newlines. There
is no other formatting override — rustfmt's defaults apply everywhere
else.

The lint policy lives in `Cargo.toml`'s `[workspace.lints]` and in
`clippy.toml`:

- `unsafe_code = "forbid"` at the workspace level. The workspace has zero
  `unsafe` code today. Keep it that way.
- `clippy::pedantic` and `clippy::nursery`, both at `warn`, with a short
  list of cosmetic lints turned off (doc-comment nitpicks with no defect
  value).
- A block of restriction lints at `warn` — `unwrap_used`, `expect_used`,
  `panic`, `indexing_slicing`, `todo`, `unimplemented`, and others. This is
  the security half of the policy: it flags the exact constructs that turn
  untrusted input into a crash or an information leak.
- `clippy.toml` allows `unwrap`/`expect`/`panic`/indexing in test code only
  (`allow-unwrap-in-tests = true` and its siblings). Production code has no
  such allowance.
- `clippy::cognitive_complexity` is on, with
  `cognitive-complexity-threshold = 15` in `clippy.toml`. This is the same
  limit SonarCloud's S3776 rule uses. Clippy's metric is an approximation of
  Sonar's, so the two numbers can differ.
- Every `#[expect(clippy::...)]` in the tree carries a `reason = "..."`
  naming the specific invariant that makes the lint a false positive at
  that one site. Do not delete an `#[expect(...)]` without first checking
  that its named invariant still holds.

One more convention, stated in `AGENTS.md`: **no config knob without a test
exercising its effect.** A config section that gets parsed and validated
but never actually read back out and acted on is worse than no config at
all — it looks like a working control and isn't. If you add an environment
variable, add a test that proves it changes behavior.

## 3. Tests

```sh
cargo test --workspace
# or, matching CI:
cargo nextest run --workspace
```

Test layout:

- `crates/s3armor-format/tests/`: `boundaries.rs` and `proptest_v1.rs` (v1
  round-trip and edge-length tests), `corruption.rs` (flips each byte
  region — nonce, ciphertext, tag, metadata, footer, wrapped key — and
  checks it fails before any plaintext is released), and `multipart.rs`.
- `crates/s3armor-format/benches/crypto.rs`: a Criterion benchmark, run with
  `cargo bench`, not part of the normal test run.
- `crates/s3armor/tests/`: `conformance.rs` (SigV4 test vectors),
  `integration_minio.rs`, `integration_mpu.rs`. These two start a real
  MinIO container (via `testcontainers`) and drive the proxy against it
  with `aws-sdk-rust`. They fail, rather than skip, when Docker is
  unavailable — a missing backend is a real test failure here, not a soft
  pass.

## 4. The real-backend check scripts

`scripts/*-check.sh` are not unit tests. Each script builds the real `s3armor`
binary, starts a real backend (usually MinIO, in one case Ceph RGW) in a
Docker container, drives the compiled binary with real client tools
(`aws-cli`, `rclone`, `curl`, `openssl`), and cleans up after itself with a
`trap`. Each script proves one area of behavior end to end, against the
actual compiled artifact — not against an in-process Rust test harness that
stands in for it.

| Script | What it verifies |
|---|---|
| `scripts/passthrough-check.sh` | Passthrough proxying: real S3 clients (`aws-cli`, `rclone`) work correctly through the proxy for operations it does not intercept, against real MinIO. |
| `scripts/crypto-check.sh` | Single-part crypto: PUT encrypts and GET/HEAD decrypts, checked with a real client's own checksum verification (`rclone check`, `aws-cli`), against real MinIO. |
| `scripts/multipart-check.sh` | Multipart crypto with real clients against real MinIO: parallel parts, at the same client-tool level the retried-part/duplicate-part/retried-Complete/restart-loss regressions are unit-tested at in `tests/integration_mpu.rs`, plus the multipart-session TTL sweeper's backend-abort behavior. |
| `scripts/multi-backend-check.sh` | Multi-backend routing against two independent real MinIO containers: a client's PUT lands on its own backend and nowhere else, the footer cache never serves one backend's object for another's request to the same bucket/key, and an abandoned multipart upload is aborted on the backend it was created on — the one case nothing else in the suite exercises against the real sweeper tick. |
| `scripts/tooling-check.sh` | Tooling: generates a key with `openssl`, then `s3armor check --bucket` clean against real MinIO, then all three `s3armor bench` tiers (local, `--backend-tier`, `--proxy`), then confirms `--write-config`'s output is valid env `s3armor serve` accepts. |
| `scripts/tls-check.sh` | TLS and auth rate limiting: a self-signed certificate round-trips over https and `s3armor health-probe` succeeds against it; repeated bad-signature requests get HTTP 429 while a good-credential request keeps succeeding throughout. |
| `scripts/bind-paths-check.sh` | `S3A_BIND_PATHS` (`on`/`strict`) and `s3armor rebind`: the ciphertext-swap attack this feature detects, compatibility with objects written under `off`, `CopyObject` as a legitimate rewrap, a multipart round trip, and the `rebind` retirement path. |
| `scripts/e2e-check.sh` | Drives the full `docker-compose.e2e.yml` stack: Nextcloud as primary storage through the proxy (upload, download, rename, delete over WebDAV), and confirms the object stored at the backend is genuinely ciphertext, not just that the client-visible behavior looks right. |
| `scripts/e2e-rgw-check.sh` | Ceph RGW: `s3armor check --bucket` clean, plus a proxy round-trip, a multipart upload, and a ranged GET, against a real Ceph RGW container — the same software Hetzner Object Storage runs. |
| `scripts/conditional-check.sh` | Conditional requests (`If-Match`/`If-None-Match`): a plaintext-checksum PUT, `aws-cli`'s own conditional get-object flags, and a raw `curl` conditional header, each checked against the exact HTTP status returned. |
| `scripts/lifecycle-check.sh` | Graceful drain, `/ready`, `S3A_TIMEOUT_CONNECT`, and `S3A_BIND_PATHS=strict` plus `rebind` — against the real compiled binary: SIGTERM sent mid-upload flips `/health` to 503 immediately while the in-flight PUT still completes, then the process exits on its own once drained. |

Each script sources `scripts/common.sh` after setting `ROOT`. On a machine
where Docker requires sudo, run `DOCKER="sudo docker" scripts/<name>.sh` —
cargo runs as your user, only docker uses sudo. Do not run the script
itself under sudo; cargo would write root-owned files to the build
directory. Scripts find the s3armor binary through `cargo metadata`, so
any target directory set by `CARGO_TARGET_DIR` or by `build.target-dir` in
a cargo config works.

None of these scripts run in CI (see [section 10](#10-continuous-integration)).
Run them locally before a change that touches proxying, crypto, multipart,
tooling, TLS, bind-path binding, the compose stack, conditional requests, or
shutdown behavior. Each script lists its own required tools at the top of
the file (`docker`, `cargo`, `aws-cli` v2, and a small set of others per
script) and fails fast if one is missing.

## 5. Fuzzing

Four fuzz targets exist. All four run as short jobs in CI (20,000
iterations each) so a regression in untrusted-input parsing is caught on
every push, not only when a contributor remembers to fuzz locally.

| Target | Crate | What it fuzzes |
|---|---|---|
| `v1_frame` | `crates/s3armor-format/fuzz/fuzz_targets/v1_frame.rs` | The v1 AEAD frame parser. |
| `v1_footer` | `crates/s3armor-format/fuzz/fuzz_targets/v1_footer.rs` | The v1 multipart footer and trailer parser. |
| `aws_chunked` | `crates/s3armor/fuzz/fuzz_targets/aws_chunked.rs` | The aws-chunked decoder. |
| `sigv4_parsers` | `crates/s3armor/fuzz/fuzz_targets/sigv4_parsers.rs` | The SigV4 header and query-string parsers. |

These four cover every parser in the workspace that reads bytes it did not
generate itself: the v1 format decoders in `s3armor-format`, and the two
untrusted-input parsers in `s3armor` itself.

To run one locally (needs a nightly toolchain and `cargo-fuzz`):

```sh
cargo install cargo-fuzz --locked
cd crates/s3armor-format   # or crates/s3armor, depending on the target
cargo +nightly fuzz run v1_frame -- -runs=20000
```

There is no committed fuzz corpus. Both fuzz crates' `corpus/` and
`artifacts/` directories are gitignored on purpose — add a committed
corpus only if fuzzing finds a durable regression worth pinning as a
regression case.

## 6. Coverage

CI enforces an 80%-lines coverage gate with `cargo-llvm-cov`:

```sh
cargo llvm-cov nextest --workspace --locked --lcov --output-path lcov.info \
  --ignore-filename-regex 's3armor/src/main\.rs|s3armor/src/tools/(check|bench)\.rs'
cargo llvm-cov report --fail-under-lines 80 \
  --ignore-filename-regex 's3armor/src/main\.rs|s3armor/src/tools/(check|bench)\.rs'
```

Three files are excluded from the gate: `crates/s3armor/src/main.rs`,
`crates/s3armor/src/tools/check.rs`, and `crates/s3armor/src/tools/bench.rs`. All
three sit at 0% Rust-line coverage, because nothing in
`cargo test`/`cargo nextest` calls them — `main.rs`'s own `serve` and
`handle_connection` accept loop, and the `check`/`bench` CLI entry points,
are validated instead by the real-backend check scripts in section 4,
against the real compiled binary and a real backend, not by Rust tests.

Measured numbers: the whole workspace, unexcluded, sits at 74.77% lines.
Excluding just those three files puts the rest of the workspace at 86.78%
lines. The CI gate is set at 80%, against the excluded measurement — high
enough to catch a real regression in ordinary library code, with headroom
below 86.78% so the gate is not immediately fragile.

The three files are excluded rather than the gate being lowered to fit
them, because lowering the number to accommodate three files that are
*correctly* untested by Rust tests would also mask a real coverage
regression anywhere else in the workspace. Excluding the specific files
that have a different, already-real verification path (the check scripts)
keeps the 80% number meaningful for the code it actually measures. This is
the same split the project draws everywhere: Rust tests cover library
code, and the shell scripts cover binary-level behavior — TLS, signals,
real backends — that a Rust test harness cannot exercise by calling `main`
directly.

## 7. End-to-end testing (`docker-compose.e2e.yml`)

`docker-compose.e2e.yml` stands up the proxy against two real client
applications: Nextcloud (primary storage over WebDAV) and Stalwart (a mail
server, using S3 as its blob store). Its own header comment calls this
"the acceptance test for the actual product promise." It is not a
production topology — MinIO runs as a single node, with no TLS and
throwaway secrets.

No job in `.github/workflows/ci.yml` runs this stack. Run it locally:

```sh
scripts/e2e-check.sh
```

**Nextcloud** is fully driven and checked by that script: WebDAV upload,
download, rename, and delete through the proxy, plus a direct read against
MinIO confirming the stored object is genuinely ciphertext (the `s3a-v`/
`s3a-dek` metadata is present, and the uploaded marker text is absent from
the raw bytes).

**Stalwart** is a known, accepted gap, not a bug. Stalwart v0.16 has no
flat-file, fully non-interactive bootstrap this project can drive headless
— its own `--config` flag only accepts a minimal data-store pointer.
Configuring the rest (listeners, storage roles, the S3 blob store pointed
at this proxy) needs either its `stalwart-cli apply` management-API
command, or its one-time interactive web setup wizard. Neither is
scriptable from what Stalwart documents today.

Complete the wizard once, by hand:

```sh
docker compose -f docker-compose.e2e.yml up stalwart
```

Then open **`http://localhost:18381`** (published from the container's
internal web port) and complete the setup wizard. The result persists in
the `stalwart-etc` volume, so this is a one-time step, not a per-run one.
`scripts/e2e-check.sh` only confirms the Stalwart container starts and is
reachable on the network. It does not assert the mailbox round-trip, and
it says so plainly rather than reporting a false pass.

**Ceph RGW** is checked separately, by `scripts/e2e-rgw-check.sh` (see
section 4), against `quay.io/ceph/demo` — the same software Hetzner Object
Storage runs. This script is local opt-in only, not wired into CI. Ceph's
own monitor refuses to start below 5% free disk space on the host
filesystem — a real Ceph safety floor, not a defect in the script or the
proxy. The one sandbox where this was last attempted had about 3% free
disk space, so the check could not run to completion there. Run it on a
host with normal free disk space to get a live pass.

## 8. Supply-chain policy (`deny.toml`)

`cargo deny check` runs in CI (the `deny` job) and again at `pre-push`
locally.

**Licenses.** The allow-list covers the usual permissive set (MIT,
Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib), plus three specific
additions with a reason each: `CDLA-Permissive-2.0` (bundled Mozilla root
CA data, pulled in by the TLS stack), `CC0-1.0` (one of `dunce`'s
alternate license options — also satisfiable via the Apache-2.0 already
on this list, so this entry is belt and suspenders, not load-bearing),
and this project's own `AGPL-3.0-or-later`.
One scoped license exception exists: `inferno` (the flamegraph renderer
behind the optional, off-by-default `pprof` profiling feature) is allowed
to carry `CDDL-1.0`, scoped to that one crate only — not a blanket allow.
A future dependency pulling `CDDL-1.0` through any other path still fails
the check. Anyone building the `-debug` profiling image should review the
`CDDL-1.0`/`AGPL-3.0-or-later` combination first.

**Ignored advisories**, each with a stated reason in `deny.toml`:

- `RUSTSEC-2023-0071` — the `rsa` crate's RSA-OAEP decrypt is not
  constant-time (the "Marvin Attack"), and no patched release exists. RSA
  unwrap is a deliberate, already-made product decision (the v1 write-only
  key path), not something a code change can route around. Upgrade path: a
  constant-time OAEP implementation, or dropping RSA support, if the fix
  never lands upstream.
- `RUSTSEC-2026-0098`, `-0099`, `-0104` — certificate name-constraint and
  CRL parsing bugs in an old `rustls-webpki`, pulled in transitively by an
  outdated internal HTTP client inside `aws-config` (a dev-only
  dependency). Confirmed dev-dependency-only with `cargo tree`. The
  project's own client pins a newer, unaffected `rustls-webpki` directly.
  Upgrade path: wait for `aws-config` to adopt a newer runtime internally.
- `RUSTSEC-2025-0111` — `tokio-tar` (archived) mis-parses PAX headers in
  `testcontainers`' image-loading path, dev-only. Only known-good, official
  images are pulled by tag in this project, never untrusted tarballs.
- `RUSTSEC-2025-0134` — `rustls-pemfile` is unmaintained, pulled by
  `bollard` inside `testcontainers`, dev-only. Upgrade path: `bollard`
  moving to a newer PEM API upstream.
- `RUSTSEC-2026-0258` — unbounded empty DATA frames in an old `h2`, pulled
  by `aws-config`'s old HTTP stack, dev-only. The project's own runtime
  stack uses a current, already-patched `h2` version; both versions
  coexist in the dependency tree without conflict.
- `RUSTSEC-2026-0194`, `-0195` — parsing bugs in an old `quick-xml`, pulled
  in only through `inferno` (the optional `pprof` feature). Traced the
  actual code path `inferno` calls for flamegraph output and confirmed it
  only writes SVG output — it never parses XML input, so the vulnerable
  code paths are never reached.

**Notable pin.** The project's own direct `quick-xml` dependency (used by
the S3 XML request/response bodies) was bumped to 0.41 specifically to
clear the last two advisories above for the workspace's own use. The older,
vulnerable `quick-xml` version still appears in the dependency tree, but
only transitively through the optional `pprof`/`inferno` path.

**Bans.** Duplicate dependency versions only warn, not fail
(`multiple-versions = "warn"`) — this is a large workspace and duplicate
versions are common and usually harmless. Wildcard version requirements are
denied outright. Dependencies must come from a known registry or a pinned
git source; an unknown registry or an unpinned git dependency fails the
check.

## 9. Two lessons worth keeping in mind

**Graceful drain: keep accepting connections through the whole shutdown
window.** The proxy's accept loop must keep calling `listener.accept()`
after a shutdown signal arrives, not stop immediately. The reason: the
`/health` endpoint's promised 503-during-drain response only has value if
a client can still connect to receive it. An accept loop that stops the
instant the signal fires makes that response unobservable — every new
probe connection after that point gets refused outright instead of
answered, so a client watching for the 503 never sees anything at all.
This class of bug is invisible to the in-process Rust integration test
harness, because that harness stands in for `main::serve` with its own
simplified accept loop — it never calls the real `main`/`serve` function,
so it cannot catch a defect in that function's own shutdown sequence. Only
`scripts/lifecycle-check.sh`, sending a real SIGTERM to the real compiled binary,
caught this in practice. If you touch the shutdown sequence in `main.rs`'s
`serve` function, keep this invariant true: the accept loop keeps running
through the whole drain window, and it exits only once every in-flight
connection has finished or the drain deadline has passed, whichever comes
first.

**Silent authentication failure in a streaming decoder.** An earlier
version of a streaming CTR-mode decoder released decrypted plaintext bytes
into the HTTP response body before its own HMAC check had run. Because the response's
`Content-Length` is fixed up front, once every byte had been written the
HTTP layer stopped polling the body for more — so the final chunk, the one
carrying the failed HMAC result, was silently dropped. The client received
a `200 OK` with wrong bytes instead of the `403` a failed check should have
produced. A dedicated regression test already existed for this and still
did not catch the bug: it only asserted that tampered output differed from
the original plaintext, which is true either way — tampered ciphertext
decrypts to different bytes whether or not the authentication error ever
surfaced. The fix holds the most recently decrypted frame back by one
step, releasing it only once another frame — or a verified end of stream —
is confirmed to follow it. That way the final authentication check always
runs while the HTTP layer is still polling the body, so a failure aborts
the response instead of quietly completing it; the failure now also logs.
The general lesson for anyone touching a streaming decoder that
authenticates only at the end: releasing output speculatively before the
last check has run can make an authentication failure permanently
unobservable to the caller, even when the check itself is correct and does
run. Hold the last unit of output back until you have proof nothing later
can invalidate it. (Ranged reads of this same format are unaffected by
design — the authentication tag covers the whole plaintext, so a range read
never carries it and is already treated as unauthenticated on purpose.)

## 10. Continuous integration

`.github/workflows/ci.yml` runs these jobs on every push and pull request:

- **fmt** — `cargo fmt --all -- --check`.
- **clippy** — `cargo clippy --workspace --all-targets --locked -- -D
  warnings`.
- **test** — `cargo nextest run --workspace`.
- **fuzz-smoke** — all four fuzz targets from section 5, 20,000 iterations
  each.
- **deny** — `cargo-deny`, checking the license/advisory/ban policy from
  section 8.
- **docker** — builds the release image and runs `--version` against it as
  a smoke test.
- **pre-commit** — runs the hygiene, secret-scan, and shellcheck hooks
  (`gitleaks`, `shellcheck`, `detect-private-key`) for anyone who did not
  install the hooks locally. `fmt` and `clippy` are skipped here since the
  two jobs above already ran them.
- **coverage** — the 80%-lines gate from section 6, uploading an `lcov`
  report as a build artifact.
- **sonarcloud** — uploads that coverage report to SonarCloud for further
  static analysis, gated on the coverage job passing first.

The `scripts/*-check.sh` real-backend scripts from section 4, and the
`docker-compose.e2e.yml` stack from section 7, do **not** run in CI. They
need Docker containers, native client tools, and in one case a very large
Ceph image — deliberately kept out of the default CI run. Run them locally
before a change that touches the behavior they check.

## 11. Contribution conventions

Read `AGENTS.md` in the repo root before you start. Read
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md) before you touch format, crypto,
or the S3 operation matrix — it records decisions and rejected
alternatives, so you do not need to re-derive them.

**Commits** follow the Conventional Commits format: `feat:`, `fix:`,
`refactor:`, `test:`, `docs:`, `chore:`. Reference the relevant
`docs/ARCHITECTURE.md` section or an issue number in the commit body, if
one applies.

**Before every commit**, `cargo fmt` and
`cargo clippy --all-targets -- -D warnings` must be clean. This is
enforced by hooks, not left to memory. Install them once per clone:

```sh
pre-commit install --install-hooks
```

`.pre-commit-config.yaml` runs `cargo fmt`, `cargo clippy -D warnings`, and
the hygiene/secret-scan hooks on every commit; it runs `cargo test` and
`cargo deny check` on every push. CI re-runs the same checks (plus
`pre-commit run --all-files`) so a skipped local install still gets
caught.

**Other conventions**, from `AGENTS.md`:

- No new abstraction for a single implementation.
- No config knob without a test exercising its effect (section 2 explains
  why).
- Every `#[expect(...)]` lint suppression names the invariant it excuses.
  Do not delete one without checking that invariant still holds.

## 12. Known developer-facing limitations

- **`Footer::md5` (`crates/s3armor-format/src/v1/footer.rs`) is a dead
  field.** Every call site that constructs a `Footer` sets this field to
  `None`. Nothing in the tree ever sets it to `Some` or reads it back out.
  It is encoded into the wire format but serves no purpose today. If you
  add multipart content-MD5 support, this is the field to wire up — or
  remove, if the feature is dropped instead.
