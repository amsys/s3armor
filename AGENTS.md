# AGENTS.md — orientation for s3armor (Rust)

## What this is

A client-side S3 encryption proxy. It sits between S3-compatible storage and
applications that speak S3 (Nextcloud, Stalwart, restic, rclone, s3cmd,
aws-cli). It makes the ciphertext the only thing the storage operator ever
sees.

Design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). User-facing
behavior: [`docs/USER-GUIDE.md`](docs/USER-GUIDE.md). Contributor workflow:
[`docs/DEVELOPER-GUIDE.md`](docs/DEVELOPER-GUIDE.md). Read the architecture
doc before making a change that touches format, crypto, or the S3 operation
matrix — it records decisions and rejected alternatives so you do not
re-litigate them.

## Documentation and comment style

Write all documentation and comments in **ASD-STE100 Simplified Technical
English**: approved words, short sentences, active voice, one topic per
sentence. This rule is stated here only — do not repeat it in other files.

## Repo layout

```
crates/s3armor-format/   pure crypto/framing (v1), no tokio, no http
crates/s3armor/           binary: proxy, sigv4, intercept, tools, config
```

`s3armor-format` has no dependency on `s3armor`. It is the fuzzable, benchable,
auditable surface — keep it that way.

## Conventions

- Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`,
  `chore:`). Reference the relevant `docs/ARCHITECTURE.md` section (e.g.
  "Path binding") or a GitHub issue in the commit body, when applicable.
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` clean before
  every commit. This is enforced, not honor-system: run
  `pre-commit install --install-hooks` once per clone (see below).
- No new abstraction for a single implementation. No config knob without a
  test exercising its effect.

## Lint policy and pre-commit hooks

The strict lint policy lives in `Cargo.toml`'s `[workspace.lints]`
(`clippy::pedantic` + `clippy::nursery`, plus the `unwrap_used`/
`expect_used`/`indexing_slicing`/... restriction lints) and `clippy.toml`
(MSRV, test-code allowances). Every `#[expect(...)]` in the tree names the
specific invariant that makes the lint a false positive at that site — do
not delete one without checking that invariant still holds.

`.pre-commit-config.yaml` runs `cargo fmt`, `cargo clippy -D warnings`, and
hygiene/secret-scan hooks (gitleaks, shellcheck, `detect-private-key`) on
`pre-commit`; `cargo test` and `cargo deny check` on `pre-push`. Install
once with:

```sh
pre-commit install --install-hooks
```

CI (`.github/workflows/ci.yml`) runs the same checks plus `pre-commit run
--all-files` and a `cargo-llvm-cov` coverage job feeding a SonarCloud scan
(`sonar-project.properties`) — a skipped local install still gets caught.
