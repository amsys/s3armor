#!/usr/bin/env bash
# tooling-check: generate a key -> `s3armor check --bucket` full green against
# real MinIO -> `s3armor bench` local/--backend-tier/--proxy tiers all run ->
# `--write-config` output is valid env `s3armor serve` accepts.
#
# Requires: docker, cargo, aws-cli v2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINIO_CONTAINER="s3a-tooling-check-minio"
MINIO_PORT=19104
PROXY_PORT=18184
BUCKET="tooling-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws; do
  command -v "$tool" >/dev/null || { echo "tooling-check: missing required tool: $tool" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
echo "== building s3armor =="
cargo build -p s3armor --quiet

echo "== starting MinIO on :$MINIO_PORT =="
docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$MINIO_CONTAINER" -p "$MINIO_PORT:9000" \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data >/dev/null
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$MINIO_PORT/minio/health/live" >/dev/null 2>&1 && break
  sleep 1
done

echo "== generating a master key =="
KEY_B64="$(openssl rand -base64 32)"
[ -n "$KEY_B64" ] || { echo "tooling-check: openssl rand produced no key"; exit 1; }
# RSA keypair generation/parsing (the write-only ingestion node path) has no
# CLI surface to smoke anymore — it's covered directly by
# crates/s3armor-format/src/v1/wrap.rs's own unit test
# (rsa_pem_round_trips_to_the_same_key_id), which exercises the same
# RsaKek::generate/from_private_pem/from_public_pem code this script would
# otherwise be smoke-testing through a subprocess.

echo "== creating bucket direct against MinIO =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3 mb "s3://$BUCKET"

BACKEND_ENV=(
  S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT"
  S3A_BACKEND_ACCESS_KEY=minioadmin
  S3A_BACKEND_SECRET_KEY=minioadmin
  S3A_KEY_ACTIVE=TOOLINGCHECK
  S3A_KEY_TOOLINGCHECK="$KEY_B64"
)

echo "== s3armor check --bucket $BUCKET (direct to backend) =="
# Local MinIO over plain http is expected to land on "degraded" (the
# TLS-not-in-use warning, docs/ARCHITECTURE.md "UNSIGNED-PAYLOAD to the backend over TLS") — the
# reachable/exit-0-worthy verdicts are compatible and degraded; only
# "incompatible" (a real probe
# failure) should fail this check. `$()` under `set -e` already requires
# `check` to have exited 0 (compatible/degraded), so this is belt and
# suspenders against the wording itself.
CHECK_OUT="$(env "${BACKEND_ENV[@]}" "$ROOT/target/debug/s3armor" check --bucket "$BUCKET")"
echo "$CHECK_OUT"
echo "$CHECK_OUT" | grep -q "verdict: incompatible" && {
  echo "tooling-check: s3armor check reported 'incompatible' against real MinIO"; exit 1;
}
true

echo "== s3armor bench (local tier) =="
env "${BACKEND_ENV[@]}" "$ROOT/target/debug/s3armor" bench | tee "$WORKDIR/bench-local.txt"
grep -q "recommended: S3A_ALG=" "$WORKDIR/bench-local.txt"

echo "== s3armor bench --backend-tier --bucket $BUCKET =="
env "${BACKEND_ENV[@]}" "$ROOT/target/debug/s3armor" bench --backend-tier --bucket "$BUCKET" | tee "$WORKDIR/bench-backend.txt"
grep -q "max sustained concurrency" "$WORKDIR/bench-backend.txt"

echo "== starting s3armor serve on :$PROXY_PORT for the --proxy tier =="
env "${BACKEND_ENV[@]}" S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
  S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
  S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
  "$ROOT/target/debug/s3armor" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "tooling-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

echo "== s3armor bench --proxy http://127.0.0.1:$PROXY_PORT --bucket $BUCKET =="
# The --proxy tier authenticates against the running proxy like any other
# S3 client — needs the same S3A_CLIENT_* credential `serve` was started
# with, not just the backend-direct vars every other invocation here uses.
env "${BACKEND_ENV[@]}" \
  S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
  S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
  "$ROOT/target/debug/s3armor" bench --proxy "http://127.0.0.1:$PROXY_PORT" --bucket "$BUCKET" \
  | tee "$WORKDIR/bench-proxy.txt"
grep -q "verified" "$WORKDIR/bench-proxy.txt"
grep -q " NO" "$WORKDIR/bench-proxy.txt" && {
  echo "tooling-check: proxy-vs-direct tier reported an unverified (corrupted) round-trip"; exit 1;
}

kill "$S3A_PID" 2>/dev/null || true
S3A_PID=""

echo "== --write-config output is valid env s3armor accepts =="
WRITE_CONFIG_OUT="$(env "${BACKEND_ENV[@]}" "$ROOT/target/debug/s3armor" bench --write-config)"
echo "$WRITE_CONFIG_OUT"
eval "export ${WRITE_CONFIG_OUT//$'\n'/$'\n'export }"
env "${BACKEND_ENV[@]}" S3A_ALG="$S3A_ALG" S3A_CHUNK_SIZE="$S3A_CHUNK_SIZE" \
  "$ROOT/target/debug/s3armor" config >/dev/null

echo "== tooling-check: PASS =="
