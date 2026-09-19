#!/usr/bin/env bash
# passthrough-check: drives the proxy with real clients (aws-cli, rclone), not just
# aws-sdk-rust in the integration suite.
#
# Requires: docker, cargo, aws-cli v2, rclone (native install).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"
MINIO_CONTAINER="s3a-passthrough-check-minio"
MINIO_PORT=19100
PROXY_PORT=18180
BUCKET="passthrough-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws rclone; do
  command -v "$tool" >/dev/null || { echo "passthrough-check: missing required tool: $tool" >&2; exit 1; }
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

echo "== starting s3armor serve on :$PROXY_PORT =="
# A master key is mandatory at startup (an encryption proxy that silently
# stores plaintext because a key var was missing is the failure mode this
# product exists to prevent) — a throwaway all-zero key is fine for this
# local passthrough-architecture check.
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
S3A_KEY_ACTIVE=PASSTHROUGHCHECK \
S3A_KEY_PASSTHROUGHCHECK="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
"$S3ARMOR" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "passthrough-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

export AWS_ACCESS_KEY_ID=checkkey
export AWS_SECRET_ACCESS_KEY=checksecret1234567890
export AWS_DEFAULT_REGION=us-east-1
AWS="aws --endpoint-url http://127.0.0.1:$PROXY_PORT"

echo "== aws-cli: mb / cp up / ls / cp down / diff / rm =="
$AWS s3 mb "s3://$BUCKET"
echo "hello from passthrough-check, with spaces and a café" >"$WORKDIR/up.txt"
$AWS s3 cp "$WORKDIR/up.txt" "s3://$BUCKET/a dir/café.txt"
$AWS s3 ls "s3://$BUCKET/" --recursive | grep -q "café.txt"
$AWS s3 cp "s3://$BUCKET/a dir/café.txt" "$WORKDIR/down.txt"
diff "$WORKDIR/up.txt" "$WORKDIR/down.txt"
$AWS s3 rm "s3://$BUCKET/a dir/café.txt"

echo "== rclone: copy up / check / copy down / lsjson =="
export RCLONE_CONFIG_PASSTHROUGHCHECK_TYPE=s3
export RCLONE_CONFIG_PASSTHROUGHCHECK_PROVIDER=Other
export RCLONE_CONFIG_PASSTHROUGHCHECK_ENDPOINT="http://127.0.0.1:$PROXY_PORT"
export RCLONE_CONFIG_PASSTHROUGHCHECK_ACCESS_KEY_ID=checkkey
export RCLONE_CONFIG_PASSTHROUGHCHECK_SECRET_ACCESS_KEY=checksecret1234567890
mkdir -p "$WORKDIR/rclone-src"
head -c 2000000 /dev/urandom >"$WORKDIR/rclone-src/blob.bin"
rclone copy "$WORKDIR/rclone-src" "passthroughcheck:$BUCKET/rclone" --no-check-certificate
# Not `rclone check`: PUT/GET/HEAD are encrypted by default and
# `rclone check` gates on ListObjectsV2's reported size before comparing
# content — List stays passthrough on purpose (docs/ARCHITECTURE.md "List sizes are ciphertext sizes"), so
# it reports the ciphertext size, not the plaintext size. `copy` + `diff`
# below prove the same byte-exact round-trip property, through the size
# that actually holds.
mkdir -p "$WORKDIR/rclone-dst"
rclone copy "passthroughcheck:$BUCKET/rclone" "$WORKDIR/rclone-dst"
diff "$WORKDIR/rclone-src/blob.bin" "$WORKDIR/rclone-dst/blob.bin"
rclone lsjson "passthroughcheck:$BUCKET/rclone" | grep -q "blob.bin"

echo "== passthrough-check: PASS =="
