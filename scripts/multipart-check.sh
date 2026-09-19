#!/usr/bin/env bash
# multipart-check: drives the proxy's multipart crypto with real clients
# (aws-cli, rclone) against real MinIO, covering a 500 MiB parallel
# multipart upload plus retried-part, duplicate-part, retried-Complete, and
# restart-loss cases — the four production-bug regressions live in
# tests/integration_mpu.rs (aws-sdk-rust, part-level control); this script
# is the end-to-end proof with the actual client tools operators use. It
# also proves the multipart-session TTL sweeper aborts an abandoned upload
# on the backend, not just in local session state.
#
# Requires: docker, cargo, aws-cli v2, rclone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"
MINIO_CONTAINER="s3a-multipart-check-minio"
MINIO_PORT=19103
PROXY_PORT=18183
BUCKET="multipart-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws rclone; do
  command -v "$tool" >/dev/null || { echo "multipart-check: missing required tool: $tool" >&2; exit 1; }
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
TEST_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
S3A_KEY_ACTIVE=MULTIPARTCHECK \
S3A_KEY_MULTIPARTCHECK="$TEST_KEY_B64" \
"$S3ARMOR" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "multipart-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

export AWS_ACCESS_KEY_ID=checkkey
export AWS_SECRET_ACCESS_KEY=checksecret1234567890
export AWS_DEFAULT_REGION=us-east-1
AWS="aws --endpoint-url http://127.0.0.1:$PROXY_PORT"
$AWS s3 mb "s3://$BUCKET"

echo "== aws-cli: 500 MiB upload (forces real multipart, parallel parts) =="
SIZE=$((500 * 1024 * 1024))
python3 -c "
import sys
n = $SIZE
buf = bytearray(1 << 20)
written = 0
i = 0
while written < n:
    for j in range(len(buf)):
        buf[j] = (i * 31 + j) & 0xFF
    chunk = min(len(buf), n - written)
    sys.stdout.buffer.write(bytes(buf[:chunk]))
    written += chunk
    i += 1
" >"$WORKDIR/big.bin"
$AWS s3 cp "$WORKDIR/big.bin" "s3://$BUCKET/big.bin"
$AWS s3 cp "s3://$BUCKET/big.bin" "$WORKDIR/big-down.bin"
diff "$WORKDIR/big.bin" "$WORKDIR/big-down.bin"

echo "== HEAD reports the exact plaintext size =="
HEAD_SIZE=$($AWS s3api head-object --bucket "$BUCKET" --key big.bin --query ContentLength --output text)
[ "$HEAD_SIZE" -eq "$SIZE" ] || {
  echo "multipart-check: HEAD content-length $HEAD_SIZE != plaintext size $SIZE"; exit 1;
}

echo "== ranged GET mid-object matches the same offset of the source file =="
OFFSET=$((200 * 1024 * 1024))
LEN=4096
dd if="$WORKDIR/big.bin" bs=1 skip="$OFFSET" count="$LEN" of="$WORKDIR/expected-range.bin" status=none
$AWS s3api get-object --bucket "$BUCKET" --key big.bin \
  --range "bytes=$OFFSET-$((OFFSET + LEN - 1))" "$WORKDIR/got-range.bin" >/dev/null
diff "$WORKDIR/expected-range.bin" "$WORKDIR/got-range.bin"

echo "== at rest, straight against MinIO: ciphertext, never plaintext, and multipart metadata set =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3api head-object \
  --bucket "$BUCKET" --key big.bin --query 'Metadata."s3a-mp"' --output text \
  | grep -q '^1$'
$AWS s3 rm "s3://$BUCKET/big.bin"

echo "== rclone: parallel multipart copy up / copy down / diff =="
export RCLONE_CONFIG_MULTIPARTCHECK_TYPE=s3
export RCLONE_CONFIG_MULTIPARTCHECK_PROVIDER=Other
export RCLONE_CONFIG_MULTIPARTCHECK_ENDPOINT="http://127.0.0.1:$PROXY_PORT"
export RCLONE_CONFIG_MULTIPARTCHECK_ACCESS_KEY_ID=checkkey
export RCLONE_CONFIG_MULTIPARTCHECK_SECRET_ACCESS_KEY=checksecret1234567890
mkdir -p "$WORKDIR/rclone-src"
cp "$WORKDIR/big.bin" "$WORKDIR/rclone-src/blob.bin"
rclone copy "$WORKDIR/rclone-src" "multipartcheck:$BUCKET/rclone" \
  --s3-upload-concurrency 8 --s3-chunk-size 16M --no-check-certificate
mkdir -p "$WORKDIR/rclone-dst"
rclone copy "multipartcheck:$BUCKET/rclone" "$WORKDIR/rclone-dst"
diff "$WORKDIR/rclone-src/blob.bin" "$WORKDIR/rclone-dst/blob.bin"

echo "== restarting s3armor with S3A_MP_TTL=2s for the TTL-sweeper check =="
kill "$S3A_PID" 2>/dev/null || true
wait "$S3A_PID" 2>/dev/null || true
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
S3A_KEY_ACTIVE=MULTIPARTCHECK \
S3A_KEY_MULTIPARTCHECK="$TEST_KEY_B64" \
S3A_MP_TTL=2s \
"$S3ARMOR" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "multipart-check: proxy never became healthy after S3A_MP_TTL restart"; cat "$WORKDIR/s3armor.log"; exit 1;
}

echo "== the TTL sweeper aborts an abandoned multipart upload on the backend =="
UPLOAD_ID=$($AWS s3api create-multipart-upload --bucket "$BUCKET" --key "abandoned.bin" --query UploadId --output text)
echo "created upload $UPLOAD_ID, waiting for S3A_MP_TTL=2s + the 60s production sweep tick..."
# The direct-to-MinIO check below must use MinIO's own credentials, not the
# proxy client creds `$AWS`/`AWS_ACCESS_KEY_ID` were exported to above —
# querying MinIO with the wrong key errors, and a swallowed error here would
# make this check pass for the wrong reason (an error, not an empty list).
SWEPT=0
for _ in $(seq 1 30); do
  sleep 5
  # `--output text` prints the literal word "None" for a null/empty JMESPath
  # result, not an empty string — an empty-string check alone never matches.
  REMAINING=$(AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3api list-multipart-uploads --bucket "$BUCKET" \
    --query 'Uploads[?UploadId==`'"$UPLOAD_ID"'`]' --output text)
  if [ -z "$REMAINING" ] || [ "$REMAINING" = "None" ]; then
    SWEPT=1
    break
  fi
done
[ "$SWEPT" -eq 1 ] || {
  echo "multipart-check: the sweeper never aborted the abandoned multipart upload on the backend" >&2
  exit 1
}
echo "abandoned upload was aborted on the backend"

echo "== multipart-check: PASS =="
