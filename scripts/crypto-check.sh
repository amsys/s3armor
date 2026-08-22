#!/usr/bin/env bash
# crypto-check: drives the proxy's single-part crypto (PUT encrypt, GET/HEAD
# decrypt) with real clients (aws-cli, rclone), not just aws-sdk-rust in the
# integration suite (s3cmd is not installed on every dev machine, so
# aws-cli stands in for the same "a real client's own checksum verification
# trusts our ETag policy" property `rclone check` proves).
#
# Requires: docker, cargo, aws-cli v2, rclone.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINIO_CONTAINER="s3a-crypto-check-minio"
MINIO_PORT=19101
PROXY_PORT=18181
BUCKET="crypto-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws rclone; do
  command -v "$tool" >/dev/null || { echo "crypto-check: missing required tool: $tool" >&2; exit 1; }
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
# A 32-byte all-zero key, base64'd — fine for a throwaway local check.
TEST_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
S3A_KEY_ACTIVE=CRYPTOCHECK \
S3A_KEY_CRYPTOCHECK="$TEST_KEY_B64" \
"$ROOT/target/debug/s3armor" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "crypto-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

export AWS_ACCESS_KEY_ID=checkkey
export AWS_SECRET_ACCESS_KEY=checksecret1234567890
export AWS_DEFAULT_REGION=us-east-1
AWS="aws --endpoint-url http://127.0.0.1:$PROXY_PORT"
MINIO_AWS="aws --endpoint-url http://127.0.0.1:$MINIO_PORT"

echo "== aws-cli: mb / cp up / ls / cp down / diff =="
$AWS s3 mb "s3://$BUCKET"
echo "hello from crypto-check, with spaces and a café" >"$WORKDIR/up.txt"
$AWS s3 cp "$WORKDIR/up.txt" "s3://$BUCKET/a dir/café.txt"
$AWS s3 ls "s3://$BUCKET/" --recursive | grep -q "café.txt"
$AWS s3 cp "s3://$BUCKET/a dir/café.txt" "$WORKDIR/down.txt"
diff "$WORKDIR/up.txt" "$WORKDIR/down.txt"

echo "== the proxy's own ls shows the ciphertext size, not the plaintext size =="
PLAINTEXT_SIZE=$(wc -c <"$WORKDIR/up.txt")
PROXY_SIZE=$($AWS s3 ls "s3://$BUCKET/a dir/café.txt" | awk '{print $3}')
[ "$PROXY_SIZE" -gt "$PLAINTEXT_SIZE" ] || {
  echo "crypto-check: expected the stored (ciphertext) size ($PROXY_SIZE) to exceed the plaintext size ($PLAINTEXT_SIZE)"; exit 1;
}

echo "== at rest, straight against MinIO: ciphertext, never plaintext =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin $MINIO_AWS s3api head-object \
  --bucket "$BUCKET" --key "a dir/café.txt" --query 'Metadata."s3a-v"' --output text \
  | grep -q '^1$'
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin $MINIO_AWS s3 cp \
  "s3://$BUCKET/a dir/café.txt" "$WORKDIR/raw-ciphertext.bin"
if cmp -s "$WORKDIR/up.txt" "$WORKDIR/raw-ciphertext.bin"; then
  echo "FAIL: raw object at rest matches plaintext, encryption did not run" >&2
  exit 1
fi
$AWS s3 rm "s3://$BUCKET/a dir/café.txt"

echo "== rclone: copy up / check / copy down / diff / lsjson =="
export RCLONE_CONFIG_CRYPTOCHECK_TYPE=s3
export RCLONE_CONFIG_CRYPTOCHECK_PROVIDER=Other
export RCLONE_CONFIG_CRYPTOCHECK_ENDPOINT="http://127.0.0.1:$PROXY_PORT"
export RCLONE_CONFIG_CRYPTOCHECK_ACCESS_KEY_ID=checkkey
export RCLONE_CONFIG_CRYPTOCHECK_SECRET_ACCESS_KEY=checksecret1234567890
mkdir -p "$WORKDIR/rclone-src"
head -c 2000000 /dev/urandom >"$WORKDIR/rclone-src/blob.bin"
# Deliberately not `rclone check`: it always gates on ListObjectsV2's
# reported size before comparing content — even with `--download` — and
# List stays passthrough on purpose (docs/ARCHITECTURE.md "List sizes are ciphertext sizes": List
# sizes are ciphertext sizes, "not done"; fixing it costs a HEAD per
# listed object). `copy` + `diff` below proves the same byte-exact
# round-trip property `rclone check` exists for, through the property that
# actually holds: the plaintext, not the backend's stored size.
rclone copy "$WORKDIR/rclone-src" "cryptocheck:$BUCKET/rclone" --no-check-certificate
mkdir -p "$WORKDIR/rclone-dst"
rclone copy "cryptocheck:$BUCKET/rclone" "$WORKDIR/rclone-dst"
diff "$WORKDIR/rclone-src/blob.bin" "$WORKDIR/rclone-dst/blob.bin"
rclone lsjson "cryptocheck:$BUCKET/rclone" | grep -q "blob.bin"

echo "== a large upload (aws-cli's own multipart threshold) round-trips =="
# Multipart crypto handles large uploads; a large `aws s3 cp` no longer
# gets rejected — see scripts/multipart-check.sh for the dedicated multipart test
# matrix (retried/duplicate/out-of-order parts, retried Complete, ranges
# across a part boundary). This is only a smoke check that this script's
# own scope (single-part crypto) didn't regress the large-object path.
LARGE=$((10 * 1024 * 1024))
head -c "$LARGE" /dev/urandom >"$WORKDIR/big.bin"
$AWS s3 cp "$WORKDIR/big.bin" "s3://$BUCKET/big.bin"
$AWS s3 cp "s3://$BUCKET/big.bin" "$WORKDIR/big-down.bin"
diff "$WORKDIR/big.bin" "$WORKDIR/big-down.bin"
$AWS s3 rm "s3://$BUCKET/big.bin"

echo "== crypto-check: PASS =="
