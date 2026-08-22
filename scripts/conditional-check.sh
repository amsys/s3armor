#!/usr/bin/env bash
# conditional-check: conditional requests (If-Match/If-None-Match) against real
# MinIO, driven by real clients — not the Rust integration harness.
# 1. PUT with Content-MD5 (so s3a-emd5 exists) -> the plaintext ETag.
# 2. aws-cli's own `get-object --if-none-match`/`--if-match` (the SDK path).
# 3. curl with a raw conditional header, asserting the exact HTTP status.
#
# Requires: docker, cargo, aws-cli v2, curl, md5sum, openssl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINIO_CONTAINER="s3a-conditional-check-minio"
MINIO_PORT=19204
PROXY_PORT=18284
BUCKET="conditional-check"
KEY="checked.bin"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws curl md5sum openssl; do
  command -v "$tool" >/dev/null || { echo "conditional-check: missing required tool: $tool" >&2; exit 1; }
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

echo "== creating bucket direct against MinIO =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3 mb "s3://$BUCKET"

TEST_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

echo "== starting s3armor serve on :$PROXY_PORT =="
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_KEY_ACTIVE=CONDITIONALCHECK \
S3A_KEY_CONDITIONALCHECK="$TEST_KEY_B64" \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
  "$ROOT/target/debug/s3armor" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!

for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "conditional-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

export AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1
PROXY_URL="http://127.0.0.1:$PROXY_PORT"

echo "== PUT with Content-MD5 so s3a-emd5 exists =="
echo -n "the quick brown fox jumps over the lazy dog" > "$WORKDIR/plain.txt"
MD5_B64="$(openssl dgst -md5 -binary "$WORKDIR/plain.txt" | openssl base64)"
aws --endpoint-url "$PROXY_URL" s3api put-object \
  --bucket "$BUCKET" --key "$KEY" --body "$WORKDIR/plain.txt" --content-md5 "$MD5_B64" >/dev/null

ETAG="\"$(md5sum "$WORKDIR/plain.txt" | awk '{print $1}')\""
echo "plaintext etag: $ETAG"

echo "== aws-cli: get-object --if-none-match <plaintext etag> must fail (304, no re-download) =="
if aws --endpoint-url "$PROXY_URL" s3api get-object \
  --bucket "$BUCKET" --key "$KEY" --if-none-match "$ETAG" "$WORKDIR/should-not-download.bin" 2>"$WORKDIR/err.txt"; then
  echo "conditional-check: get-object with a matching If-None-Match unexpectedly succeeded"; cat "$WORKDIR/err.txt"; exit 1
fi
grep -qi "304\|not.modified" "$WORKDIR/err.txt" || {
  echo "conditional-check: expected a 304/NotModified error, got:"; cat "$WORKDIR/err.txt"; exit 1;
}

echo "== aws-cli: get-object --if-match <plaintext etag> must succeed with the real plaintext =="
aws --endpoint-url "$PROXY_URL" s3api get-object \
  --bucket "$BUCKET" --key "$KEY" --if-match "$ETAG" "$WORKDIR/downloaded.bin" >/dev/null
diff "$WORKDIR/plain.txt" "$WORKDIR/downloaded.bin" || {
  echo "conditional-check: If-Match GET returned wrong content"; exit 1;
}

echo "== aws-cli: get-object --if-match \"bogus\" must fail (412) =="
if aws --endpoint-url "$PROXY_URL" s3api get-object \
  --bucket "$BUCKET" --key "$KEY" --if-match '"bogus"' "$WORKDIR/should-not-download2.bin" 2>"$WORKDIR/err2.txt"; then
  echo "conditional-check: get-object with a non-matching If-Match unexpectedly succeeded"; cat "$WORKDIR/err2.txt"; exit 1
fi
grep -qi "412\|precondition" "$WORKDIR/err2.txt" || {
  echo "conditional-check: expected a 412/PreconditionFailed error, got:"; cat "$WORKDIR/err2.txt"; exit 1;
}

echo "== curl: raw If-None-Match header against the SigV4-signed URL yields exactly 304 =="
# aws s3 presign carries the signature in the query string, so a plain curl
# with an extra conditional header still authenticates.
PRESIGNED="$(aws --endpoint-url "$PROXY_URL" s3 presign "s3://$BUCKET/$KEY" --expires-in 60)"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "If-None-Match: $ETAG" "$PRESIGNED")
echo "curl status: $STATUS"
[ "$STATUS" = "304" ] || {
  echo "conditional-check: expected curl to see exactly 304, got $STATUS"; exit 1;
}

echo "== aws-cli: head-object --if-none-match <plaintext etag> must fail (304) =="
if aws --endpoint-url "$PROXY_URL" s3api head-object \
  --bucket "$BUCKET" --key "$KEY" --if-none-match "$ETAG" 2>"$WORKDIR/err3.txt"; then
  echo "conditional-check: head-object with a matching If-None-Match unexpectedly succeeded"; cat "$WORKDIR/err3.txt"; exit 1
fi
grep -qi "304\|not.modified" "$WORKDIR/err3.txt" || {
  echo "conditional-check: expected a 304/NotModified error on HEAD, got:"; cat "$WORKDIR/err3.txt"; exit 1;
}

kill "$S3A_PID" 2>/dev/null || true
S3A_PID=""

echo "== conditional-check: PASS =="
