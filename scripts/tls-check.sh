#!/usr/bin/env bash
# tls-check: TLS listener and auth rate limiting, against real MinIO.
# 1. Self-signed cert + S3A_TLS_CERT/S3A_TLS_KEY -> aws-cli round-trips over
#    https, and `s3armor health-probe` succeeds against the TLS listener.
# 2. S3A_AUTH_FAIL_LIMIT small -> repeated bad-signature requests get 429,
#    while a good-credential request still succeeds throughout.
#
# Requires: docker, cargo, aws-cli v2, openssl, curl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINIO_CONTAINER="s3a-tls-check-minio"
MINIO_PORT=19203
PROXY_PORT=18283
BUCKET="tls-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws openssl curl; do
  command -v "$tool" >/dev/null || { echo "tls-check: missing required tool: $tool" >&2; exit 1; }
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

echo "== generating a self-signed cert for 127.0.0.1 =="
openssl req -x509 -newkey ed25519 -nodes \
  -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" \
  -days 1 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
  >/dev/null 2>&1

# A 32-byte all-zero key, base64'd — fine for a throwaway local check.
TEST_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

echo "== starting s3armor serve on :$PROXY_PORT with TLS + S3A_AUTH_FAIL_LIMIT=3 =="
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_KEY_ACTIVE=TLSCHECK \
S3A_KEY_TLSCHECK="$TEST_KEY_B64" \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
S3A_TLS_CERT="$WORKDIR/cert.pem" \
S3A_TLS_KEY="$WORKDIR/key.pem" \
S3A_AUTH_FAIL_LIMIT=3 \
  "$ROOT/target/debug/s3armor" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!

for _ in $(seq 1 30); do
  curl -sfk "https://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sfk "https://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "tls-check: TLS proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

echo "== s3armor health-probe succeeds against the TLS listener =="
env S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
  S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
  S3A_BACKEND_ACCESS_KEY=minioadmin S3A_BACKEND_SECRET_KEY=minioadmin \
  S3A_KEY_ACTIVE=TLSCHECK S3A_KEY_TLSCHECK="$TEST_KEY_B64" \
  S3A_TLS_CERT="$WORKDIR/cert.pem" S3A_TLS_KEY="$WORKDIR/key.pem" \
  "$ROOT/target/debug/s3armor" health-probe

echo "== aws s3 cp round-trip over https (self-signed cert, --no-verify-ssl) =="
echo "hello over tls" > "$WORKDIR/plain.txt"
AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "https://127.0.0.1:$PROXY_PORT" --no-verify-ssl s3 cp "$WORKDIR/plain.txt" "s3://$BUCKET/plain.txt"
AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "https://127.0.0.1:$PROXY_PORT" --no-verify-ssl s3 cp "s3://$BUCKET/plain.txt" "$WORKDIR/plain-down.txt"
diff "$WORKDIR/plain.txt" "$WORKDIR/plain-down.txt" || {
  echo "tls-check: TLS round-trip content mismatch"; exit 1;
}

bad_auth_status() {
  curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: AWS4-HMAC-SHA256 Credential=checkkey/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000" \
    -H "x-amz-date: 20260101T000000Z" \
    "https://127.0.0.1:$PROXY_PORT/$BUCKET/plain.txt"
}

echo "== auth rate limiting: 3 bad-signature requests consume the S3A_AUTH_FAIL_LIMIT=3 budget =="
for i in 1 2 3; do
  STATUS=$(bad_auth_status)
  echo "attempt $i (bad signature): status=$STATUS"
  [ "$STATUS" = "403" ] || {
    echo "tls-check: expected 403 (ordinary auth failure) on attempt $i, got $STATUS"; exit 1;
  }
done

echo "== 4th bad-signature request is rate-limited (429), not a normal auth failure =="
RL_STATUS=$(bad_auth_status)
echo "4th attempt: status=$RL_STATUS"
[ "$RL_STATUS" = "429" ] || {
  echo "tls-check: expected 429 after S3A_AUTH_FAIL_LIMIT=3 was exceeded, got $RL_STATUS"; exit 1;
}

echo "== the IP stays blocked even for a good credential while over budget (per-IP, not per-credential) =="
GOOD_DURING_BLOCK=$(AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "https://127.0.0.1:$PROXY_PORT" --no-verify-ssl s3api head-object \
  --bucket "$BUCKET" --key plain.txt 2>&1 || true)
echo "$GOOD_DURING_BLOCK" | grep -qi "slowdown\|429" || {
  echo "tls-check: expected a good-credential request to also be rate-limited while the IP is over budget"; exit 1;
}

echo "== waiting for the bucket to refill one token (limit 3/min => ~20s/token) =="
sleep 22

echo "== a good-credential request succeeds once the bucket has refilled =="
AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "https://127.0.0.1:$PROXY_PORT" --no-verify-ssl s3api head-object \
  --bucket "$BUCKET" --key plain.txt >/dev/null

kill "$S3A_PID" 2>/dev/null || true
S3A_PID=""

echo "== tls-check: PASS =="
