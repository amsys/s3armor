#!/usr/bin/env bash
# multi-backend-check: two independent MinIO backends, two clients each
# routed to a different one. Proves the things a single-backend check can't:
#
#   1. a client's PUT lands on ITS backend and nowhere else
#   2. the footer cache never serves one backend's object for another's
#      request to the same bucket/key (the A.6 cache-collision case)
#   3. an abandoned multipart upload is aborted on the backend it was
#      created on, not left dangling and not aborted on the wrong one
#      (the mpu.rs SessionKey fix — this is the one thing nothing else in
#      the test suite exercises against the real, hardcoded 60s sweeper
#      tick, so this script's third check is the only one that costs real
#      wall-clock time; the rest are fast)
#
# Requires: docker, cargo, aws-cli v2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"
MINIO_A="s3a-multi-backend-check-minio-a"
MINIO_B="s3a-multi-backend-check-minio-b"
MINIO_A_PORT=19120
MINIO_B_PORT=19121
PROXY_PORT=18190
BUCKET="multi-backend-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_A" "$MINIO_B" >/dev/null 2>&1
  [ -n "${MB_CHECK_KEEP_WORKDIR:-}" ] || rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws; do
  command -v "$tool" >/dev/null || { echo "multi-backend-check: missing required tool: $tool" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
echo "== building s3armor =="
cargo build -p s3armor --quiet

start_minio() {
  local name="$1" port="$2"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" -p "$port:9000" \
    -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
    minio/minio server /data >/dev/null
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$port/minio/health/live" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "multi-backend-check: MinIO ($name) never became healthy" >&2
  exit 1
}

echo "== starting two independent MinIO backends =="
start_minio "$MINIO_A" "$MINIO_A_PORT"
start_minio "$MINIO_B" "$MINIO_B_PORT"

echo "== starting s3armor serve on :$PROXY_PORT with two backends, two clients =="
# S3A_MP_TTL as low as the parser accepts (whole seconds) — the real
# sweeper still ticks every 60s regardless (hardcoded, not configurable),
# so check #3 below waits on that tick, not this TTL.
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_MP_TTL=1s \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_A_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_BACKEND_BRAVO_ENDPOINT="http://127.0.0.1:$MINIO_B_PORT" \
S3A_BACKEND_BRAVO_ACCESS_KEY=minioadmin \
S3A_BACKEND_BRAVO_SECRET_KEY=minioadmin \
S3A_CLIENT_ALPHA_ACCESS_KEY=alphakey \
S3A_CLIENT_ALPHA_SECRET_KEY=alphasecret1234567890 \
S3A_CLIENT_BRAVO_ACCESS_KEY=bravokey \
S3A_CLIENT_BRAVO_SECRET_KEY=bravosecret1234567890 \
S3A_CLIENT_BRAVO_BACKEND=BRAVO \
S3A_KEY_ACTIVE=MBCHECK \
S3A_KEY_MBCHECK="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
"$S3ARMOR" serve >"$WORKDIR/s3armor.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
  echo "multi-backend-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

AWS_ALPHA="aws --endpoint-url http://127.0.0.1:$PROXY_PORT"
AWS_BRAVO="aws --endpoint-url http://127.0.0.1:$PROXY_PORT"
AWS_DIRECT_A="aws --endpoint-url http://127.0.0.1:$MINIO_A_PORT"
AWS_DIRECT_B="aws --endpoint-url http://127.0.0.1:$MINIO_B_PORT"
export AWS_DEFAULT_REGION=us-east-1

echo "== creating $BUCKET on both backends directly =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin $AWS_DIRECT_A s3 mb "s3://$BUCKET" >/dev/null
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin $AWS_DIRECT_B s3 mb "s3://$BUCKET" >/dev/null

echo "== check 1: client ALPHA's PUT lands on backend A only =="
echo "alpha's object" >"$WORKDIR/alpha.txt"
AWS_ACCESS_KEY_ID=alphakey AWS_SECRET_ACCESS_KEY=alphasecret1234567890 \
  $AWS_ALPHA s3 cp "$WORKDIR/alpha.txt" "s3://$BUCKET/shared-key.txt" >/dev/null
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  $AWS_DIRECT_A s3 ls "s3://$BUCKET/shared-key.txt" >/dev/null || {
    echo "multi-backend-check: FAIL — ALPHA's object did not land on backend A" >&2; exit 1; }
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  $AWS_DIRECT_B s3 ls "s3://$BUCKET/shared-key.txt" >/dev/null 2>&1 && {
    echo "multi-backend-check: FAIL — ALPHA's object leaked onto backend B" >&2; exit 1; }
echo "  ok: object present on A, absent on B"

echo "== check 2: client BRAVO's GET of the same bucket/key sees backend B, not A's object =="
AWS_ACCESS_KEY_ID=bravokey AWS_SECRET_ACCESS_KEY=bravosecret1234567890 \
  $AWS_BRAVO s3api head-object --bucket "$BUCKET" --key "shared-key.txt" >/dev/null 2>&1 && {
    echo "multi-backend-check: FAIL — BRAVO (backend B) unexpectedly found ALPHA's (backend A) object" >&2; exit 1; }
echo "  ok: BRAVO gets NoSuchKey — no cross-backend cache collision"

echo "== check 3: an abandoned multipart upload is aborted on its own backend, not the other =="
UPLOAD_ID=$(AWS_ACCESS_KEY_ID=alphakey AWS_SECRET_ACCESS_KEY=alphasecret1234567890 \
  $AWS_ALPHA s3api create-multipart-upload --bucket "$BUCKET" --key "abandoned.bin" \
  --query 'UploadId' --output text)
echo "  created upload $UPLOAD_ID on backend A via client ALPHA, abandoning it"
echo "  waiting up to 90s for the real 60s sweeper tick to reap it..."
REAPED=0
for _ in $(seq 1 90); do
  # `--output text` on an empty match renders the literal string "None",
  # not an empty string — `length(...)` returns an unambiguous number
  # instead, so "reaped" is a real `0`, not a text quirk to special-case.
  # `Uploads` is absent (not an empty array) once the bucket has zero
  # in-progress uploads, so `Uploads[?...]` alone is null — `length(null)`
  # is a hard AWS CLI error, not `0`. `|| \`[]\`` coalesces that null to an
  # empty array first, so `length(...)` always returns a real number.
  COUNT=$(AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    $AWS_DIRECT_A s3api list-multipart-uploads --bucket "$BUCKET" \
    --query "length(Uploads[?UploadId=='$UPLOAD_ID'] || \`[]\`)" --output text 2>/dev/null || echo 1)
  [ "$COUNT" = "0" ] && { REAPED=1; break; }
  sleep 1
done
[ "$REAPED" -eq 1 ] || {
  echo "multi-backend-check: FAIL — upload was not aborted on backend A within 90s" >&2
  exit 1
}
# Backend B was never touched by this upload — a dangling upload there
# would mean the sweeper resolved the wrong backend from the session key.
DANGLING_B=$(AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  $AWS_DIRECT_B s3api list-multipart-uploads --bucket "$BUCKET" \
  --query "length(Uploads || \`[]\`)" --output text 2>/dev/null || echo 1)
[ "$DANGLING_B" = "0" ] || {
  echo "multi-backend-check: FAIL — backend B has $DANGLING_B dangling multipart upload(s)" >&2
  exit 1
}
echo "  ok: aborted on backend A, backend B untouched"

echo "== multi-backend check: PASS =="
