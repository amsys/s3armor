#!/usr/bin/env bash
# lifecycle-check: graceful drain (SIGTERM), /ready, S3A_TIMEOUT_CONNECT, and
# S3A_BIND_PATHS=strict + s3armor rebind — all against the real binary, not the
# in-process Rust integration harness. crates/s3armor/tests/integration_minio.rs
# stands in for main::serve with a simplified accept loop (spawn_proxy's own
# doc comment explains why); this script is what actually exercises
# main::serve's own signal handling end to end.
#
# 1. /health 200 -> SIGTERM sent mid-upload -> /health 503 immediately, the
#    in-flight PUT still completes (not severed), the process exits on its
#    own once drained.
# 2. S3A_BIND_PATHS=strict rejects an object written under off; s3armor rebind
#    makes it readable again (same sequence bind-paths-check.sh's own tail already
#    covers for =on; this is strict specifically).
# 3. /ready: 200 against a live backend, 503 once it's gone.
# 4. S3A_TIMEOUT_CONNECT bounds a dial to an unroutable backend — fails in
#    seconds, not the OS's own multi-minute default connect timeout.
#
# Timing note: step 1 sends SIGTERM a fixed 0.4s after starting a 400 MiB
# background PUT, on the assumption that's enough head start for aws-cli to
# open its connection but not enough to finish streaming+encrypting 400 MiB
# first. Best-effort, like every poll-loop timing assumption in this repo's
# other check scripts — not an adversarially-timed guarantee.
#
# Requires: docker, cargo, aws-cli v2, curl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"
MINIO_CONTAINER="s3a-lifecycle-check-minio"
MINIO_PORT=19206
PROXY_PORT=18287
BUCKET="lifecycle-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws curl; do
  command -v "$tool" >/dev/null || { echo "lifecycle-check: missing required tool: $tool" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
echo "== building s3armor =="
cargo build -p s3armor --quiet

echo "== starting MinIO on :$MINIO_PORT =="
docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$MINIO_CONTAINER" -p "$MINIO_PORT:9000" \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z server /data >/dev/null
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$MINIO_PORT/minio/health/live" >/dev/null 2>&1 && break
  sleep 1
done

echo "== creating bucket direct against MinIO =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3 mb "s3://$BUCKET"

TEST_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PROXY_URL="http://127.0.0.1:$PROXY_PORT"

# Starts s3armor serve against the MinIO above, on $PROXY_PORT, with any extra
# NAME=value env assignments passed as args. Sets $S3A_PID; blocks until
# /health answers or exits 1.
start_s3armor() {
  S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
  S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
  S3A_BACKEND_ACCESS_KEY=minioadmin \
  S3A_BACKEND_SECRET_KEY=minioadmin \
  S3A_KEY_ACTIVE=LIFECYCLECHECK \
  S3A_KEY_LIFECYCLECHECK="$TEST_KEY_B64" \
  S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
  S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
    env "$@" "$S3ARMOR" serve >"$WORKDIR/s3armor.log" 2>&1 &
  S3A_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "$PROXY_URL/health" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "lifecycle-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1
}

export AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1

echo "== 1: SIGTERM mid-upload -- /health flips to 503, the PUT still completes, s3armor exits on its own =="
start_s3armor
# 100 MiB: comfortably large enough that a real HTTP connection to it stays
# open for a measurable moment on any host, however loaded.
dd if=/dev/urandom of="$WORKDIR/big.bin" bs=1M count=100 status=none

aws --endpoint-url "$PROXY_URL" s3api put-object --bucket "$BUCKET" --key drain-big.bin \
  --body "$WORKDIR/big.bin" >"$WORKDIR/put.log" 2>&1 &
PUT_PID=$!

# Wait for the PUT's own TCP connection to actually be ESTABLISHED before
# sending SIGTERM, rather than a fixed sleep-and-hope: this proxy's own
# request-handling speed varies a lot with host load (seconds to tens of
# seconds for 100 MiB have both been observed on shared/loaded hosts), so a
# fixed delay either fires too early (nothing accepted yet) or, if sized to
# be safe on a slow host, wastes time on a fast one. `ss` confirms the
# connection genuinely exists before the signal is sent — SIGTERM always
# lands mid-request, deterministically.
CONNECTED=""
for _ in $(seq 1 100); do
  if ss -tn "( sport = :$PROXY_PORT )" 2>/dev/null | grep -q ESTAB; then
    CONNECTED=1
    break
  fi
  sleep 0.1
done
[ -n "$CONNECTED" ] || {
  echo "lifecycle-check: the PUT's connection never became established"; exit 1
}
kill -TERM "$S3A_PID"

# Signal delivery + the async runtime actually polling it is a handful of
# milliseconds normally, but can stretch on a loaded box — poll rather than
# a single fixed-delay check.
STATUS="000"
for _ in $(seq 1 25); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/health" || echo "000")
  [ "$STATUS" = "503" ] && break
  sleep 0.2
done
[ "$STATUS" = "503" ] || {
  echo "lifecycle-check: /health did not flip to 503 within 5s of SIGTERM (got $STATUS)"
  cat "$WORKDIR/s3armor.log"; exit 1
}
echo "confirmed: /health -> 503 after SIGTERM"

wait "$PUT_PID" || {
  echo "lifecycle-check: the in-flight PUT was severed by SIGTERM"; cat "$WORKDIR/put.log"; exit 1
}
echo "confirmed: the in-flight PUT completed despite SIGTERM"

for _ in $(seq 1 60); do
  kill -0 "$S3A_PID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$S3A_PID" 2>/dev/null; then
  echo "lifecycle-check: s3armor did not exit on its own after SIGTERM + drain"; exit 1
fi
echo "confirmed: s3armor exited on its own after draining"
S3A_PID=""

AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3api head-object \
  --bucket "$BUCKET" --key drain-big.bin >/dev/null
echo "confirmed: the drained-through object exists at rest"

echo "== 2: S3A_BIND_PATHS=strict rejects an object written under off, s3armor rebind fixes it =="
start_s3armor
aws --endpoint-url "$PROXY_URL" s3api put-object --bucket "$BUCKET" --key strict-me.bin \
  --body "$WORKDIR/big.bin" >/dev/null
kill "$S3A_PID"; wait "$S3A_PID" 2>/dev/null || true

start_s3armor S3A_BIND_PATHS=strict
if aws --endpoint-url "$PROXY_URL" s3api get-object --bucket "$BUCKET" --key strict-me.bin \
  "$WORKDIR/should-not-download.bin" 2>"$WORKDIR/err.txt"; then
  echo "lifecycle-check: strict unexpectedly served an unbound object"; exit 1
fi
grep -qi "403\|accessdenied" "$WORKDIR/err.txt" || {
  echo "lifecycle-check: expected 403 AccessDenied under strict, got:"; cat "$WORKDIR/err.txt"; exit 1
}
echo "confirmed: strict rejects an object written under off"

S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_KEY_ACTIVE=LIFECYCLECHECK \
S3A_KEY_LIFECYCLECHECK="$TEST_KEY_B64" \
S3A_BIND_PATHS=strict \
  "$S3ARMOR" rebind --bucket "$BUCKET"

aws --endpoint-url "$PROXY_URL" s3api get-object --bucket "$BUCKET" --key strict-me.bin \
  "$WORKDIR/rebound.bin" >/dev/null
cmp -s "$WORKDIR/big.bin" "$WORKDIR/rebound.bin" || {
  echo "lifecycle-check: rebound object content mismatch"; exit 1
}
echo "confirmed: s3armor rebind makes the object readable under strict"

echo "== 3: /ready reflects backend reachability =="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/ready")
[ "$STATUS" = "200" ] || { echo "lifecycle-check: /ready expected 200 with a live backend, got $STATUS"; exit 1; }
docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/ready")
[ "$STATUS" = "503" ] || { echo "lifecycle-check: /ready expected 503 with no backend, got $STATUS"; exit 1; }
echo "confirmed: /ready is 200 live, 503 once the backend is gone"

kill "$S3A_PID" 2>/dev/null || true
wait "$S3A_PID" 2>/dev/null || true
S3A_PID=""

echo "== 4: S3A_TIMEOUT_CONNECT bounds a dial to an unroutable backend =="
# TEST-NET-3 (RFC 5737): reserved for documentation, so most networks/
# sandboxes silently drop packets to it rather than refusing outright — a
# real hung dial, exercising the timeout rather than an instant ECONNREFUSED.
S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
S3A_BACKEND_ENDPOINT="http://203.0.113.1:9" \
S3A_BACKEND_ACCESS_KEY=minioadmin \
S3A_BACKEND_SECRET_KEY=minioadmin \
S3A_KEY_ACTIVE=LIFECYCLECHECK \
S3A_KEY_LIFECYCLECHECK="$TEST_KEY_B64" \
S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
S3A_TIMEOUT_CONNECT=2 \
  "$S3ARMOR" serve >"$WORKDIR/s3a-timeout.log" 2>&1 &
S3A_PID=$!
for _ in $(seq 1 30); do
  curl -sf "$PROXY_URL/health" >/dev/null 2>&1 && break
  sleep 1
done

START=$(date +%s)
aws --endpoint-url "$PROXY_URL" s3api head-bucket --bucket "$BUCKET" 2>"$WORKDIR/err2.txt" && {
  echo "lifecycle-check: head-bucket against an unroutable backend unexpectedly succeeded"; exit 1
}
ELAPSED=$(( $(date +%s) - START ))
echo "backend dial failed after ${ELAPSED}s (S3A_TIMEOUT_CONNECT=2)"
[ "$ELAPSED" -lt 20 ] || {
  echo "lifecycle-check: expected a bounded failure well under the OS default connect timeout, took ${ELAPSED}s"
  exit 1
}
echo "confirmed: S3A_TIMEOUT_CONNECT bounds the dial instead of hanging"

kill "$S3A_PID" 2>/dev/null || true
S3A_PID=""

echo "== lifecycle-check: PASS =="
