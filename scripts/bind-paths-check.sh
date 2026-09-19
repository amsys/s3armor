#!/usr/bin/env bash
# bind-paths-check: S3A_BIND_PATHS (on/strict) and `s3armor rebind`, against real MinIO.
# 1. The actual attack docs/ARCHITECTURE.md "Path binding" describes: an attacker
#    with backend write access overwrites object b's ciphertext+metadata
#    with object a's (a plain
#    server-side copy, direct to the backend, bypassing the proxy). Under
#    S3A_BIND_PATHS=off this silently succeeds (GET b returns a's content).
#    Under =on/strict it is detected: a's wrapped DEK is bound to "a", not
#    "b", so unwrapping at b's path fails.
# 2. Compat: objects written under =off still read under =on (bound-then-
#    unbound retry) — enabling the feature never breaks an existing bucket.
# 3. CopyObject under =on is a legitimate rewrap, not an attack: the copy is
#    readable at its new key.
# 4. Multipart round-trip under =on.
# 5. `s3armor rebind --dry-run` then `rebind`, then =strict still green — the
#    retirement path once every object in a bucket is bound.
#
# Requires: docker, cargo, aws-cli v2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"
MINIO_CONTAINER="s3a-bind-paths-check-minio"
MINIO_PORT=19204
PROXY_PORT=18284
BUCKET="bind-paths-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws; do
  command -v "$tool" >/dev/null || { echo "bind-paths-check: missing required tool: $tool" >&2; exit 1; }
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

BACKEND_AWS=(env AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT")
"${BACKEND_AWS[@]}" s3 mb "s3://$BUCKET"

PROXY_AWS=(env AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$PROXY_PORT")

# A 32-byte all-zero key, base64'd — fine for a throwaway local check.
TEST_KEY_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

start_proxy() {
  local bind_paths="$1"
  S3A_LISTEN="127.0.0.1:$PROXY_PORT" \
  S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT" \
  S3A_BACKEND_ACCESS_KEY=minioadmin \
  S3A_BACKEND_SECRET_KEY=minioadmin \
  S3A_KEY_ACTIVE=BINDPATHSCHECK \
  S3A_KEY_BINDPATHSCHECK="$TEST_KEY_B64" \
  S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
  S3A_CLIENT_CHECK_SECRET_KEY=checksecret1234567890 \
  S3A_BIND_PATHS="$bind_paths" \
    "$S3ARMOR" serve >"$WORKDIR/s3a-$bind_paths.log" 2>&1 &
  S3A_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null || {
    echo "bind-paths-check: proxy (S3A_BIND_PATHS=$bind_paths) never became healthy"
    cat "$WORKDIR/s3a-$bind_paths.log"; exit 1
  }
}

stop_proxy() {
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null || true
  wait "$S3A_PID" 2>/dev/null || true
  S3A_PID=""
}

echo "== off: the object-swap attack succeeds silently (today's default, documented risk) =="
start_proxy off
echo "content A" > "$WORKDIR/a.txt"
echo "content B" > "$WORKDIR/b.txt"
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/a.txt" "s3://$BUCKET/off-a.txt"
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/b.txt" "s3://$BUCKET/off-b.txt"
# The attacker: a plain server-side copy direct to the backend, bypassing
# the proxy entirely — overwrites b's ciphertext *and* metadata with a's.
"${BACKEND_AWS[@]}" s3 cp "s3://$BUCKET/off-a.txt" "s3://$BUCKET/off-b.txt"
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/off-b.txt" "$WORKDIR/off-b-after.txt"
diff "$WORKDIR/a.txt" "$WORKDIR/off-b-after.txt" >/dev/null || {
  echo "bind-paths-check: expected the off-mode swap to silently succeed (this is the documented risk, not the fix)"; exit 1;
}
echo "confirmed: under off, GET off-b now silently returns object a's content"
stop_proxy

echo "== on: the same swap is detected (GET fails instead of returning the wrong object) =="
start_proxy on
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/a.txt" "s3://$BUCKET/on-a.txt"
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/b.txt" "s3://$BUCKET/on-b.txt"
"${BACKEND_AWS[@]}" s3 cp "s3://$BUCKET/on-a.txt" "s3://$BUCKET/on-b.txt"
if "${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/on-b.txt" "$WORKDIR/on-b-after.txt" 2>"$WORKDIR/on-b-swap.err"; then
  echo "bind-paths-check: expected the on-mode swap to be detected (GET should fail), but it succeeded"
  cat "$WORKDIR/on-b-swap.err"; exit 1
fi
echo "confirmed: under on, the swapped object's GET fails (wrong binding rejected)"

echo "== on: compat — objects written before S3A_BIND_PATHS existed still read =="
# off-a.txt/off-b.txt (before the swap corrupted off-b) were both written
# under off — off-a.txt was never touched by the swap, so it is exactly
# that "pre-existing bucket" case.
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/off-a.txt" "$WORKDIR/off-a-under-on.txt"
diff "$WORKDIR/a.txt" "$WORKDIR/off-a-under-on.txt" >/dev/null || {
  echo "bind-paths-check: an object written under off should still read under on"; exit 1;
}

echo "== on: CopyObject is a legitimate rewrap, readable at its new key =="
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/on-a.txt" "s3://$BUCKET/on-a-copy.txt"
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/on-a-copy.txt" "$WORKDIR/on-a-copy-down.txt"
diff "$WORKDIR/a.txt" "$WORKDIR/on-a-copy-down.txt" >/dev/null || {
  echo "bind-paths-check: CopyObject under on should produce a readable copy at the new key"; exit 1;
}

echo "== on: multipart round-trip =="
head -c $((6 * 1024 * 1024)) /dev/urandom > "$WORKDIR/big.bin"
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/big.bin" "s3://$BUCKET/on-big.bin"
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/on-big.bin" "$WORKDIR/big-down.bin"
diff "$WORKDIR/big.bin" "$WORKDIR/big-down.bin" >/dev/null || {
  echo "bind-paths-check: multipart round-trip under on did not match"; exit 1;
}
stop_proxy

echo "== s3armor rebind --dry-run reports without modifying, then a real rebind, then strict is still green =="
REBIND_ENV=(
  S3A_BACKEND_ENDPOINT="http://127.0.0.1:$MINIO_PORT"
  S3A_BACKEND_ACCESS_KEY=minioadmin
  S3A_BACKEND_SECRET_KEY=minioadmin
  S3A_KEY_ACTIVE=BINDPATHSCHECK
  S3A_KEY_BINDPATHSCHECK="$TEST_KEY_B64"
  S3A_BIND_PATHS=on
)
DRY_OUT="$(env "${REBIND_ENV[@]}" "$S3ARMOR" rebind --bucket "$BUCKET" --prefix "off-a" --dry-run)"
echo "$DRY_OUT"
echo "$DRY_OUT" | grep -q "would rebind 1" || {
  echo "bind-paths-check: expected rebind --dry-run to report exactly 1 object under prefix off-a"; exit 1;
}
env "${REBIND_ENV[@]}" "$S3ARMOR" rebind --bucket "$BUCKET" --prefix "off-a"

start_proxy strict
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/off-a.txt" "$WORKDIR/off-a-under-strict.txt"
diff "$WORKDIR/a.txt" "$WORKDIR/off-a-under-strict.txt" >/dev/null || {
  echo "bind-paths-check: off-a.txt should read under strict after rebind"; exit 1;
}
# on-a.txt/on-a-copy.txt/on-big.bin were already written bound under on, so
# strict (bound-only, no empty-binding fallback) should already read them
# without needing rebind.
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/on-a.txt" "$WORKDIR/on-a-under-strict.txt"
diff "$WORKDIR/a.txt" "$WORKDIR/on-a-under-strict.txt" >/dev/null || {
  echo "bind-paths-check: an object already bound under on should read under strict with no rebind needed"; exit 1;
}
stop_proxy

echo "== bind-paths-check: PASS =="
