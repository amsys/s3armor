#!/usr/bin/env bash
# container-check: acceptance test for the distroless release image built by
# the Containerfile's `release` stage (the default target of `docker build`).
# Proves the hardened run posture and the image's behavior, not the Rust
# code — the other scripts/*-check.sh scripts cover that with a built
# `s3armor` binary run directly on the host.
#
# 1. Builds s3armor:check from the Containerfile (default target).
# 2. Starts MinIO and the image on one docker network.
# 3. Runs the proxy container read-only, with every capability dropped and
#    no-new-privileges, and no --user flag (the image sets user 65532).
# 4. Asserts: the image's declared user; the HEALTHCHECK reaches `healthy`;
#    an aws-cli PUT/GET round-trip through the proxy is byte-exact; the
#    object at the MinIO backend is not the plaintext; a one-off `check`
#    subcommand run of the same image exits 0; SIGTERM stops the container
#    with exit code 0 inside 10 s; the image has no shell. Prints the image
#    size.
#
# Requires: docker, aws-cli v2, curl. Does not need cargo or a built
# `s3armor` binary — the image is the thing under test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"

IMAGE="s3armor:check"
NETWORK="s3a-container-check-net"
MINIO_CONTAINER="s3a-container-check-minio"
PROXY_CONTAINER="s3a-container-check-proxy"
MINIO_PORT=19207
PROXY_PORT=18288
BUCKET="container-check"

cleanup() {
  set +e
  docker stop -t 1 "$PROXY_CONTAINER" >/dev/null 2>&1
  docker rm -f "$PROXY_CONTAINER" >/dev/null 2>&1
  docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1
  docker network rm "$NETWORK" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker aws curl; do
  command -v "$tool" >/dev/null || { echo "container-check: missing required tool: $tool" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
mkdir -p "$WORKDIR/secrets"

echo "== building $IMAGE from the Containerfile default target =="
docker build -f "$ROOT/Containerfile" -t "$IMAGE" "$ROOT"

echo "== starting MinIO on :$MINIO_PORT =="
docker rm -f "$MINIO_CONTAINER" >/dev/null 2>&1 || true
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker network create "$NETWORK" >/dev/null
docker run -d --name "$MINIO_CONTAINER" --network "$NETWORK" -p "$MINIO_PORT:9000" \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data >/dev/null
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$MINIO_PORT/minio/health/live" >/dev/null 2>&1 && break
  sleep 1
done

echo "== creating bucket direct against MinIO =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3 mb "s3://$BUCKET"

echo "== writing secret files (mounted read-only, world-readable for uid 65532) =="
printf 'minioadmin' >"$WORKDIR/secrets/backend_secret"
printf 'checksecret1234567890' >"$WORKDIR/secrets/client_secret"
# A 32-byte all-zero key, base64'd — fine for a throwaway local check.
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' >"$WORKDIR/secrets/master_key"
chmod 0644 "$WORKDIR"/secrets/*

# Shared by the proxy container and the one-off `check` run below, so the
# two configurations cannot drift apart.
BACKEND_ENV=(
  -e "S3A_BACKEND_ENDPOINT=http://$MINIO_CONTAINER:9000"
  -e S3A_BACKEND_ACCESS_KEY=minioadmin
  -e S3A_BACKEND_SECRET_KEY_FILE=/run/secrets/backend_secret
  -e S3A_KEY_ACTIVE=CONTAINERCHECK
  -e S3A_KEY_CONTAINERCHECK_FILE=/run/secrets/master_key
)

echo "== starting $IMAGE read-only, all capabilities dropped, no-new-privileges =="
docker run -d --name "$PROXY_CONTAINER" --network "$NETWORK" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p "$PROXY_PORT:8080" \
  -v "$WORKDIR/secrets:/run/secrets:ro" \
  -e S3A_LISTEN=0.0.0.0:8080 \
  "${BACKEND_ENV[@]}" \
  -e S3A_CLIENT_CHECK_ACCESS_KEY=checkkey \
  -e S3A_CLIENT_CHECK_SECRET_KEY_FILE=/run/secrets/client_secret \
  "$IMAGE" >/dev/null

echo "== (a) the image runs as uid 65532:65532, with no --user flag =="
RUN_USER="$(docker inspect -f '{{.Config.User}}' "$PROXY_CONTAINER")"
[ "$RUN_USER" = "65532:65532" ] || {
  echo "container-check: expected Config.User 65532:65532, got '$RUN_USER'" >&2
  exit 1
}

echo "== (b) HEALTHCHECK reaches healthy within 60 s =="
HEALTHY=0
for _ in $(seq 1 60); do
  STATUS="$(docker inspect -f '{{.State.Health.Status}}' "$PROXY_CONTAINER" 2>/dev/null || echo "")"
  [ "$STATUS" = "healthy" ] && { HEALTHY=1; break; }
  sleep 1
done
[ "$HEALTHY" = "1" ] || {
  echo "container-check: HEALTHCHECK never reached healthy (last status: '$STATUS')" >&2
  docker logs "$PROXY_CONTAINER" >&2 || true
  exit 1
}

export AWS_ACCESS_KEY_ID=checkkey
export AWS_SECRET_ACCESS_KEY=checksecret1234567890
export AWS_DEFAULT_REGION=us-east-1
AWS="aws --endpoint-url http://127.0.0.1:$PROXY_PORT"

echo "== (c) aws-cli PUT then GET of a random 1 MiB file, through the proxy =="
head -c 1048576 /dev/urandom >"$WORKDIR/plain.bin"
$AWS s3 cp "$WORKDIR/plain.bin" "s3://$BUCKET/probe.bin" >/dev/null
$AWS s3 cp "s3://$BUCKET/probe.bin" "$WORKDIR/round-trip.bin" >/dev/null
cmp -s "$WORKDIR/plain.bin" "$WORKDIR/round-trip.bin" || {
  echo "container-check: round-trip content mismatch" >&2
  exit 1
}

echo "== (d) the object at the MinIO backend is not the plaintext =="
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" s3 cp "s3://$BUCKET/probe.bin" "$WORKDIR/direct.bin" >/dev/null
cmp -s "$WORKDIR/plain.bin" "$WORKDIR/direct.bin" && {
  echo "container-check: the backend object equals the plaintext — encryption did not happen" >&2
  exit 1
}
# Compare as hex text, since the plaintext's first 64 bytes may contain
# bytes that upset a line-oriented tool such as grep on a binary pattern.
PLAIN_HEAD_HEX="$(od -An -tx1 -N64 "$WORKDIR/plain.bin" | tr -d ' \n')"
CIPHER_HEX="$(od -An -tx1 "$WORKDIR/direct.bin" | tr -d ' \n')"
case "$CIPHER_HEX" in
*"$PLAIN_HEAD_HEX"*)
  echo "container-check: the backend object contains the plaintext's first 64 bytes" >&2
  exit 1
  ;;
esac

echo "== (e) a one-off 'check' subcommand run of the same image exits 0 =="
docker run --rm --network "$NETWORK" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$WORKDIR/secrets:/run/secrets:ro" \
  "${BACKEND_ENV[@]}" \
  "$IMAGE" check --bucket "$BUCKET" || {
  echo "container-check: 'check --bucket $BUCKET' did not exit 0" >&2
  exit 1
}

echo "== (f) SIGTERM (docker stop -t 10) stops the container within 10 s, exit code 0 =="
STOP_START="$(date +%s)"
docker stop -t 10 "$PROXY_CONTAINER" >/dev/null
STOP_ELAPSED=$(($(date +%s) - STOP_START))
[ "$STOP_ELAPSED" -le 10 ] || {
  echo "container-check: docker stop took ${STOP_ELAPSED}s, expected 10s or less" >&2
  exit 1
}
STOP_EXIT_CODE="$(docker inspect -f '{{.State.ExitCode}}' "$PROXY_CONTAINER")"
[ "$STOP_EXIT_CODE" = "0" ] || {
  echo "container-check: expected ExitCode 0 after SIGTERM, got $STOP_EXIT_CODE" >&2
  exit 1
}

echo "== (g) the image has no shell =="
docker run --rm --entrypoint /bin/sh "$IMAGE" -c true >/dev/null 2>&1 && {
  echo "container-check: /bin/sh -c true succeeded — the image has a shell" >&2
  exit 1
}

echo "== (h) image size =="
IMAGE_SIZE_BYTES="$(docker image inspect -f '{{.Size}}' "$IMAGE")"
echo "$IMAGE image size: $((IMAGE_SIZE_BYTES / 1024 / 1024)) MiB ($IMAGE_SIZE_BYTES bytes)"

echo "== container-check: PASS =="
