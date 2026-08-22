#!/usr/bin/env bash
# e2e-rgw-check: `s3armor check --bucket` full green against a real Ceph RGW
# (what Hetzner Object Storage actually runs), plus a proxy round-trip,
# a multipart upload, and a ranged GET — coverage the MinIO-based checks
# defer: "s3armor check already probes a live backend for every format
# requirement (docs/ARCHITECTURE.md "Backend conformance check (`s3armor
# check`)") at a fraction of the CI cost a testcontainers-based RGW suite
# would add". This script is that probe, run locally and on demand, not
# wired into CI (same posture as scripts/e2e-check.sh).
#
# Local opt-in, not testcontainers: the two integration suites
# (tests/integration_{minio,mpu}.rs) hardcode MinIO's image, port,
# credentials, and a MinIO-specific readiness predicate in two duplicated
# launch blocks with no env escape hatch (deliberate — docs/ARCHITECTURE.md
# "Integration tests"'s fail-never-skip policy). Parameterizing them for RGW
# would touch both, invent a backend abstraction for one caller, and put a
# slow, heavy container in the default `cargo test` path CI runs on every
# push.
#
# RGW boot is much slower than MinIO's (Ceph brings up a monitor, OSD, MDS,
# and RGW daemon from cold) — expect 60-120s, ~1.3GB image, ~2GB RAM.
#
# Requires: docker, cargo, aws-cli v2.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RGW_CONTAINER="s3a-e2e-rgw-check-rgw"
RGW_PORT=19106
PROXY_PORT=18185
BUCKET="e2e-rgw-check"
S3A_PID=""

cleanup() {
  set +e
  [ -n "$S3A_PID" ] && kill "$S3A_PID" 2>/dev/null
  docker rm -f "$RGW_CONTAINER" >/dev/null 2>&1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in docker cargo aws; do
  command -v "$tool" >/dev/null || { echo "e2e-rgw-check: missing required tool: $tool" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
echo "== building s3armor =="
cargo build -p s3armor --quiet

echo "== starting Ceph RGW demo on :$RGW_PORT (this takes a while — cold Ceph boot) =="
docker rm -f "$RGW_CONTAINER" >/dev/null 2>&1 || true
# Ceph's own monitor refuses to start below ~5% free disk on the host
# filesystem backing the container (a real Ceph safety floor, not a bug in
# this script) — if this container never reaches "ready", check `docker
# logs` for that message before assuming anything else is wrong.
docker run -d --name "$RGW_CONTAINER" -p "$RGW_PORT:8080" \
  -e MON_IP=127.0.0.1 \
  -e CEPH_PUBLIC_NETWORK=0.0.0.0/0 \
  -e RGW_NAME=localhost \
  -e RGW_FRONTEND_PORT=8080 \
  -e CEPH_DEMO_UID=cephdemo \
  -e CEPH_DEMO_ACCESS_KEY=cephdemo \
  -e CEPH_DEMO_SECRET_KEY=cephdemosecret1234567890 \
  -e CEPH_DEMO_BUCKET="$BUCKET" \
  -e DEMO_DAEMONS="osd mds rgw" \
  quay.io/ceph/demo:latest-reef >/dev/null
RGW_READY=""
for _ in $(seq 1 120); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RGW_PORT/" 2>/dev/null || true)"
  [ "$code" = "200" ] && { RGW_READY=1; break; }
  sleep 1
done
[ -n "$RGW_READY" ] || {
  echo "e2e-rgw-check: RGW never answered 200 on / within 120s"
  docker logs "$RGW_CONTAINER" 2>&1 | tail -40
  exit 1
}
# A 200 on / can precede the demo user/bucket actually existing — confirm
# the bucket the demo entrypoint should have created is really there.
for _ in $(seq 1 30); do
  AWS_ACCESS_KEY_ID=cephdemo AWS_SECRET_ACCESS_KEY=cephdemosecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
    aws --endpoint-url "http://127.0.0.1:$RGW_PORT" s3 ls "s3://$BUCKET" >/dev/null 2>&1 && break
  sleep 1
done
AWS_ACCESS_KEY_ID=cephdemo AWS_SECRET_ACCESS_KEY=cephdemosecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$RGW_PORT" s3 ls "s3://$BUCKET" >/dev/null || {
  echo "e2e-rgw-check: demo bucket $BUCKET never became listable"; exit 1;
}

BACKEND_ENV=(
  S3A_BACKEND_ENDPOINT="http://127.0.0.1:$RGW_PORT"
  S3A_BACKEND_ACCESS_KEY=cephdemo
  S3A_BACKEND_SECRET_KEY=cephdemosecret1234567890
  S3A_KEY_ACTIVE=E2ERGWCHECK
  S3A_KEY_E2ERGWCHECK="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

echo "== s3armor check --bucket $BUCKET against real Ceph RGW =="
# This is coverage the MinIO-based checks defer, run for the first time
# here: metadata survival, the 2KB user-metadata headroom, ranged GET,
# CopyObject metadata preservation, checksum-header handling, and the
# small-final-part multipart probe — all of docs/ARCHITECTURE.md "Hetzner (Ceph RGW) specifics"'s
# "Hetzner specifics", "all probed by s3armor check, not assumed", against the
# backend Hetzner actually runs, not just MinIO.
CHECK_OUT="$(env "${BACKEND_ENV[@]}" "$ROOT/target/debug/s3armor" check --bucket "$BUCKET")"
echo "$CHECK_OUT"
echo "$CHECK_OUT" | grep -q "verdict: incompatible" && {
  echo "e2e-rgw-check: s3armor check reported 'incompatible' against real Ceph RGW"; exit 1;
}
true

echo "== starting s3armor serve on :$PROXY_PORT =="
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
  echo "e2e-rgw-check: proxy never became healthy"; cat "$WORKDIR/s3armor.log"; exit 1;
}

PROXY_AWS=(env AWS_ACCESS_KEY_ID=checkkey AWS_SECRET_ACCESS_KEY=checksecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$PROXY_PORT")
BACKEND_AWS=(env AWS_ACCESS_KEY_ID=cephdemo AWS_SECRET_ACCESS_KEY=cephdemosecret1234567890 AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$RGW_PORT")

echo "== proxy PUT/GET round-trip against real RGW =="
head -c 4096 /dev/urandom > "$WORKDIR/small.bin"
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/small.bin" "s3://$BUCKET/round-trip.bin"
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/round-trip.bin" "$WORKDIR/small-after.bin"
diff "$WORKDIR/small.bin" "$WORKDIR/small-after.bin" >/dev/null || {
  echo "e2e-rgw-check: PUT/GET round-trip through the proxy was not byte-exact"; exit 1;
}

echo "== ciphertext at rest, direct to RGW =="
"${BACKEND_AWS[@]}" s3api head-object --bucket "$BUCKET" --key round-trip.bin | grep -qi 's3a-' || {
  echo "e2e-rgw-check: expected s3a-* v1 metadata on the object stored at RGW"; exit 1;
}
"${BACKEND_AWS[@]}" s3 cp "s3://$BUCKET/round-trip.bin" "$WORKDIR/raw.bin"
cmp -s "$WORKDIR/small.bin" "$WORKDIR/raw.bin" && {
  echo "e2e-rgw-check: object at rest on RGW matches plaintext exactly — not encrypted"; exit 1;
}
true

echo "== multipart round-trip (6 MiB, forces the small-final-part footer path) against RGW =="
head -c 6291456 /dev/urandom > "$WORKDIR/mpu.bin"
"${PROXY_AWS[@]}" s3 cp "$WORKDIR/mpu.bin" "s3://$BUCKET/mpu.bin" \
  --expected-size 6291456
"${PROXY_AWS[@]}" s3 cp "s3://$BUCKET/mpu.bin" "$WORKDIR/mpu-after.bin"
diff "$WORKDIR/mpu.bin" "$WORKDIR/mpu-after.bin" >/dev/null || {
  echo "e2e-rgw-check: multipart round-trip through the proxy was not byte-exact"; exit 1;
}

echo "== ranged GET through the proxy against RGW =="
"${PROXY_AWS[@]}" s3api get-object --bucket "$BUCKET" --key mpu.bin --range bytes=1000-1999 \
  "$WORKDIR/range.bin" >/dev/null
cmp -s <(dd if="$WORKDIR/mpu.bin" bs=1 skip=1000 count=1000 2>/dev/null) "$WORKDIR/range.bin" || {
  echo "e2e-rgw-check: ranged GET through the proxy did not match the plaintext slice"; exit 1;
}

kill "$S3A_PID" 2>/dev/null || true
S3A_PID=""

echo "== e2e-rgw-check: PASS =="
