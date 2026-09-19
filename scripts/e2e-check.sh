#!/usr/bin/env bash
# e2e-check: docker-compose.e2e.yml end to end — "the acceptance test for
# the actual product promise" (docs/ARCHITECTURE.md "End-to-end smoke test"). Drives
# Nextcloud primary storage through the proxy (upload, download, rename,
# delete) and confirms the object stored at the backend is genuinely
# ciphertext, not just that the client-visible behavior looks right.
#
# Departure from every other scripts/*-check.sh: those use raw `docker
# run` and the s3armor binary from the cargo target directory. This one drives `docker
# compose`, because the thing under test is a multi-service product
# topology — Nextcloud and s3armor wired together the way an operator wires
# them — and that wiring *is* docker-compose.e2e.yml, itself a deliverable
# docs/ARCHITECTURE.md "Repository layout"'s repo layout names. Reproducing four services'
# networking and startup ordering with raw `docker run` would mean
# hand-rolling what compose's healthchecks and `depends_on` already do.
#
# Stalwart's mailbox round-trip is NOT asserted here — see
# docker-compose.e2e.yml's header comment for why:
# Stalwart v0.16 has no scriptable non-interactive bootstrap this script
# could drive. This script confirms the container starts and is reachable
# on the network, then says so plainly rather than faking a pass.
#
# Requires: docker (with compose v2), curl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"
COMPOSE=(docker compose -f "$ROOT/docker-compose.e2e.yml" -p s3a-e2e-check)
NC_PORT=18380
NC_ADMIN_PASS="e2e-admin-password"

cleanup() {
  set +e
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$WORKDIR" "$ROOT/secrets-e2e"
}
trap cleanup EXIT

for tool in docker curl; do
  command -v "$tool" >/dev/null || { echo "e2e-check: missing required tool: $tool" >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || {
  echo "e2e-check: docker compose (v2) is required" >&2; exit 1;
}

WORKDIR="$(mktemp -d)"

echo "== writing throwaway secrets for the e2e stack =="
# Compose `secrets: file:` paths resolve relative to the compose file, so
# these must live under $ROOT, not $WORKDIR.
mkdir -p "$ROOT/secrets-e2e"
printf 'minioadmin-e2e-secret' > "$ROOT/secrets-e2e/backend_secret"
printf 'e2e-nextcloud-secret' > "$ROOT/secrets-e2e/nc_secret"
printf 'e2e-stalwart-secret' > "$ROOT/secrets-e2e/sw_secret"
# A 32-byte all-zero key, base64'd — the same throwaway convention every
# other check script uses.
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' > "$ROOT/secrets-e2e/master_key"

echo "== building the s3armor image and bringing up the e2e stack =="
"${COMPOSE[@]}" build s3armor
"${COMPOSE[@]}" up -d minio
"${COMPOSE[@]}" up createbuckets
"${COMPOSE[@]}" up -d s3armor nextcloud stalwart

echo "== waiting for s3armor to become healthy =="
for _ in $(seq 1 60); do
  status="$("${COMPOSE[@]}" ps s3armor --format '{{.Health}}' 2>/dev/null || true)"
  [ "$status" = "healthy" ] && break
  sleep 2
done
[ "$status" = "healthy" ] || {
  echo "e2e-check: s3armor never became healthy"; "${COMPOSE[@]}" logs s3armor; exit 1;
}

echo "== waiting for Nextcloud to finish installing =="
NC_READY=""
for _ in $(seq 1 120); do
  out="$(curl -s "http://127.0.0.1:$NC_PORT/status.php" 2>/dev/null || true)"
  echo "$out" | grep -q '"installed":true' && { NC_READY=1; break; }
  sleep 2
done
[ -n "$NC_READY" ] || {
  echo "e2e-check: Nextcloud never reported installed:true"
  "${COMPOSE[@]}" logs nextcloud | tail -60
  exit 1
}

MARKER="s3a-e2e-check-marker-$$-$(date +%s)"
echo "$MARKER" > "$WORKDIR/upload.txt"

echo "== Nextcloud primary-storage smoke: upload =="
curl -sf -u "admin:$NC_ADMIN_PASS" -T "$WORKDIR/upload.txt" \
  -w "PUT: %{http_code}\n" -o /dev/null \
  "http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e.txt" || {
  echo "e2e-check: WebDAV upload failed"; exit 1;
}

echo "== download =="
curl -sf -u "admin:$NC_ADMIN_PASS" -o "$WORKDIR/download.txt" \
  -w "GET: %{http_code}\n" \
  "http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e.txt"
diff "$WORKDIR/upload.txt" "$WORKDIR/download.txt" >/dev/null || {
  echo "e2e-check: downloaded content did not match what was uploaded"; exit 1;
}

echo "== rename =="
# Objectstore primary storage keys objects by `urn:oid:<fileid>` — a
# rename is a database-only operation, no S3 request at all. This proves
# the object survives a rename and stays readable, not a CopyObject test.
curl -sf -u "admin:$NC_ADMIN_PASS" -X MOVE \
  -H "Destination: http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e-renamed.txt" \
  -w "MOVE: %{http_code}\n" -o /dev/null \
  "http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e.txt"
curl -sf -u "admin:$NC_ADMIN_PASS" -o "$WORKDIR/after-rename.txt" \
  -w "GET after rename: %{http_code}\n" \
  "http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e-renamed.txt"
diff "$WORKDIR/upload.txt" "$WORKDIR/after-rename.txt" >/dev/null || {
  echo "e2e-check: content changed across a rename"; exit 1;
}

echo "== delete =="
curl -sf -u "admin:$NC_ADMIN_PASS" -X DELETE \
  -w "DELETE: %{http_code}\n" -o /dev/null \
  "http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e-renamed.txt"
DELETED_CODE="$(curl -s -o /dev/null -w '%{http_code}' -u "admin:$NC_ADMIN_PASS" \
  "http://127.0.0.1:$NC_PORT/remote.php/dav/files/admin/e2e-renamed.txt")"
[ "$DELETED_CODE" = "404" ] || {
  echo "e2e-check: deleted file still reachable (got $DELETED_CODE)"; exit 1;
}

echo "== the actual product promise: ciphertext at rest, direct to MinIO =="
# Backend creds, kept separate from every client credential above — querying
# with the wrong key errors, and a swallowed error here would make this
# check pass for the wrong reason (an error, not "no plaintext found").
#
# `minio/minio`'s image ships only `mc` and a shell — no grep, awk, sed, or
# find (confirmed: `command -v grep` fails in it). So this splits the work:
# the container does the *text* matching that's safe as a shell variable
# (an `mc stat` header line is always plain ASCII) using `case`, not grep;
# any candidate ciphertext object is written to a bind-mounted file instead
# of captured into a shell variable (which mangles embedded null bytes);
# the marker search over those (binary) files runs on the host, where a
# real `grep -a` exists.
BACKEND_SECRET="$(cat "$ROOT/secrets-e2e/backend_secret")"
mkdir -p "$WORKDIR/candidates"
CIPHERTEXT_CHECK="$(docker run --rm --network "s3a-e2e-check_default" -v "$WORKDIR/candidates:/out" \
  --entrypoint sh quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z -c "
  set -e
  mc alias set m http://minio:9000 minioadmin '$BACKEND_SECRET' >/dev/null
  found=0
  n=0
  for obj in \$(mc find m/nextcloud --newer-than 5m); do
    meta=\"\$(mc stat \"\$obj\" 2>/dev/null)\"
    case \"\$meta\" in
      *S3a-V*)
        found=1
        n=\$((n + 1))
        mc cat \"\$obj\" 2>/dev/null > \"/out/candidate-\$n.bin\"
        ;;
    esac
  done
  [ \"\$found\" = 1 ] && echo 'CIPHERTEXT_CONFIRMED' || echo 'NO_V1_OBJECT_FOUND'
")"
case "$CIPHERTEXT_CHECK" in
  *NO_V1_OBJECT_FOUND*)
    echo "e2e-check: no s3a-v1 object found in the nextcloud bucket — objectstore is not routing through the proxy as v1"; exit 1;;
  *CIPHERTEXT_CONFIRMED*) ;;
  *) echo "e2e-check: ciphertext-at-rest check produced no verdict: $CIPHERTEXT_CHECK"; exit 1;;
esac
grep -qa "$MARKER" "$WORKDIR"/candidates/*.bin && {
  echo "e2e-check: found the uploaded marker in plaintext at rest — Nextcloud's object is NOT encrypted"; exit 1;
}
true
echo "confirmed: Nextcloud's objects carry s3a-v1 metadata and the uploaded marker never appears in plaintext at rest"

echo "== Stalwart: container reachable, mailbox round-trip NOT covered (see docker-compose.e2e.yml header) =="
STALWART_UP="$("${COMPOSE[@]}" ps stalwart --format '{{.State}}' 2>/dev/null || true)"
[ "$STALWART_UP" = "running" ] || {
  echo "e2e-check: stalwart container is not running"; "${COMPOSE[@]}" logs stalwart | tail -40; exit 1;
}
echo "stalwart container is up; its non-interactive bootstrap is a documented gap, not asserted by this script"

echo "== e2e-check: PASS (Nextcloud fully verified; Stalwart reachability only — see above) =="
