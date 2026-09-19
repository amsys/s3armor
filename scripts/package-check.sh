#!/usr/bin/env bash
# package-check: build and test the .deb (systemd, Debian) and .apk (OpenRC, Alpine)
# packages for the host architecture. Verify that each package installs, the service
# files exist at their documented paths, and s3armor --version reports the correct
# version.
#
# Requires: docker, cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/common.sh
. "$ROOT/scripts/common.sh"

# Map host architecture to package architecture.
UNAME_M="$(uname -m)"
case "$UNAME_M" in
  x86_64)
    ARCH=amd64
    ;;
  aarch64)
    ARCH=arm64
    ;;
  *)
    echo "package-check: unsupported architecture: $UNAME_M" >&2
    exit 1
    ;;
esac

# nfpm version pinned for reproducibility.
NFPM_VERSION="v2.35.0"

# Read the s3armor version from Cargo.toml via cargo metadata.
# Use sed to parse JSON; no external JSON parsing tool dependency.
VERSION="$(cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" \
  | sed -n 's/.*"packages":\[\s*{\s*"name":"s3armor".*"version":"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$VERSION" ] || {
  echo "package-check: cannot read s3armor version from Cargo.toml" >&2
  exit 1
}

DIST_DIR="$ROOT/dist"
BINARY="$DIST_DIR/s3armor"

cleanup() {
  set +e
  # Leave dist/ in place for release.yml to upload, unless KEEP_DIST=1 was set.
  # The presence of dist/ tells the user what was built.
  if [ -z "${KEEP_DIST:-}" ]; then
    : # Leave dist/ as-is; release.yml uploads it.
  fi
}
trap cleanup EXIT

for tool in docker cargo; do
  command -v "$tool" >/dev/null || { echo "package-check: missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$DIST_DIR"

echo "== building static binary for $ARCH with docker buildx =="
docker buildx build --target binary --output "type=local,dest=$DIST_DIR" "$ROOT"
[ -f "$BINARY" ] || {
  echo "package-check: docker buildx did not produce $BINARY" >&2
  exit 1
}

echo "== building .deb and .apk packages with nfpm =="
docker run --rm -v "$ROOT:/src" -w /src \
  -e "VERSION=$VERSION" \
  -e "ARCH=$ARCH" \
  -e "BINARY=$BINARY" \
  "goreleaser/nfpm:${NFPM_VERSION}" package -f packaging/nfpm.yaml -p deb -t dist/

docker run --rm -v "$ROOT:/src" -w /src \
  -e "VERSION=$VERSION" \
  -e "ARCH=$ARCH" \
  -e "BINARY=$BINARY" \
  "goreleaser/nfpm:${NFPM_VERSION}" package -f packaging/nfpm.yaml -p apk -t dist/

# Find the built packages.
DEB="$(find "$DIST_DIR" -maxdepth 1 -name 's3armor_*.deb' -print -quit)"
APK="$(find "$DIST_DIR" -maxdepth 1 -name 's3armor_*.apk' -print -quit)"
[ -f "$DEB" ] || {
  echo "package-check: .deb not found in $DIST_DIR" >&2
  exit 1
}
[ -f "$APK" ] || {
  echo "package-check: .apk not found in $DIST_DIR" >&2
  exit 1
}

echo "== testing .deb install on debian:12 =="
docker run --rm -v "$DIST_DIR:/dist:ro" debian:12 bash -c "
  dpkg -i /dist/$(basename "$DEB")
  s3armor --version | grep -q '$VERSION' || { echo 'Version mismatch on debian:12'; exit 1; }
  test -f /usr/lib/systemd/system/s3armor.service || { echo 'Service file missing on debian:12'; exit 1; }
  test -f /etc/s3armor/env || { echo 'Config file missing on debian:12'; exit 1; }
  echo 'debian:12 PASS'
"

echo "== testing .deb install on debian:13 =="
docker run --rm -v "$DIST_DIR:/dist:ro" debian:13 bash -c "
  dpkg -i /dist/$(basename "$DEB")
  s3armor --version | grep -q '$VERSION' || { echo 'Version mismatch on debian:13'; exit 1; }
  test -f /usr/lib/systemd/system/s3armor.service || { echo 'Service file missing on debian:13'; exit 1; }
  test -f /etc/s3armor/env || { echo 'Config file missing on debian:13'; exit 1; }
  echo 'debian:13 PASS'
"

echo "== testing .apk install on alpine:3 =="
docker run --rm -v "$DIST_DIR:/dist:ro" alpine:3 ash -c "
  apk add --allow-untrusted /dist/$(basename "$APK")
  s3armor --version | grep -q '$VERSION' || { echo 'Version mismatch on alpine:3'; exit 1; }
  test -f /etc/init.d/s3armor || { echo 'Init script missing on alpine:3'; exit 1; }
  test -f /etc/s3armor/env || { echo 'Config file missing on alpine:3'; exit 1; }
  id s3armor >/dev/null 2>&1 || { echo 'User s3armor missing on alpine:3'; exit 1; }
  echo 'alpine:3 PASS'
"

echo "== package-check: PASS =="
