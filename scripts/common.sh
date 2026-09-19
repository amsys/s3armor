# shellcheck shell=bash
# scripts/common.sh: setup shared by every scripts/*-check.sh script.
# The caller sources this file after it sets ROOT. This file has no shebang
# and is not executable, because no one runs it directly.
: "${ROOT:?scripts/common.sh: set ROOT before you source this file}"

# Some machines put Docker behind sudo. Run a script with
# DOCKER="sudo docker" scripts/<name>.sh to use it there.
read -r -a DOCKER_CMD <<<"${DOCKER:-docker}"
[ "${#DOCKER_CMD[@]}" -gt 0 ] || {
  echo "DOCKER is set but empty" >&2
  exit 1
}
command -v "${DOCKER_CMD[0]}" >/dev/null || {
  echo "missing required tool: ${DOCKER_CMD[0]}" >&2
  exit 1
}
docker() { command "${DOCKER_CMD[@]}" "$@"; }

# Cargo can build outside ./target, through CARGO_TARGET_DIR or through
# build.target-dir in a cargo config file.
TARGET_DIR="$(cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
[ -n "$TARGET_DIR" ] || {
  echo "cannot find the cargo target directory" >&2
  exit 1
}

# The caller reads S3ARMOR; this file does not use it itself.
export S3ARMOR="$TARGET_DIR/debug/s3armor"
