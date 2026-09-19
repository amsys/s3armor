# scripts-docker-target: evaluation

## Steps: predicted and actual

| Step | Predicted | Actual |
|---|---|---|
| s1 common.sh and 11 scripts | cheap x module, raised to mid | PASS, first round |
| s2 developer guide note | cheap x local, cheap | PASS, first round |

Escalations: 0 of 2.

## What went wrong

- The manifest asked for a shebang in `scripts/common.sh`. The file is
  sourced and not executable, so the pre-commit hook
  `check-shebang-scripts-are-executable` would reject it. The done check of
  s1 did not run the hygiene hooks, so C1 passed. Fixed by hand after the
  run: `# shellcheck shell=bash` replaces the shebang.
- Lesson for a later manifest: when a step adds a file, put
  `pre-commit run --files <new file>` in its done check.

## Why this work exists

The live scripts could not run on a machine with Docker behind sudo and a
cargo target directory outside `./target`. A run of the whole script under
sudo would run cargo as root. A `docker` wrapper first on `PATH` was tried
first and the permission classifier refused it. The repo change is the
lasting fix.

## Live evidence (run by the user)

`DOCKER="sudo docker" scripts/multipart-check.sh` and
`DOCKER="sudo docker" scripts/tooling-check.sh`: both PASS, with the binary
found in `/tmp/cargo-target` and no `./target` directory.
