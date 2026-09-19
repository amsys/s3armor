# mpu-gc: evaluation

## Steps: predicted and actual

| Step | Predicted | Actual |
|---|---|---|
| s0 design record | cheap x local, raised to strong | PASS, first round |
| s1 RAM fix | cheap x system, mid, strong judge | PASS, first round. The judge gave no finding. |
| s2 lifecycle probe | cheap x local, raised to mid | PASS, first round |
| s3 operator docs | cheap x local, cheap | PASS, first round |

Escalations: 0 of 2. No rework after "done".

## What the record cannot show

- The design changed before the manifest. The first draft had a second
  clock for finished sessions (`COMPLETED_RETENTION`). The adversarial
  design check replaced it with eviction at the cap. That check also found
  the `record_part` race.
- The design check made one wrong claim: that each cap trip makes an
  orphan on the backend. `handle_create` has a pre-check before the backend
  call. The same read showed that the pre-check must call `make_room`, or
  the eviction can never run. Read the code after a design check, too.
- The plan named the test binary as `./target/debug/deps/...`. Cargo builds
  into `/tmp/cargo-target` on this machine.
- `upload_part_after_complete_is_no_such_upload` is a contract pin. It
  passes before and after the change.

## Live evidence (run by the user, Docker through sudo)

- `integration_mpu`: 20 passed, 0 failed.
- `scripts/multipart-check.sh`: PASS. The sweeper aborted an abandoned
  upload on the backend.
- `scripts/tooling-check.sh`: PASS. The new probe shows a check mark on
  MinIO, so the test image sends `Server: MinIO`. Unknown u1 is closed.
