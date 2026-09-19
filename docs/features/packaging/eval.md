# packaging — run wf_64a4e363-277 (2026-09-19)

- s1–s5 PASS on the predicted tier. s6 FAIL after fix rounds and one escalation.
- Cause of the s6 FAIL: a manifest defect, not an s6 defect. The s2 action asked for an apk
  preinstall script, but s2 `files` did not list it. The executor kept to its file list and
  wrote a warning comment. The s6 judge found that the docs said a user exists that no package
  file creates. The main session fixed it (packaging/s3armor-preinstall.sh, nfpm overrides).
- The s6 judge did not see a second defect: on Alpine, docs set master.key to root 0600, and
  the service user cannot read that. The main session fixed it (root:s3armor 0640).
- Lesson: every file that a step's action names must be in `files`. The row fence is strict.
- The FAIL note stopped at 1500 characters before the finding. The main session read the
  journal to get the finding. This is a driver defect: put the finding before the evidence.
- Runtime checks (container-check.sh, package-check.sh) not run: Docker needs sudo.
