# eval — sonar-dependabot (workflow-design run, 2026-09-15)

## Steps: predicted vs actual

| Step | Predicted rev × blast | Actual | Tier | Escalated | Rework after "done" |
|---|---|---|---|---|---|
| dependabot | cheap × system | cheap × system (8-line YAML) | mid | no | no |
| refactor-list | cheap × local | cheap × local | cheap | run 1: yes, to mid; no change in outcome | comment dropped in run 1, restored in run 2 |
| refactor-main | cheap × local | cheap × local | cheap | no | no |
| refactor-mpu | cheap × system | cheap × system (511-line diff) | mid | no | judge VERIFIED |
| refactor-body | cheap × system | cheap × system (365-line diff) | mid | no | judge CAVEATS, no defect |

## What went wrong

- Run 1 failed on the done check, not on the code. `cargo test -p s3armor` runs the
  Docker MinIO suites. Docker is not reachable for this user. A clean HEAD fails the same way.
- The escalation to mid did not help. A stronger model cannot fix the environment.
  One escalation and 3 fix rounds were spent.
- Lesson: before a done check goes into a manifest, run it once on HEAD.
  A check that fails on the base is a broken check.
- run.js commits once per wave. That conflicts with RULES.md #6. The user gave
  explicit consent at the gate.
- run.js commit subjects use the row id, which is not a conventional commit.
  This run passed commit_prefix and commit_subject through an inline change.

## Cost

- Run 1: 10 agents, 488k subagent tokens, 15 min.
- Run 2: 14 agents, 855k subagent tokens, 24 min.
