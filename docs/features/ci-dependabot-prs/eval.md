# eval — ci-dependabot-prs (workflow-design run, 2026-09-18)

## Steps: predicted vs actual

| Step | Predicted rev × blast | Actual | Tier | Escalated | Rework after "done" |
|---|---|---|---|---|---|
| sonar-skip | cheap × system | cheap × system (3-line YAML) | mid | no | no; strong judge passed |
| dependabot-hold | cheap × system | cheap × system (14-line YAML) | mid | no | no; strong judge passed |
| push | irreversible × external | as predicted | strong | no | driver FAIL: nothing to push (see below); run by hand |
| close-prs | irreversible × external | none needed | strong | no | BLOCKED; Dependabot closed #2-#5 itself after the push |

## What went wrong

- The wave-1 committer (sonnet) staged ci.yml and returned "I'll wait for this
  monitor notification" without committing. The driver reads only lines with
  FAIL, so it logged wave1 PASS. The push judge caught it: HEAD equaled
  origin/main because nothing was committed. Driver gap: reconcile commits by
  checking `git log` for each row, not by parsing the committer's prose.
- An agent in the run wrote an out-of-scope manifest,
  docs/features/ci-comprehensive-fix/. It was deleted by hand.
- The strong tier for push and close-prs cost about 6 opus agents for two
  shell commands. The table routes irreversible × external to strong; the risk
  is in the decision (made at the gate), not in the typing.
- The close-prs step was not necessary. Dependabot closes a PR by itself when
  an ignore rule in dependabot.yml covers it.

## Cost

- 10 agents, 410k subagent tokens, 8.3 min. Push and PR close were done inline
  after the driver stopped.
