# Working rules for this repo

## When you change lab content, three things must move together

1. **`labs/weekNN-<slug>/`** — the student-facing worksheet / README / code.
2. **The curriculum monorepo** (`../KOSEN69 - curriculum/lessons/<slug>/`) holds a
   byte-identical copy. A parity gate enforces it:
   `cd "../KOSEN69 - curriculum" && .venv/bin/python -m pytest tests/ -q`
   Apply the *same* edit to both — don't `cp` the `.md` files, the monorepo copies
   carry template tokens (`{{ slot_label }}`, `{{ labpath }}`).
3. **`instructor/`** — the answer keys, quiz keys, exam keys and research
   instruments that grade that lab. **`instructor/` is git-ignored**, so nothing in
   CI or the diff will remind you. A worksheet fix that leaves its key stale means
   students get marked wrong for correct answers. Check the matching
   `instructor/quizzes/weekly/weekNN-answers.md`, `instructor/exams/*`, and
   `instructor/research/{planted-error-bank,pre-post-test}.md`.

## Never "fix" the deliberately vulnerable material

`labs/week*/`, `labs/toolbox/` and `project/starter-app/` are insecure on purpose —
old pins, root containers, planted secrets, SQL injection. They are the exercise.

- `.github/dependabot.yml` ignores those directories; do not merge a dependency
  bump there (it silently destroys the Week 12 SCA lesson and the term project).
- `security-ci` deliberately does not gate on them (`.semgrepignore`, Trivy
  `skip-dirs`, `.gitleaks.toml` allowlist). It *does* gate `labs/live-quiz`,
  `tools/` and the workflow itself — keep those clean rather than widening the
  exclusions.
- Planted secrets must stay detectable by the tool the worksheet names. Week 2's
  values were once undetectable by Gitleaks, which made a graded task impossible.

## Verify by running, not by reading

Payloads, expected tool output, crash messages, line-number citations and package
pins in a worksheet are all things students execute literally. Run the command
before you claim it works — several worksheet "facts" here turned out to be wrong
under reproduction (an SQLi payload that never bypassed login, a `docker compose
run` that skipped the Flask install, a hardened build that traps in
FORTIFY_SOURCE rather than the stack canary).

## Build artifacts

`make` in `labs/week11-memory-safety-exploitation` produces `vuln`, `vuln-*` and
`fuzz`. They are git-ignored; delete them rather than leaving them in the tree —
the monorepo parity gate compares every file in the lab directory.
