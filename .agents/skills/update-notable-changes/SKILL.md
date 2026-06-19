# update-notable-changes

Manual invocation only. Do not auto-trigger.

## When to Use

Use only when explicitly asked to update README notable changes.

## Procedure

1. Scan recent branch history: `git log --oneline --decorate -20` and `git diff --stat $(git merge-base HEAD origin/fork)..HEAD` when available.
2. Summarize user-facing changes only; skip chores, formatting, and test-only noise unless they matter.
3. Edit the README `## Notable changes` bullets to reflect the branch accurately and concisely.
4. Do not commit.

## Verification

Run `git diff -- README.md` and report the README change.
