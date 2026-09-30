#!/usr/bin/env bash
# Commit-msg hook body: enforce conventional commits.
# Types mirror @commitlint/config-conventional.
set -euo pipefail
msg_file="${1:-}"
# prek does not forward the filename to commit-msg entries (argc=0 in
# 0.4.14); git always runs this stage against .git/COMMIT_EDITMSG.
[ -n "$msg_file" ] || msg_file=".git/COMMIT_EDITMSG"
pattern='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\(.+\))?!?: .+'
if ! grep -qE "$pattern" "$msg_file"; then
  echo "commit message must match: type[(scope)][!]: subject" >&2
  echo "example: feat(broker): cap request line length" >&2
  echo "types: build chore ci docs feat fix perf refactor revert style test" >&2
  exit 1
fi
