#!/usr/bin/env bash
# Commit-msg hook body: enforce conventional commits.
# Types mirror @commitlint/config-conventional.
set -euo pipefail
msg_file="${1:-}"
pattern='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\(.+\))?!?: .+'
if ! grep -qE "$pattern" "$msg_file"; then
  echo "commit message must match: type[(scope)][!]: subject" >&2
  echo "example: feat(broker): cap request line length" >&2
  echo "types: build chore ci docs feat fix perf refactor revert style test" >&2
  exit 1
fi
