#!/usr/bin/env bash
# Produce a clean public repository snapshot from the current working
# tree: a fresh git repo whose root commit contains exactly the reviewed
# files, with no history from the private repository.
#
# Usage:
#   scripts/make-public-snapshot.sh [destination-dir]
#
# The commit author is taken from git config unless overridden:
#   PUBLIC_NAME="Your Name" PUBLIC_EMAIL="you@example.com" scripts/...
#
# The private repository is never modified. Inspect the result, then:
#   cd <destination-dir> && git remote add origin <public-url> && git push -u origin main

set -euo pipefail

cd "$(dirname "$0")/.."
src="$(pwd)"

dest="${1:-../stile-public}"
if [ -e "$dest" ]; then
    echo "refusing to overwrite existing $dest" >&2
    exit 1
fi

# Require a clean, committed tree so the snapshot matches what was
# reviewed.
if [ -n "$(git status --porcelain)" ]; then
    echo "working tree is dirty; commit or stash first" >&2
    git status --short >&2
    exit 1
fi

mkdir -p "$dest"
cd "$dest"
git init -q -b main

# Copy exactly the tracked files.
git -C "$src" archive HEAD | tar -x -C "$dest"

# Private-only material (see PRIVATE.md) never ships.
rm -f "$dest/PRIVATE.md"

name="${PUBLIC_NAME:-$(git -C "$src" config user.name)}"
email="${PUBLIC_EMAIL:-$(git -C "$src" config user.email)}"
GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" \
GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email" \
    git add -A
GIT_AUTHOR_NAME="$name" GIT_AUTHOR_EMAIL="$email" \
GIT_COMMITTER_NAME="$name" GIT_COMMITTER_EMAIL="$email" \
    git commit -q -m "stile v0.1.0: capability-oriented secret broker

Initial public snapshot. Give agents capabilities, not credentials:
privileged lifecycle operations (rotate, verify, reconcile, status,
list, provider-assisted import) over SOPS-managed secrets, with no
code path that can return a secret value to an untrusted caller.

See README.md and THREAT_MODEL.md."

echo "public snapshot created at $dest"
echo "author: $name <$email>"
git log --oneline
