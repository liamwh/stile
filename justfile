# stile development tasks — see https://github.com/casey/just
# `just` with no argument runs `check`, the pre-push gate.

default: check

# Everything CI runs. Run this before pushing.
check: fmt-check clippy test deny

# Format the tree.
fmt:
    cargo fmt --all

# Fail if anything is unformatted.
fmt-check:
    cargo fmt --all --check

# Lint with warnings denied (same as CI).
clippy:
    CARGO_TARGET_DIR=target cargo clippy --all-targets --all-features --locked -- -D warnings

# Dependency advisories, licences and sources (same as CI).
deny:
    cargo deny --all-features check

# Build release binaries (stile, stile-brokerd) from the locked deps.
build:
    cargo build --release --locked -p stile -p stile-brokerd

# Full test suite, unit + end-to-end, via nextest (process-per-test, so
# broker env overrides stay isolated). Builds the binaries the e2e suite
# locates in the repo-local target dir first — a shared CARGO_TARGET_DIR
# cache holding stale binaries is deliberately ignored.
test: (binaries) 
    CARGO_TARGET_DIR=target cargo nextest run --all-features --locked

# Binaries the e2e suite spawns (debug broker, release CLI).
[private]
binaries:
    CARGO_TARGET_DIR=target cargo build --all-targets --locked
    CARGO_TARGET_DIR=target cargo build --release --locked -p stile -p stile-brokerd

# Keep a failing e2e fixture under /tmp/stile-it-* for inspection.
# Set STILE_IT_KEEP=1 before `just test`.

# Remove repo-local build artefacts only (never a shared cargo cache).
clean:
    rm -rf target

# Install the prek git hooks (secret scan, fmt, clippy, lock check,
# conventional-commit messages). Run once per clone.
hooks:
    prek install --hook-type pre-commit --hook-type commit-msg

# Run every hook against the whole tree once (no commit made).
hooks-run:
    prek run --all-files

# Produce a clean one-commit public snapshot from the committed tree.
# PUBLIC_NAME/PUBLIC_EMAIL override the commit author.
snapshot dest="../stile-public":
    bash scripts/make-public-snapshot.sh {{dest}}
