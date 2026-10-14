#!/usr/bin/env bash
# check.sh — single-pass repo health check.
#
# Runs build, the shim build, tests, clippy, `plzn lint` over the corpus, and
# the shim conformance corpus itself (which `cargo test` alone leaves out).
# Cargo commands use the checked-in lockfile without updating dependencies.
# Build warnings and clippy warnings fail the run.
# Bails at the first failing stage so the relevant output is on screen.
#
# Usage: ./check.sh          # full check
#        ./check.sh --quick  # skip clippy

set -uo pipefail

cd "$(dirname "$0")"

quick=0
for arg in "$@"; do
    case "$arg" in
        --quick) quick=1 ;;
        -h|--help)
            sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "check.sh: unknown flag $arg" >&2
            exit 2
            ;;
    esac
done

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

step() { printf '\n=== %s ===\n' "$*"; }

# 1. Build all targets; fail on any rustc warning.
step "build (warnings = errors)"
build_log=$(mktemp)
trap 'rm -f "$build_log"' EXIT
if ! cargo build --locked --all-targets 2>&1 | tee "$build_log"; then
    red "FAIL: cargo build"
    exit 1
fi
if grep -qE '^warning:' "$build_log"; then
    red "FAIL: build produced warnings (see above)"
    exit 1
fi
green "ok"

# 1b. Shims. `make -C shims` relinks a shim only when its source, the shared
#     helper lib, or the library it links against is newer than the binary
#     (the library file is a make prerequisite), so this is a no-op in the
#     common case. A shim left linked against a library that has since been
#     rebuilt dies on every case (`plzn run` reports it as [CRASH]); this step
#     is what keeps the gate from running such a binary.
step "shims (make -C shims)"
if ! make -C shims; then
    red "FAIL: shim build"
    exit 1
fi
green "ok"

# 2. Tests.
step "cargo test"
if ! cargo test --locked --no-fail-fast; then
    red "FAIL: cargo test"
    exit 1
fi
green "ok"

# 3. Canonical DSL formatting.
step "plzn fmt --check"
if ! ./target/debug/plzn fmt --check suite tests/cases; then
    red "FAIL: .plzn files need formatting (run: plzn fmt suite tests/cases)"
    exit 1
fi
green "ok"

# 4. plzn lint over the corpus. The conformance corpus lives in suite/ (lint
#    recurses into its subdirs); matcher, DTLS reassembly, and local rejection
#    self-tests live under tests/cases/.
#    tests/cases/wedge/ holds design ports for unimplemented features (no
#    runnable cases) and is skipped.
step "plzn lint suite"
if ! ./target/debug/plzn lint --errors-only suite tests/cases/negative tests/cases/dtls_reassembly tests/cases/local_rejections; then
    red "FAIL: plzn lint reported errors"
    exit 1
fi
green "ok"

# 5. Clippy — warnings are denied via `-D warnings` so the gate
#    rises with the codebase. Lints we explicitly want to keep
#    should be silenced locally with `#[allow(...)]` + a comment.
if [[ $quick -eq 0 ]]; then
    step "clippy (warnings denied)"
    if ! cargo clippy --locked --all-targets -- -D warnings; then
        red "FAIL: clippy"
        exit 1
    fi
    green "ok"
fi

# 6. The conformance corpus against every built shim. These tests are
#    `#[ignore]`d so a plain `cargo test` stays quick and environment-neutral;
#    this gate runs them explicitly. Last, so the fast checks above report
#    first.
step "shim corpus (cargo test --test shim_corpus -- --ignored)"
if ! cargo test --locked --test shim_corpus -- --ignored; then
    red "FAIL: shim corpus"
    exit 1
fi
green "ok"

echo
green "all checks passed"
