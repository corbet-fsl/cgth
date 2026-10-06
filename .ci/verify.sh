#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

# dependency-policy first-party only; deny advisories separate always-run.
python3 .github/check-first-party.py

# check job exact order.
rustc --version
rustc --version
cargo fmt --all
git diff --exit-code -- '*.rs' > format.patch
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets

# Coverage runs under nightly end to end. cargo-llvm-cov re-invokes rustc
# for the real compile, and wrapping only the top command leaves those child
# compiles on the stable toolchain, so resolve the nightly binaries once and
# export them (RUSTC, CARGO, PATH, RUSTUP_TOOLCHAIN) for this block.
export CARGO_PROFILE_TEST_OPT_LEVEL='0'
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex "/tests/" --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
)
python3 .github/check-coverage.py coverage.lcov coverage.json
