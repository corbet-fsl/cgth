#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

# dependency-policy first-party only; deny advisories separate always-run.
python3 .github/check-first-party.py

# Import the independently checked genuine R2 capture into this job's own
# snapshot. Never execute an unpinned cached worker or regenerate these proofs.
# cblc produces the capture (record-epoch) and retains it write-once under the
# digest of its worker receipt; that digest is the pin, and the store is read
# content-addressed because the producer's ccid cache namespace follows its
# repository URL (the org moved once already).
fixture_cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $fixture_cache_root = /* ]] || { echo 'An absolute fixture cache root is required' >&2; exit 2; }
record_fixture_source=e5514337959c4aacb3e9d7f678e3f45898b61061
record_fixture_digest=e55d4cafadb748f4e24a7a581208407c2fcb32ea74a1ae37532167e9054c4925
fixture_directory=
for candidate in "$fixture_cache_root"/ccid-cached/*/release-artifacts/gather-record-fixture-retained/"$record_fixture_digest"; do
  if [[ -d $candidate ]]; then fixture_directory=$candidate; break; fi
done
[[ -n $fixture_directory ]] || { echo "The retained record fixture $record_fixture_digest is missing under $fixture_cache_root (cblc record-epoch retains it)" >&2; exit 2; }
fixture_snapshot=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cgth-record-fixture.XXXXXXXX")
export CBLC_BB
CBLC_BB=$(python3 .ci/check-record-fixture.py \
  --directory "$fixture_directory" \
  --source "$record_fixture_source" \
  --metadata-sha256 "$record_fixture_digest" \
  --output "$fixture_snapshot/capture")
export CBLC_RECORD_EPOCH_FIXTURE="$fixture_snapshot/capture/gather-record-fixture.json"

# check job exact order.
rustc --version
rustc --version
bash .ci/update-our-crates.sh
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
