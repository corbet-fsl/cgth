# cgth agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cgth` — green, exit 0
  (lib `1 passed`; `--test accounting` `0 passed`: compiled out by default,
  `#![cfg(all(feature = "accounting", not(target_arch = "wasm32")))]`)
- `test -p cgth --features accounting` needs the CI fixture
  `CBLC_RECORD_EPOCH_FIXTURE` (genuine retained R2 capture imported by
  `.ci/verify.sh`); without it all 6 tests panic at
  `tests/accounting/fixture.rs:37`. Full gate (coverage `--all-features`)
  runs in CI only.
- `~/agents/scratch/cbuild <lane> fmt -p cgth -- --check` — must be clean
- `clippy -p cgth --all-targets -- -D warnings` is red at HEAD from upstream
  `ckmg` lints (unused `SigningPhase` import, dead `label`/`insert`), not this
  crate.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Thin routing only: no duplicated policy, quota, room protocol or member
  registry; quota and volatile children stay with their owners
  -> `src/tests.rs::real_quota_and_volatile_children_remain_the_owners`
- Accounting (`--features accounting`, CI fixture only): wrong record owner
  omitted before cursor seen
  -> `tests/accounting.rs::lookup::genuinely_signed_wrong_record_owner_is_omitted_before_cursor_seen`
- Other members cannot reuse the original record owner; fresh proof/device
  mutations leave pending retryable, never admittable
  -> `refusals::authenticated_other_member_cannot_reuse_original_record_owner`,
  `refusals::fresh_context_proof_and_device_mutations_leave_pending_retryable`
- Capacity failure rolls back both pending and attendance rows
  -> `refusals::real_capacity_failure_rolls_back_both_pending_and_attendance_rows`
- Allowance change permanently fences the original issuer; withdrawal cannot
  resurrect it -> `rooms::authenticated_room_allowance_change_permanently_fences_original_issuer`
- `forbid(unsafe_code)` (`src/lib.rs:2`); hostile wire refused
  (`deny_unknown_fields`, `src/accounting.rs:37`)

Pointers: `src/lib.rs`, `src/accounting.rs`, `tests/accounting.rs`,
`docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
FSL-1.1-ALv2 (`LICENSE.md`); no registry publication.
