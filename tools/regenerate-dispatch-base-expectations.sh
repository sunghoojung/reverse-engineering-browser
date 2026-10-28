#!/usr/bin/env bash
# Rebuild the base analyzer from DISPATCH_BASE_COMMIT in a disposable
# directory, write every differential input from the current tree, and
# snapshot base behavior into the checked-in expectation file.
set -euo pipefail

commit=${DISPATCH_BASE_COMMIT:?DISPATCH_BASE_COMMIT is required}
output=${1:?usage: regenerate-dispatch-base-expectations.sh OUTPUT}
repository=$(git rev-parse --show-toplevel)
work=$(mktemp -d "${TMPDIR:-/tmp}/dispatch-base.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/src" "$work/inputs"
git -C "$repository" archive "$commit" apps/origin-trace-backend protocol tools/fixtures |
  tar -x -C "$work/src"
CARGO_TARGET_DIR="$work/target" cargo build --release --locked \
  --manifest-path "$work/src/apps/origin-trace-backend/Cargo.toml" --bin origin-trace-vm
# The grep makes a renamed or filtered-out writer fail instead of passing
# with 0 tests and an empty input directory.
REB_DIFFERENTIAL_INPUTS="$work/inputs" cargo test --locked \
  --manifest-path "$repository/apps/origin-trace-backend/Cargo.toml" --lib \
  -- --ignored --exact vm::dispatch_shape_tests::write_differential_inputs |
  tee "$work/writer.log"
grep -q '^test result: ok\. 1 passed; 0 failed;' "$work/writer.log" ||
  { echo "write_differential_inputs did not run and pass" >&2; exit 1; }
python3 "$repository/tools/dispatch-base-expectations.py" \
  --binary "$work/target/release/origin-trace-vm" --inputs "$work/inputs" \
  --commit "$(git -C "$repository" rev-parse "$commit")" --output "$output"
