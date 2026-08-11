#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly bootstrap_script="${repository_root}/scripts/bootstrap-brave.sh"

test_root="$(mktemp -d)"
readonly test_root
trap 'rm -rf "${test_root}"' EXIT

source_repository="${test_root}/source"
remote_repository="${test_root}/remote.git"
remote_url="file://${remote_repository}"
private_repository="${test_root}/private.git"
private_url="file://${private_repository}"
fake_bin="${test_root}/bin"
mkdir -p "${source_repository}" "${fake_bin}"

git -C "${source_repository}" init -q -b main
printf 'fixture\n' >"${source_repository}/README.md"
git -C "${source_repository}" add README.md
git -C "${source_repository}" \
  -c user.name='Bootstrap Test' \
  -c user.email='bootstrap-test@example.invalid' \
  commit -q -m fixture
git clone -q --bare "${source_repository}" "${remote_repository}"
git clone -q --bare "${source_repository}" "${private_repository}"

git -C "${source_repository}" checkout -q -b official-only
printf 'official remote only\n' >"${source_repository}/official-only"
git -C "${source_repository}" add official-only
git -C "${source_repository}" \
  -c user.name='Bootstrap Test' \
  -c user.email='bootstrap-test@example.invalid' \
  commit -q -m official-only
official_only_revision="$(git -C "${source_repository}" rev-parse HEAD)"
git -C "${source_repository}" push -q "${remote_url}" official-only

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "Filesystem 1024-blocks Used Available Capacity Mounted on\\n"' \
  'printf "fixture 999999999 1 999999998 1%% /fixture\\n"' \
  >"${fake_bin}/df"
# The generated script expands these variables when it runs, not while this
# fixture is being written.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\\n" "$*" >"${BOOTSTRAP_TEST_LOG}"' \
  >"${fake_bin}/corepack"
chmod +x "${fake_bin}/df" "${fake_bin}/corepack"

run_bootstrap() {
  local checkout_name="$1"
  local log_file="$2"
  shift 2
  PATH="${fake_bin}:${PATH}" \
    BOOTSTRAP_TEST_LOG="${log_file}" \
    REB_BRAVE_WORKTREE="${test_root}/${checkout_name}" \
    "${bootstrap_script}" --remote "${remote_url}" --revision main "$@"
}

shallow_log="${test_root}/shallow.log"
run_bootstrap shallow "${shallow_log}" --init >/dev/null
grep -Fxq 'pnpm run init -- --no-history' "${shallow_log}"
mkdir -p "${test_root}/shallow/src/out"
printf 'keep checkout\n' >"${test_root}/shallow/src/brave/local-marker"
printf 'keep build\n' >"${test_root}/shallow/src/out/local-marker"
run_bootstrap shallow "${shallow_log}" >/dev/null
grep -Fxq 'keep checkout' "${test_root}/shallow/src/brave/local-marker"
grep -Fxq 'keep build' "${test_root}/shallow/src/out/local-marker"

full_log="${test_root}/full.log"
run_bootstrap full "${full_log}" --init --full-history >/dev/null
grep -Fxq 'pnpm run init' "${full_log}"

commit_log="${test_root}/commit.log"
run_bootstrap commit "${commit_log}" --revision "${official_only_revision}" >/dev/null
test "$(git -C "${test_root}/commit/src/brave" rev-parse HEAD)" = \
  "${official_only_revision}"

remote_selection_worktree="${test_root}/remote-selection"
mkdir -p "${remote_selection_worktree}/src"
git clone -q "${private_url}" "${remote_selection_worktree}/src/brave"
git -C "${remote_selection_worktree}/src/brave" remote add upstream "${remote_url}"
PATH="${fake_bin}:${PATH}" \
  REB_BRAVE_WORKTREE="${remote_selection_worktree}" \
  "${bootstrap_script}" --remote "${remote_url}" \
    --revision official-only >/dev/null
test "$(git -C "${remote_selection_worktree}/src/brave" rev-parse HEAD)" = \
  "${official_only_revision}"

dirty_mismatch_worktree="${test_root}/dirty-mismatch"
mkdir -p "${dirty_mismatch_worktree}/src"
git clone -q "${private_url}" "${dirty_mismatch_worktree}/src/brave"
git -C "${dirty_mismatch_worktree}/src/brave" remote add upstream "${remote_url}"
printf 'local change\n' >"${dirty_mismatch_worktree}/src/brave/local-marker"
if PATH="${fake_bin}:${PATH}" \
  REB_BRAVE_WORKTREE="${dirty_mismatch_worktree}" \
  "${bootstrap_script}" --remote "${remote_url}" --revision official-only \
  >"${test_root}/dirty-mismatch.out" 2>"${test_root}/dirty-mismatch.err"; then
  echo "Bootstrap unexpectedly switched a dirty checkout" >&2
  exit 1
fi
grep -Fq 'Brave checkout has local changes at a different revision.' \
  "${test_root}/dirty-mismatch.err"
grep -Fxq 'local change' "${dirty_mismatch_worktree}/src/brave/local-marker"

nested_non_checkout="${source_repository}/nested-worktree"
mkdir -p "${nested_non_checkout}/src/brave"
if PATH="${fake_bin}:${PATH}" \
  REB_BRAVE_WORKTREE="${nested_non_checkout}" \
  "${bootstrap_script}" --remote "${remote_url}" --revision main \
  >"${test_root}/nested.out" 2>"${test_root}/nested.err"; then
  echo "Bootstrap unexpectedly accepted a nested non-checkout" >&2
  exit 1
fi
grep -Fq "Existing path is not a Git checkout: ${nested_non_checkout}/src/brave" \
  "${test_root}/nested.err"

if run_bootstrap invalid "${test_root}/invalid.log" --full-history \
  >"${test_root}/invalid.out" 2>"${test_root}/invalid.err"; then
  echo "--full-history unexpectedly succeeded without --init" >&2
  exit 1
fi
grep -Fxq -- '--full-history requires --init' "${test_root}/invalid.err"

help_output="$("${bootstrap_script}" --help)"
grep -Fq -- '--full-history' <<<"${help_output}"
grep -Fq 'shallow Chromium history' <<<"${help_output}"

echo "bootstrap_brave_test passed"
