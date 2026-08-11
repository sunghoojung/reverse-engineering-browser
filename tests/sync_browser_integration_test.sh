#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly sync_script="${repository_root}/scripts/sync-browser-integration.sh"

test_root="$(mktemp -d)"
readonly test_root
trap 'rm -rf "${test_root}"' EXIT
git -C "${test_root}" init -q

readonly brave_directory="${test_root}/src/brave"
mkdir -p "${brave_directory}"
git -C "${brave_directory}" init -q

if REB_BRAVE_DIRECTORY="${brave_directory}" "${sync_script}" \
  >"${test_root}/sync.out" 2>"${test_root}/sync.err"; then
  echo "Sync unexpectedly succeeded without Chromium" >&2
  exit 1
fi

grep -Fq "Chromium checkout is missing: ${test_root}/src" "${test_root}/sync.err"
test ! -e "${brave_directory}/components/reverse_engineering_browser"

git -C "${test_root}/src" init -q
git -C "${test_root}/src" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m fixture
git -C "${brave_directory}" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m fixture
if REB_BRAVE_DIRECTORY="${brave_directory}" \
  REB_BRAVE_CORE_REVISION=HEAD REB_CHROMIUM_REVISION=HEAD "${sync_script}" \
  >"${test_root}/patch.out" 2>"${test_root}/patch.err"; then
  echo "Sync unexpectedly accepted an incompatible Brave checkout" >&2
  exit 1
fi

grep -Fq 'patch does not apply cleanly:' "${test_root}/patch.err"
test ! -e "${brave_directory}/components/reverse_engineering_browser"

git -C "${brave_directory}" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m mismatch
if REB_BRAVE_DIRECTORY="${brave_directory}" \
  REB_BRAVE_CORE_REVISION='HEAD~1' REB_CHROMIUM_REVISION=HEAD "${sync_script}" \
  >"${test_root}/brave-revision.out" 2>"${test_root}/brave-revision.err"; then
  echo "Sync unexpectedly accepted a mismatched Brave revision" >&2
  exit 1
fi
grep -Fq 'Brave checkout revision does not match the pin.' \
  "${test_root}/brave-revision.err"

git -C "${test_root}/src" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m mismatch
if REB_BRAVE_DIRECTORY="${brave_directory}" \
  REB_BRAVE_CORE_REVISION=HEAD REB_CHROMIUM_REVISION='HEAD~1' "${sync_script}" \
  >"${test_root}/chromium-revision.out" 2>"${test_root}/chromium-revision.err"; then
  echo "Sync unexpectedly accepted a mismatched Chromium revision" >&2
  exit 1
fi
grep -Fq 'Chromium checkout revision does not match the pin.' \
  "${test_root}/chromium-revision.err"
test ! -e "${brave_directory}/components/reverse_engineering_browser"

echo "sync_browser_integration_test passed"
