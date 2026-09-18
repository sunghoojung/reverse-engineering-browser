#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly sync_script="${repository_root}/scripts/sync-browser-integration.sh"

test_root="$(mktemp -d)"
readonly test_root
cleanup() {
  local status
  local log_file
  status="$1"
  if ((status != 0)); then
    while IFS= read -r log_file; do
      echo "--- ${log_file#"${test_root}/"}" >&2
      sed -n '1,160p' "${log_file}" >&2
    done < <(find "${test_root}" -type f -name '*.err' -print | sort)
  fi
  rm -rf "${test_root}"
  exit "${status}"
}
trap 'cleanup $?' EXIT
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
mkdir -p "${test_root}/src/v8"
git -C "${test_root}/src/v8" init -q
git -C "${test_root}/src/v8" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m fixture
export REB_V8_REVISION=HEAD
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

git -C "${test_root}/src/v8" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m mismatch
if REB_BRAVE_DIRECTORY="${brave_directory}" \
  REB_BRAVE_CORE_REVISION=HEAD REB_CHROMIUM_REVISION=HEAD \
  REB_V8_REVISION='HEAD~1' "${sync_script}" \
  >"${test_root}/v8-revision.out" 2>"${test_root}/v8-revision.err"; then
  echo "Sync unexpectedly accepted a mismatched V8 revision" >&2
  exit 1
fi
grep -Fq 'V8 checkout revision does not match the pin.' \
  "${test_root}/v8-revision.err"

readonly overlap_root="${test_root}/overlap"
readonly overlap_checkout="${overlap_root}/checkout"
readonly overlap_integration="${overlap_root}/integration"
mkdir -p "${overlap_checkout}" "${overlap_integration}/patches"
git -C "${overlap_checkout}" init -q
printf 'base\n' >"${overlap_checkout}/fixture.txt"
git -C "${overlap_checkout}" add fixture.txt
git -C "${overlap_checkout}" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q -m fixture
cat >"${overlap_integration}/patches/0001-first.patch" <<'PATCH'
diff --git a/fixture.txt b/fixture.txt
index df967b9..9c59e24 100644
--- a/fixture.txt
+++ b/fixture.txt
@@ -1 +1 @@
-base
+first
PATCH
cat >"${overlap_integration}/patches/0002-overlap.patch" <<'PATCH'
diff --git a/fixture.txt b/fixture.txt
index 9c59e24..e019be0 100644
--- a/fixture.txt
+++ b/fixture.txt
@@ -1 +1 @@
-first
+second
PATCH

for run_number in 1 2; do
  REB_BRAVE_DIRECTORY="${overlap_checkout}" \
    REB_BRAVE_INTEGRATION_DIRECTORY="${overlap_integration}" \
    REB_BRAVE_CORE_REVISION=HEAD "${sync_script}" \
    >"${overlap_root}/sync-${run_number}.out" \
    2>"${overlap_root}/sync-${run_number}.err"
  test "$(tr -d '\n' <"${overlap_checkout}/fixture.txt")" = 'second'
done
grep -Fq 'Already applied: patch stack' \
  "${overlap_root}/sync-2.out"

readonly siso_root="${test_root}/siso"
readonly siso_chromium="${siso_root}/src"
readonly siso_brave="${siso_chromium}/brave"
readonly siso_integration="${siso_root}/integration"
mkdir -p "${siso_brave}/build/config/siso" "${siso_chromium}/build/config/siso" \
  "${siso_integration}/patches" "${siso_chromium}/v8"
git -C "${siso_chromium}" init -q
git -C "${siso_chromium}" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m fixture
git -C "${siso_chromium}/v8" init -q
git -C "${siso_chromium}/v8" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q --allow-empty -m fixture
git -C "${siso_brave}" init -q
printf 'patched siso config\n' >"${siso_brave}/build/config/siso/brave_siso_config.star"
git -C "${siso_brave}" add build/config/siso/brave_siso_config.star
git -C "${siso_brave}" -c user.name='Sync Test' \
  -c user.email='sync-test@example.invalid' commit -q -m fixture
# macOS ships Bash 3.2, which treats an empty array expansion as unset.
REB_BRAVE_DIRECTORY="${siso_brave}" \
  REB_BRAVE_INTEGRATION_DIRECTORY="${siso_integration}" \
  REB_BRAVE_CORE_REVISION=HEAD REB_CHROMIUM_REVISION=HEAD \
  REB_V8_REVISION=HEAD /bin/bash "${sync_script}" \
  >"${siso_root}/sync.out" 2>"${siso_root}/sync.err"
cmp -s "${siso_brave}/build/config/siso/brave_siso_config.star" \
  "${siso_chromium}/build/config/siso/brave_siso_config.star"

echo "sync_browser_integration_test passed"
