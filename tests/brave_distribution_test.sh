#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly build_script="${repository_root}/scripts/build-brave-distribution.sh"
readonly package_script="${repository_root}/scripts/package-brave-distribution.sh"

test_root="$(mktemp -d)"
readonly test_root
trap 'rm -rf "${test_root}"' EXIT
mkdir -p "${test_root}/bin" "${test_root}/src/brave" \
  "${test_root}/src/out/Static_arm64/Brave Browser Development.app" \
  "${test_root}/dist"

# The rejection paths do not need macOS tools; exercise them in Linux CI too.
printf '#!/usr/bin/env bash\necho Darwin\n' >"${test_root}/bin/uname"
printf '#!/usr/bin/env bash\nexit 0\n' >"${test_root}/bin/sccache"
chmod +x "${test_root}/bin/uname" "${test_root}/bin/sccache"
export PATH="${test_root}/bin:${PATH}"
export REB_BRAVE_DIRECTORY="${test_root}/src/brave"
export REB_BRAVE_DISTRIBUTION_DIRECTORY="${test_root}/dist"

"${build_script}" --help | grep -Fq 'non-official macOS arm64'
"${package_script}" --help | grep -Fq 'static build'

if "${package_script}" invalid >"${test_root}/invalid.out" \
  2>"${test_root}/invalid.err"; then
  echo "Packaging accepted an invalid version." >&2
  exit 1
fi
grep -Fq 'Expected one version tag' "${test_root}/invalid.err"

if REB_BRAVE_JOBS=0 "${build_script}" >"${test_root}/jobs.out" \
  2>"${test_root}/jobs.err"; then
  echo "Build accepted zero jobs." >&2
  exit 1
fi
grep -Fq 'REB_BRAVE_JOBS must be a positive integer' \
  "${test_root}/jobs.err"

if "${build_script}" --verify-only >"${test_root}/pin.out" \
  2>"${test_root}/pin.err"; then
  echo "Build accepted an unpinned checkout." >&2
  exit 1
fi
grep -Fq 'Checkout does not match browser/config/brave-core.rev' \
  "${test_root}/pin.err"

if "${package_script}" v0.1.4 >"${test_root}/missing.out" \
  2>"${test_root}/missing.err"; then
  echo "Packaging accepted an output without GN arguments." >&2
  exit 1
fi
grep -Fq 'Static_arm64 browser build is missing' "${test_root}/missing.err"

printf 'is_component_build=true\n' \
  >"${test_root}/src/out/Static_arm64/args_generated.gni"
if "${package_script}" v0.1.4 >"${test_root}/component.out" \
  2>"${test_root}/component.err"; then
  echo "Packaging accepted a component build." >&2
  exit 1
fi
grep -Fq 'Distribution build argument is missing: is_component_build=false' \
  "${test_root}/component.err"

printf '%s\n' \
  'is_component_build=false' \
  'is_official_build=false' \
  'is_debug=false' \
  'target_cpu="arm64"' \
  'brave_channel="development"' \
  'skip_signing=true' \
  'enable_updater=true' \
  'enable_sparkle=false' \
  >"${test_root}/src/out/Static_arm64/args_generated.gni"
if "${package_script}" v0.1.4 >"${test_root}/updater.out" \
  2>"${test_root}/updater.err"; then
  echo "Packaging accepted an updater-enabled browser." >&2
  exit 1
fi
grep -Fq 'Distribution build argument is missing: enable_updater=false' \
  "${test_root}/updater.err"

printf '%s\n' \
  'is_component_build=false' \
  'is_official_build=false' \
  'is_debug=false' \
  'target_cpu="arm64"' \
  'brave_channel="development"' \
  'skip_signing=true' \
  'enable_updater=false' \
  'enable_sparkle=false' \
  >"${test_root}/src/out/Static_arm64/args_generated.gni"
archive="${test_root}/dist/Brave-Browser-Development-v0.1.4-macos-arm64.zip"
printf 'keep existing archive\n' >"${archive}"
if "${package_script}" v0.1.4 >"${test_root}/existing.out" \
  2>"${test_root}/existing.err"; then
  echo "Packaging replaced an existing archive." >&2
  exit 1
fi
grep -Fq 'Refusing to replace existing archive' \
  "${test_root}/existing.err"
grep -Fxq 'keep existing archive' "${archive}"

echo "brave_distribution_test passed"
