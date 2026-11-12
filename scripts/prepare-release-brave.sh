#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
cd "${repository_root}"

# --check-pin stops after the pin and browser-input checks, before any
# platform, network or filesystem work, so a release workflow can refuse a
# stale pin before it spends a build on it.
check_pin_only=false
case "${1:-}" in
  "") ;;
  --check-pin) check_pin_only=true ;;
  *)
    echo "usage: prepare-release-brave.sh [--check-pin]" >&2
    exit 2
    ;;
esac
readonly check_pin_only

# BEGIN reviewed paired browser pin
# One reviewed unit: the browser ZIP paired with this release, its provenance,
# where both are hosted, and the commit whose browser inputs built them. The ZIP
# may come from an earlier release when the browser inputs have not changed
# since its build commit; its name keeps the release it was built for. Replace
# every PLACEHOLDER before release. tools/write-release-pair.py reads this block
# too.
readonly brave_name=Brave-Browser-Development-v0.5.1-macos-arm64
readonly source_url=https://github.com/sunghoojung/reverse-engineering-browser/releases/download/brave-0.5.1-c31239e
readonly brave_sha256=04c4a3fd929c420ff110aa37bdccf4a47d4a03aa845edcca6857da448004da8a
readonly provenance_sha256=1b1ac88402dc94ba2ef327496aecc4ed33e2a17c7a35d630a0d8e57703a22605
readonly build_source=c31239e9c4099883ad90b5fb6bd5f415aea1f29d
# END reviewed paired browser pin

readonly plist=apps/research-ui/macos/Info.plist
read_plist() {
  python3 -I -c 'import plistlib, sys
print(plistlib.load(open(sys.argv[1], "rb")).get(sys.argv[2], ""))' "${plist}" "$1"
}
version="$(read_plist CFBundleShortVersionString)"
readonly version

# Validate the whole pin before any platform, network or filesystem work, so an
# unfinished release fails the same way everywhere.
unfinished=()
# The browser must have been built for this version or an earlier one.
brave_version=""
if [[ "${brave_name}" =~ ^Brave-Browser-Development-v([0-9]+\.[0-9]+\.[0-9]+)-macos-arm64$ ]]; then
  brave_version="${BASH_REMATCH[1]}"
fi
if [[ -z "${brave_version}" ||
      "$(printf '%s\n' "${brave_version}" "${version}" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" != "${version}" ]]; then
  unfinished+=("brave_name (must name Info.plist version ${version} or an earlier release)")
fi
[[ "${source_url}" =~ ^https://github\.com/sunghoojung/reverse-engineering-browser/releases/download/[A-Za-z0-9._-]+$ ]] ||
  unfinished+=(source_url)
[[ "${brave_sha256}" =~ ^[0-9a-f]{64}$ ]] || unfinished+=(brave_sha256)
[[ "${provenance_sha256}" =~ ^[0-9a-f]{64}$ ]] || unfinished+=(provenance_sha256)
[[ "${build_source}" =~ ^[0-9a-f]{40}$ ]] || unfinished+=(build_source)
if ((${#unfinished[@]})); then
  echo "The paired browser pin is unfinished. Fill these reviewed values:" >&2
  printf '  %s\n' "${unfinished[@]}" >&2
  exit 1
fi

# Reuse the published browser bytes only while every browser input and wire
# contract still matches the commit that built them.
if ! git cat-file -e "${build_source}^{commit}" 2>/dev/null; then
  echo "Browser build commit ${build_source} is not in this checkout's history." >&2
  exit 1
fi
if ! git diff --exit-code "${build_source}" -- \
  browser include src protocol services \
  scripts/bootstrap-brave.sh scripts/brave-toolchain.sh \
  scripts/build-brave-distribution.sh scripts/build-integrated-brave.sh \
  scripts/package-brave-distribution.sh scripts/sync-browser-integration.sh; then
  echo "Browser inputs changed since ${build_source} built ${brave_name}; build, package and pin a new browser." >&2
  exit 1
fi
if [[ "${check_pin_only}" == true ]]; then
  echo "The paired browser pin matches this source's browser inputs."
  exit 0
fi

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "The paired Brave artifact requires an arm64 macOS runner." >&2
  exit 1
fi

readonly release_root=build/release-pair
# The pin this directory was prepared from. A rerun reuses only a directory
# prepared from the same pin, after verifying it again.
readonly prepared_record="${release_root}/prepared-brave-pin.txt"
prepared_pin="$(printf '%s\n' "${brave_name}" "${source_url}" "${brave_sha256}" \
  "${provenance_sha256}" "${build_source}")"
readonly prepared_pin

verify_prepared_brave() {
  local root="$1"
  local app="${root}/extracted/Brave Browser Development.app"
  local cdhash
  local recorded_cdhash
  (
    cd "${root}/source"
    printf '%s  %s\n' \
      "${brave_sha256}" "${brave_name}.zip" \
      "${provenance_sha256}" "${brave_name}.provenance.json" |
      shasum -a 256 --check
  )
  codesign --verify --deep --strict "${app}"
  # The digest-pinned provenance records the packaged app's code signature, so a
  # matching CDHash ties the extracted bundle to that exact recorded build.
  cdhash="$(codesign -dvvv "${app}" 2>&1 | sed -n 's/^CDHash=//p')"
  recorded_cdhash="$(python3 -I -c 'import json, sys
print(json.load(open(sys.argv[1]))["app_cdhash"])' \
    "${root}/source/${brave_name}.provenance.json")"
  if [[ "${cdhash}" != "${recorded_cdhash}" ]]; then
    echo "Extracted Brave CDHash ${cdhash:-<none>} differs from its provenance (${recorded_cdhash})." >&2
    exit 1
  fi
  "${app}/Contents/MacOS/Brave Browser Development" --version
}

if [[ -e "${release_root}" ]]; then
  if [[ -f "${prepared_record}" && ! -L "${prepared_record}" &&
        "$(cat "${prepared_record}")" == "${prepared_pin}" ]]; then
    verify_prepared_brave "${release_root}"
    echo "Reused ${release_root}, prepared from this browser pin."
    exit 0
  fi
  echo "Refusing to overwrite ${release_root}: it was not prepared from this browser pin." >&2
  echo "Preserve anything you need from it, then remove it to prepare again." >&2
  exit 1
fi
# Work in a private directory and publish it by rename, so a failed or
# interrupted run leaves nothing that blocks the next one.
mkdir -p build
staging="$(mktemp -d build/release-pair.partial.XXXXXX)"
readonly staging
trap 'rm -rf "${staging}"' EXIT
mkdir -p "${staging}/source"
curl --fail --location --silent --show-error --retry 3 \
  "${source_url}/${brave_name}.zip" -o "${staging}/source/${brave_name}.zip"
curl --fail --location --silent --show-error --retry 3 \
  "${source_url}/${brave_name}.provenance.json" -o "${staging}/source/${brave_name}.provenance.json"
(
  cd "${staging}/source"
  printf '%s  %s\n' \
    "${brave_sha256}" "${brave_name}.zip" \
    "${provenance_sha256}" "${brave_name}.provenance.json" |
    shasum -a 256 --check
)
ditto -x -k "${staging}/source/${brave_name}.zip" "${staging}/extracted"
verify_prepared_brave "${staging}"
printf '%s\n' "${prepared_pin}" >"${staging}/prepared-brave-pin.txt"
mv "${staging}" "${release_root}"
trap - EXIT
