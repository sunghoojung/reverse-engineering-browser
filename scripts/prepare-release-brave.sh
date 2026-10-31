#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
cd "${repository_root}"

# BEGIN reviewed paired browser pin
# One reviewed unit: the browser ZIP built for this paired release, its
# provenance, where both are hosted, and the commit whose browser inputs built
# them. Replace every PLACEHOLDER before release. tools/write-release-pair.py
# reads this block too. The browser's CDHash lives in
# apps/research-ui/macos/Info.plist (OriginTracePairedBrowserCDHash) because
# Origin Trace reads it at launch; this script verifies it below.
readonly brave_name=Brave-Browser-Development-v0.5.0-macos-arm64
readonly source_url=https://github.com/sunghoojung/reverse-engineering-browser/releases/download/brave-0.5.0-3436163
readonly brave_sha256=39d58fa8f542f3cb0957bc2349c4c812a516180fe6869d0bdc2b2d901df2179e
readonly provenance_sha256=e038d83c14dd5030d65d89c42dbf5badf9ad0446bd0748c854a359227ce16cf2
readonly build_source=3436163584124ce081de5b0da26948bf73cdfa46
# END reviewed paired browser pin

readonly plist=apps/research-ui/macos/Info.plist
read_plist() {
  python3 -I -c 'import plistlib, sys
print(plistlib.load(open(sys.argv[1], "rb")).get(sys.argv[2], ""))' "${plist}" "$1"
}
paired_cdhash="$(read_plist OriginTracePairedBrowserCDHash)"
readonly paired_cdhash
version="$(read_plist CFBundleShortVersionString)"
readonly version

# Validate the whole pin before any platform, network or filesystem work, so an
# unfinished release fails the same way everywhere.
unfinished=()
[[ "${brave_name}" == "Brave-Browser-Development-v${version}-macos-arm64" ]] ||
  unfinished+=("brave_name (must match Info.plist version ${version})")
[[ "${source_url}" =~ ^https://github\.com/sunghoojung/reverse-engineering-browser/releases/download/[A-Za-z0-9._-]+$ ]] ||
  unfinished+=(source_url)
[[ "${brave_sha256}" =~ ^[0-9a-f]{64}$ ]] || unfinished+=(brave_sha256)
[[ "${provenance_sha256}" =~ ^[0-9a-f]{64}$ ]] || unfinished+=(provenance_sha256)
[[ "${build_source}" =~ ^[0-9a-f]{40}$ ]] || unfinished+=(build_source)
[[ "${paired_cdhash}" =~ ^[0-9a-f]{40}$ ]] ||
  unfinished+=("OriginTracePairedBrowserCDHash in ${plist}")
if ((${#unfinished[@]})); then
  echo "The paired browser pin is unfinished. Fill these reviewed values:" >&2
  printf '  %s\n' "${unfinished[@]}" >&2
  exit 1
fi

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "The paired Brave artifact requires an arm64 macOS runner." >&2
  exit 1
fi

# Reuse the published browser bytes only while every browser input and wire
# contract still matches the commit that built them.
if ! git cat-file -e "${build_source}^{commit}" 2>/dev/null; then
  echo "Browser build commit ${build_source} is not in this checkout's history." >&2
  exit 1
fi
git diff --exit-code "${build_source}" -- \
  browser include src protocol services \
  scripts/bootstrap-brave.sh scripts/brave-toolchain.sh \
  scripts/build-brave-distribution.sh scripts/build-integrated-brave.sh \
  scripts/package-brave-distribution.sh scripts/sync-browser-integration.sh

readonly release_root=build/release-pair
if [[ -e "${release_root}" ]]; then
  echo "Refusing to overwrite an existing paired release directory." >&2
  exit 1
fi
mkdir -p "${release_root}/source"
curl --fail --location --silent --show-error --retry 3 \
  "${source_url}/${brave_name}.zip" -o "${release_root}/source/${brave_name}.zip"
curl --fail --location --silent --show-error --retry 3 \
  "${source_url}/${brave_name}.provenance.json" -o "${release_root}/source/${brave_name}.provenance.json"
(
  cd "${release_root}/source"
  printf '%s  %s\n' \
    "${brave_sha256}" "${brave_name}.zip" \
    "${provenance_sha256}" "${brave_name}.provenance.json" |
    shasum -a 256 --check
)
ditto -x -k "${release_root}/source/${brave_name}.zip" "${release_root}/extracted"
readonly app="${release_root}/extracted/Brave Browser Development.app"
codesign --verify --deep --strict "${app}"
cdhash="$(codesign -dvvv "${app}" 2>&1 | sed -n 's/^CDHash=//p')"
if [[ "${cdhash}" != "${paired_cdhash}" ]]; then
  echo "Extracted Brave CDHash ${cdhash:-<none>} differs from ${plist} (${paired_cdhash})." >&2
  exit 1
fi
"${app}/Contents/MacOS/Brave Browser Development" --version
