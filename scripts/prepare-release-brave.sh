#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "The paired Brave artifact requires an arm64 macOS runner." >&2
  exit 1
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
cd "${repository_root}"

# Reuse the published browser bytes only while every browser input and wire
# contract still matches their recorded build. This is not a new Brave build.
readonly build_source=f706286fb80ae60f0be5ae54260e781a70900adf
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
readonly previous_name=Brave-Browser-Development-v0.3.0-macos-arm64
readonly source_url=https://github.com/sunghoojung/reverse-engineering-browser/releases/download/v0.3.0
curl --fail --location --silent --show-error --retry 3 \
  "${source_url}/${previous_name}.zip" -o "${release_root}/source/${previous_name}.zip"
curl --fail --location --silent --show-error --retry 3 \
  "${source_url}/${previous_name}.provenance.json" -o "${release_root}/source/${previous_name}.provenance.json"
(
  cd "${release_root}/source"
  printf '%s  %s\n' \
    07209f53456ab30fc4ad6c6d6028daf56f0251c0910e15b5b1dc441f2c8469af "${previous_name}.zip" \
    8101ff5fe36a2f97e0363913ac6ef9469cd3acf19fecefd73d616f1f0b4ef01c "${previous_name}.provenance.json" \
    | shasum -a 256 --check
)
ditto -x -k "${release_root}/source/${previous_name}.zip" "${release_root}/extracted"
readonly app="${release_root}/extracted/Brave Browser Development.app"
codesign --verify --deep --strict "${app}"
"${app}/Contents/MacOS/Brave Browser Development" --version
