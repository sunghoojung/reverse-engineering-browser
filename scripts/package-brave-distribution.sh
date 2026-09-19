#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root

if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: REB_BRAVE_DIRECTORY=/path/to/src/brave $0 v0.1.4"
  echo "Verify, ad-hoc sign, and archive the macOS arm64 static build."
  exit 0
fi
if (($# != 1)) || [[ ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Expected one version tag such as v0.1.4." >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  echo "macOS packaging requires macOS." >&2
  exit 1
fi

readonly version="$1"
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
readonly output_directory="${REB_BRAVE_DISTRIBUTION_DIRECTORY:-${repository_root}/build}"
readonly build_directory="${brave_directory}/../out/Static_arm64"
readonly app_name="Brave Browser Development.app"
readonly app_path="${build_directory}/${app_name}"
readonly executable_name="Brave Browser Development"
readonly gn_args="${build_directory}/args_generated.gni"
readonly archive="${output_directory}/Brave-Browser-Development-${version}-macos-arm64.zip"

if [[ ! -d "${app_path}" || ! -f "${gn_args}" ]]; then
  echo "The Static_arm64 browser build is missing: ${build_directory}" >&2
  exit 1
fi

required_args=(
  'is_component_build=false'
  'is_official_build=false'
  'is_debug=false'
  'target_cpu="arm64"'
  'brave_channel="development"'
  'skip_signing=true'
  'enable_updater=false'
  'enable_sparkle=false'
)
for required_arg in "${required_args[@]}"; do
  if ! grep -Fxq "${required_arg}" "${gn_args}"; then
    echo "Distribution build argument is missing: ${required_arg}" >&2
    exit 1
  fi
done
if [[ -e "${archive}" ]]; then
  echo "Refusing to replace existing archive: ${archive}" >&2
  exit 1
fi

mkdir -p "${output_directory}"
temporary_directory="$(mktemp -d "${output_directory}/.reb-brave-package.XXXXXX")"
readonly temporary_directory
trap 'rm -rf "${temporary_directory}"' EXIT
readonly signed_app="${temporary_directory}/${app_name}"
readonly extracted_directory="${temporary_directory}/extracted"
staged_archive="${temporary_directory}/$(basename "${archive}")"
readonly staged_archive

ditto "${app_path}" "${signed_app}"
codesign --force --deep --sign - "${signed_app}"
codesign --verify --deep --strict "${signed_app}"
canonical_app="$(realpath "${signed_app}")"
readonly canonical_app

while IFS= read -r -d '' link_path; do
  if ! resolved_path="$(realpath "${link_path}")" ||
    [[ "${resolved_path}" != "${canonical_app}/"* ]]; then
    echo "App bundle contains an external or broken symlink: ${link_path}" >&2
    exit 1
  fi
done < <(find "${signed_app}" -type l -print0)

# A component build can appear healthy in its output directory while an
# extracted ZIP fails to load. Always validate the archive in isolation.
mkdir -p "${extracted_directory}"
ditto -c -k --sequesterRsrc --keepParent "${signed_app}" "${staged_archive}"
ditto -x -k "${staged_archive}" "${extracted_directory}"
codesign --verify --deep --strict "${extracted_directory}/${app_name}"
"${extracted_directory}/${app_name}/Contents/MacOS/${executable_name}" --version
if [[ -e "${archive}" ]]; then
  echo "Refusing to replace existing archive: ${archive}" >&2
  exit 1
fi
mv -n "${staged_archive}" "${archive}"
if [[ -e "${staged_archive}" ]]; then
  echo "Archive appeared while packaging; preserved the existing file." >&2
  exit 1
fi
shasum -a 256 "${archive}"
