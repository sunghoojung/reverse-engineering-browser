#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root

if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: REB_BRAVE_DIRECTORY=/path/to/src/brave REB_BRAVE_JOBS=8 $0 [--verify-only]"
  echo "Build a self-contained, non-official macOS arm64 research browser."
  exit 0
fi
verify_only=false
if [[ "${1:-}" == "--verify-only" ]] && (($# == 1)); then
  verify_only=true
elif (($# != 0)); then
  echo "Unexpected argument: $1" >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin ]]; then
  echo "The Brave distribution build requires macOS." >&2
  exit 1
fi

readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
readonly brave_jobs="${REB_BRAVE_JOBS:-8}"
if [[ ! "${brave_jobs}" =~ ^[1-9][0-9]*$ ]]; then
  echo "REB_BRAVE_JOBS must be a positive integer." >&2
  exit 2
fi
if [[ ! -d "${brave_directory}" ]]; then
  echo "Pinned Brave checkout is missing: ${brave_directory}" >&2
  exit 1
fi
if ! command -v sccache >/dev/null 2>&1; then
  echo "sccache is required for the distribution build." >&2
  exit 1
fi

chromium_directory="$(cd "${brave_directory}/.." && pwd)"
readonly chromium_directory
v8_directory="${chromium_directory}/v8"
readonly v8_directory

verify_pin() {
  local checkout_directory="$1"
  local pin_file="$2"
  local pin
  local expected
  local actual
  pin="$(tr -d '[:space:]' <"${repository_root}/${pin_file}")"
  if ! expected="$(git -C "${checkout_directory}" rev-parse "${pin}^{commit}" 2>/dev/null)" ||
    ! actual="$(git -C "${checkout_directory}" rev-parse HEAD 2>/dev/null)" ||
    [[ "${actual}" != "${expected}" ]]; then
    echo "Checkout does not match ${pin_file}: ${checkout_directory}" >&2
    exit 1
  fi
}

verify_pin "${brave_directory}" browser/config/brave-core.rev
verify_pin "${chromium_directory}" browser/config/chromium.rev
verify_pin "${v8_directory}" browser/config/v8.rev

overlay_directory="${repository_root}/browser/integration/brave/overlay"
readonly overlay_directory
while IFS= read -r -d '' authored_file; do
  relative_path="${authored_file#"${overlay_directory}/"}"
  if ! cmp -s "${authored_file}" "${brave_directory}/${relative_path}"; then
    echo "Brave overlay is not synchronized: ${relative_path}" >&2
    exit 1
  fi
done < <(find "${overlay_directory}" -type f -print0)

if [[ "${verify_only}" == true ]]; then
  echo "Pinned Brave, Chromium, V8, and authored overlays match."
  exit 0
fi

# Static keeps all Chromium code inside the app instead of referring to the
# component build's out-of-bundle dylibs. The development channel and disabled
# updater prevent a stock Brave update from replacing the research probes.
export REB_BRAVE_DIRECTORY="${brave_directory}"
export SISO_LIMITS="${SISO_LIMITS:-local=${brave_jobs}}"
exec "${repository_root}/scripts/brave-toolchain.sh" build Static \
  --target_arch arm64 \
  --skip_signing \
  --gn cc_wrapper:sccache \
  --gn symbol_level:0 \
  --gn blink_symbol_level:0 \
  --gn v8_symbol_level:0 \
  --gn use_lld:false \
  --gn use_clang_modules:false \
  --gn enable_sparkle:false \
  --gn enable_updater:false \
  --ninja "j:${brave_jobs}"
