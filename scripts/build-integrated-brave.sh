#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root

usage() {
  echo "Usage: $0 [--init]"
  echo "Build the integrated macOS arm64 development browser and Origin Trace companion."
  echo "--init downloads/initializes the pinned Brave, Chromium and V8 checkout first."
  echo "Requires full Xcode; first/init builds need 150 GiB free (200–250 GiB recommended)."
  echo "Does not activate dormant native worker or proxy foundations."
}
initialize=false
case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --init) initialize=true; shift ;;
esac
if (($# != 0)); then
  usage >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "This integrated build path requires Apple silicon macOS and full Xcode." >&2
  exit 1
fi
if [[ -z "${DEVELOPER_DIR:-}" && -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi
if ! xcodebuild -version >/dev/null 2>&1 || ! xcodebuild -license check >/dev/null 2>&1; then
  echo "Full Xcode with its license already accepted is required; set DEVELOPER_DIR if needed." >&2
  exit 1
fi
for executable in git make python3 cargo c++; do
  if ! command -v "${executable}" >/dev/null 2>&1; then
    echo "Required tool is missing: ${executable}" >&2
    exit 1
  fi
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else "Python 3.8 or newer is required")'
for variable in REB_BRAVE_CORE_REMOTE REB_BRAVE_CORE_REVISION REB_CHROMIUM_REVISION \
  REB_V8_REVISION REB_BRAVE_INTEGRATION_DIRECTORY REB_BRAVE_OUTPUT_DIRECTORY; do
  if [[ -n "${!variable:-}" ]]; then
    echo "Unset ${variable}: this entrypoint uses the tracked pins, integration and Component_arm64 output." >&2
    exit 2
  fi
done
if [[ -n "${REB_BRAVE_JOBS:-}" && ! "${REB_BRAVE_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "REB_BRAVE_JOBS must be a positive integer." >&2
  exit 2
fi
readonly worktree="${REB_BRAVE_WORKTREE:-${repository_root}/browser/worktree}"
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${worktree}/src/brave}"
if [[ "${initialize}" == true && "${brave_directory}" != "${worktree}/src/brave" ]]; then
  echo "For --init, set REB_BRAVE_WORKTREE and leave REB_BRAVE_DIRECTORY unset." >&2
  exit 2
fi
export REB_BRAVE_DIRECTORY="${brave_directory}"
cd "${repository_root}"
echo "Integration commit: $(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Use a clean integration checkout so the build has a reproducible source identity." >&2
  exit 1
fi
state_arguments=(--repository "${repository_root}" --brave "${brave_directory}"
  --receipt "${repository_root}/build/integrated-brave-state.json")
# Check the destination filesystem before bootstrap downloads anything.
disk_path="${brave_directory}"
while [[ ! -d "${disk_path}" ]]; do
  disk_path="$(dirname "${disk_path}")"
done
available_kib="$(df -Pk "${disk_path}" | awk 'NR == 2 {print $4}')"
if [[ "${initialize}" == true ]]; then
  required_kib="$(python3 tools/check-integrated-brave-state.py reserve "${state_arguments[@]}" --require-clean)"
else
  required_kib="$(python3 tools/check-integrated-brave-state.py reserve "${state_arguments[@]}")"
fi
if [[ ! "${available_kib}" =~ ^[0-9]+$ || ! "${required_kib}" =~ ^[0-9]+$ ]] ||
   ((available_kib < required_kib)); then
  echo "Insufficient disk reserve: need ${required_kib} KiB free on the Brave build filesystem." >&2
  echo "First/init builds reserve 150 GiB; verified repeats reserve max(50 GiB, existing output size)." >&2
  exit 1
fi
if [[ "${initialize}" == true ]]; then
  python3 tools/check-integrated-brave-state.py check "${state_arguments[@]}" --require-clean
else
  python3 tools/check-integrated-brave-state.py check "${state_arguments[@]}"
fi
if [[ "${initialize}" == true ]]; then
  ./scripts/bootstrap-brave.sh --init
  # Initialization's own patches become the known input to the next sync.
  python3 tools/check-integrated-brave-state.py record "${state_arguments[@]}"
fi
make brave-doctor
python3 tools/check-integrated-brave-state.py check "${state_arguments[@]}"
./scripts/sync-browser-integration.sh
python3 tools/check-integrated-brave-state.py record "${state_arguments[@]}"
make demo native-probe-admission-check native-proxy-policy-check
./build/reb-event-demo
# Let Brave generate its component args before the direct GN object/test checks.
if [[ -n "${REB_BRAVE_JOBS:-}" ]]; then
  ./scripts/brave-toolchain.sh build --ninja "j:${REB_BRAVE_JOBS}"
else
  ./scripts/brave-toolchain.sh build
fi
# Includes the Console runtime object, worker objects, and the separate proxy test.
test -f "${brave_directory}/../out/Component_arm64/args.gn"
python3 tools/check-integrated-brave-state.py check "${state_arguments[@]}"
make brave-foundation-check
make app-build native-console-check
codesign --verify --deep --strict "build/Origin Trace.app"
python3 tools/check-integrated-brave-state.py complete "${state_arguments[@]}"
echo "Build steps passed. Complete the runtime checklist in docs/development/integrated-brave-build.md."
echo "This is a local component browser plus an Origin Trace companion, not a portable release."
