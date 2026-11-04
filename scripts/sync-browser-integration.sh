#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
chromium_directory="$(cd "${brave_directory}/.." 2>/dev/null && pwd)" || chromium_directory=""
readonly chromium_directory
readonly v8_directory="${chromium_directory}/v8"
readonly integration_directory="${REB_BRAVE_INTEGRATION_DIRECTORY:-${repository_root}/browser/integration/brave}"
readonly overlay_directory="${integration_directory}/overlay"
readonly patches_directory="${integration_directory}/patches"
readonly patch_contract="${repository_root}/tools/brave_patch_contract.py"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3.8 or newer is required to validate independent patch ownership." >&2
  exit 1
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else "Python 3.8 or newer is required")'
readonly brave_revision="${REB_BRAVE_CORE_REVISION:-$(
  tr -d '[:space:]' <"${repository_root}/browser/config/brave-core.rev"
)}"
readonly chromium_revision="${REB_CHROMIUM_REVISION:-$(
  tr -d '[:space:]' <"${repository_root}/browser/config/chromium.rev"
)}"
readonly v8_revision="${REB_V8_REVISION:-$(
  tr -d '[:space:]' <"${repository_root}/browser/config/v8.rev"
)}"

is_git_checkout_root() {
  local candidate_directory="$1"
  local canonical_directory
  local discovered_root
  [[ -d "${candidate_directory}" ]] || return 1
  canonical_directory="$(cd "${candidate_directory}" && pwd -P)" || return 1
  discovered_root="$(
    git -C "${canonical_directory}" rev-parse --show-toplevel 2>/dev/null
  )" || return 1
  discovered_root="$(cd "${discovered_root}" && pwd -P)" || return 1
  [[ "${canonical_directory}" == "${discovered_root}" ]]
}

if ! is_git_checkout_root "${brave_directory}"; then
  echo "Brave checkout is missing: ${brave_directory}" >&2
  echo "Run ./scripts/bootstrap-brave.sh first." >&2
  exit 1
fi

declare -a brave_patch_files=()
while IFS= read -r -d '' patch_file; do
  brave_patch_files+=("${patch_file}")
done < <(find "${patches_directory}" -maxdepth 1 -type f -name '*.patch' -print0 | sort -z)

readonly chromium_patches_directory="${patches_directory}/chromium"
declare -a chromium_patch_files=()
if [[ -d "${chromium_patches_directory}" ]]; then
  while IFS= read -r -d '' patch_file; do
    chromium_patch_files+=("${patch_file}")
  done < <(find "${chromium_patches_directory}" -maxdepth 1 -type f \
    -name '*.patch' -print0 | sort -z)
fi

readonly v8_patches_directory="${patches_directory}/v8"
declare -a v8_patch_files=()
if [[ -d "${v8_patches_directory}" ]]; then
  while IFS= read -r -d '' patch_file; do
    v8_patch_files+=("${patch_file}")
  done < <(find "${v8_patches_directory}" -maxdepth 1 -type f \
    -name '*.patch' -print0 | sort -z)
fi

if ((${#chromium_patch_files[@]} > 0)); then
  if ! is_git_checkout_root "${chromium_directory}"; then
    echo "Chromium checkout is missing: ${chromium_directory}" >&2
    echo "Run ./scripts/bootstrap-brave.sh --init first." >&2
    exit 1
  fi
fi
if ((${#v8_patch_files[@]} > 0)) && ! is_git_checkout_root "${v8_directory}"; then
  echo "V8 checkout is missing: ${v8_directory}" >&2
  echo "Run ./scripts/bootstrap-brave.sh --init first." >&2
  exit 1
fi

verify_revision() {
  local checkout_directory="$1"
  local checkout_label="$2"
  local expected_revision="$3"
  local expected_commit
  local current_commit
  if ! expected_commit="$(
    git -C "${checkout_directory}" rev-parse --verify "${expected_revision}^{commit}" 2>/dev/null
  )"; then
    echo "Pinned ${checkout_label} revision is unavailable: ${expected_revision}" >&2
    echo "Initialize the pinned checkout before synchronizing." >&2
    exit 1
  fi
  if ! current_commit="$(
    git -C "${checkout_directory}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null
  )"; then
    echo "${checkout_label} checkout has no checked out commit: ${checkout_directory}" >&2
    exit 1
  fi
  if [[ "${current_commit}" != "${expected_commit}" ]]; then
    echo "${checkout_label} checkout revision does not match the pin." >&2
    echo "Current: ${current_commit}" >&2
    echo "Pinned ${expected_revision}: ${expected_commit}" >&2
    echo "Local checkout state was not changed." >&2
    exit 1
  fi
}

# Serialize every change to these upstream checkouts. The integrated build
# wrapper already holds the lock and passes its descriptor down; it also owns
# the source receipt, so a sync it starts leaves receipts to it.
lock_path="$(python3 "${patch_contract}" lock-path --brave "${brave_directory}")"
guarded_by_caller=false
if [[ -n "${REB_BRAVE_SOURCE_LOCK_FD:-}" ]]; then
  if [[ ! "${REB_BRAVE_SOURCE_LOCK_FD}" =~ ^[0-9]+$ ]]; then
    echo "REB_BRAVE_SOURCE_LOCK_FD must name an open descriptor." >&2
    exit 2
  fi
  guarded_by_caller=true
else
  exec 9<"${lock_path}"
  export REB_BRAVE_SOURCE_LOCK_FD=9
fi
python3 "${patch_contract}" lock --brave "${brave_directory}" --fd "${REB_BRAVE_SOURCE_LOCK_FD}"

# A checkout recorded by the integrated build stays provable: a direct sync
# (make browser-sync, brave-toolchain.sh gen/probe-check/foundation-check)
# passes the same state check, names its expected result before changing
# anything, and records it afterwards, or refuses.
readonly state_helper="${repository_root}/tools/check-integrated-brave-state.py"
readonly state_arguments=(--repository "${repository_root}" --brave "${brave_directory}"
  --receipt "${repository_root}/build/integrated-brave-state.json")
guarded_sync=false
recorded_checkout=false
if [[ "${guarded_by_caller}" == false ]]; then
  recorded_checkout="$(python3 "${state_helper}" guarded "${state_arguments[@]}")"
fi
if [[ "${recorded_checkout}" == true ]]; then
  for variable in REB_BRAVE_CORE_REVISION REB_CHROMIUM_REVISION REB_V8_REVISION \
    REB_BRAVE_INTEGRATION_DIRECTORY; do
    if [[ -n "${!variable:-}" ]]; then
      echo "Unset ${variable}: build/integrated-brave-state.json records this checkout from the tracked pins and integration." >&2
      exit 2
    fi
  done
  guarded_sync=true
fi

verify_revision "${brave_directory}" "Brave" "${brave_revision}"
if ((${#chromium_patch_files[@]} > 0)); then
  verify_revision "${chromium_directory}" "Chromium" "${chromium_revision}"
fi
if ((${#v8_patch_files[@]} > 0)); then
  verify_revision "${v8_directory}" "V8" "${v8_revision}"
fi

# A nested Git checkout is an independent patch owner. Validate every stack
# before planning or applying any patch.
if ((${#brave_patch_files[@]} > 0)); then
  python3 "${patch_contract}" verify --checkout "${brave_directory}" "${brave_patch_files[@]}"
fi
if ((${#chromium_patch_files[@]} > 0)); then
  python3 "${patch_contract}" verify --checkout "${chromium_directory}" "${chromium_patch_files[@]}"
fi
if ((${#v8_patch_files[@]} > 0)); then
  python3 "${patch_contract}" verify --checkout "${v8_directory}" "${v8_patch_files[@]}"
fi

# Each checkout must hold an ordered prefix of its stack: an interrupted sync
# leaves one, and the next sync resumes from it. Anything else, such as a later
# patch applied without an earlier one, stops here before any file changes.
plan_patches() {
  local checkout_directory="$1"
  local patch_label="$2"
  shift 2
  local applied
  if ! applied="$(python3 "${patch_contract}" plan --checkout "${checkout_directory}" "$@")"; then
    echo "${patch_label}patch stack state is not resumable; no file was changed." >&2
    exit 1
  fi
  printf '%s\n' "${applied}"
}

# A failed git apply writes nothing, so the stack stays an ordered prefix that
# the next sync resumes from. Nothing is reversed or rolled back.
apply_remaining_patches() {
  local checkout_directory="$1"
  local patch_label="$2"
  local applied="$3"
  shift 3
  local total=$#
  local patch_file
  local index=0
  if ((applied == total)); then
    echo "Already applied: ${patch_label}patch stack"
    return
  fi
  for patch_file in "$@"; do
    if ((index >= applied)); then
      if ! git -C "${checkout_directory}" apply "${patch_file}"; then
        echo "${patch_label}patch did not apply: ${patch_file}" >&2
        echo "The ${patch_label}stack holds the first ${index} of ${total} patches. Inspect the checkout; a rerun resumes from that prefix." >&2
        exit 1
      fi
    fi
    index=$((index + 1))
  done
  echo "Applied ${patch_label}patches $((applied + 1)) through ${total} of ${total}."
}

sync_brave_siso_config() {
  local source_file="${brave_directory}/build/config/siso/brave_siso_config.star"
  local destination_file="${chromium_directory}/build/config/siso/brave_siso_config.star"

  # Chromium's Siso entrypoint loads this Brave-owned module from the Chromium
  # root, while brave-core tracks the authoritative copy under brave/. Keep the
  # generated root copy in lockstep after applying the Brave patch stack.
  if [[ ! -f "${source_file}" || ! -d "${chromium_directory}/build/config/siso" ]]; then
    return
  fi
  if [[ ! -e "${destination_file}" ]]; then
    cp "${source_file}" "${destination_file}"
  elif ! cmp -s "${source_file}" "${destination_file}"; then
    cp "${source_file}" "${destination_file}"
  fi
}

brave_applied=0
if ((${#brave_patch_files[@]} > 0)); then
  brave_applied="$(plan_patches "${brave_directory}" "Brave " "${brave_patch_files[@]}")"
fi
chromium_applied=0
if ((${#chromium_patch_files[@]} > 0)); then
  chromium_applied="$(plan_patches "${chromium_directory}" "Chromium " "${chromium_patch_files[@]}")"
fi
v8_applied=0
if ((${#v8_patch_files[@]} > 0)); then
  v8_applied="$(plan_patches "${v8_directory}" "V8 " "${v8_patch_files[@]}")"
fi

if [[ "${guarded_sync}" == true ]]; then
  # Name the expected result before the first change, so an interrupted sync
  # can be resumed and its result verified instead of abandoning the checkout.
  python3 "${state_helper}" begin --phase sync "${state_arguments[@]}"
fi

if [[ -d "${overlay_directory}" ]]; then
  cp -Rp "${overlay_directory}/." "${brave_directory}/"
fi

if ((${#brave_patch_files[@]} > 0)); then
  apply_remaining_patches "${brave_directory}" "Brave " "${brave_applied}" "${brave_patch_files[@]}"
fi
if ((${#chromium_patch_files[@]} > 0)); then
  apply_remaining_patches "${chromium_directory}" "Chromium " "${chromium_applied}" "${chromium_patch_files[@]}"
fi
if ((${#v8_patch_files[@]} > 0)); then
  apply_remaining_patches "${v8_directory}" "V8 " "${v8_applied}" "${v8_patch_files[@]}"
fi

sync_brave_siso_config

if [[ "${guarded_sync}" == true ]]; then
  python3 "${state_helper}" record "${state_arguments[@]}"
fi

echo "Synchronized Brave integration (${#brave_patch_files[@]} Brave patch(es), ${#chromium_patch_files[@]} Chromium patch(es), ${#v8_patch_files[@]} V8 patch(es))."
