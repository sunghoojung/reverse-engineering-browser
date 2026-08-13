#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
chromium_directory="$(cd "${brave_directory}/.." 2>/dev/null && pwd)" || chromium_directory=""
readonly chromium_directory
readonly integration_directory="${repository_root}/browser/integration/brave"
readonly overlay_directory="${integration_directory}/overlay"
readonly patches_directory="${integration_directory}/patches"
readonly brave_revision="${REB_BRAVE_CORE_REVISION:-$(
  tr -d '[:space:]' <"${repository_root}/browser/config/brave-core.rev"
)}"
readonly chromium_revision="${REB_CHROMIUM_REVISION:-$(
  tr -d '[:space:]' <"${repository_root}/browser/config/chromium.rev"
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

if ((${#chromium_patch_files[@]} > 0)); then
  if ! is_git_checkout_root "${chromium_directory}"; then
    echo "Chromium checkout is missing: ${chromium_directory}" >&2
    echo "Run ./scripts/bootstrap-brave.sh --init first." >&2
    exit 1
  fi
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

verify_revision "${brave_directory}" "Brave" "${brave_revision}"
if ((${#chromium_patch_files[@]} > 0)); then
  verify_revision "${chromium_directory}" "Chromium" "${chromium_revision}"
fi

preflight_patches() {
  local checkout_directory="$1"
  local patch_label="$2"
  shift 2
  local patch_file
  for patch_file in "$@"; do
    if git -C "${checkout_directory}" apply --check "${patch_file}" 2>/dev/null; then
      continue
    elif git -C "${checkout_directory}" apply --reverse --check \
      "${patch_file}" 2>/dev/null; then
      continue
    else
      echo "${patch_label}patch does not apply cleanly: ${patch_file}" >&2
      exit 1
    fi
  done
}

apply_patches() {
  local checkout_directory="$1"
  local patch_prefix="$2"
  shift 2
  local patch_file
  for patch_file in "$@"; do
    if git -C "${checkout_directory}" apply --check "${patch_file}" 2>/dev/null; then
      git -C "${checkout_directory}" apply "${patch_file}"
    elif git -C "${checkout_directory}" apply --reverse --check \
      "${patch_file}" 2>/dev/null; then
      echo "Already applied: ${patch_prefix}$(basename "${patch_file}")"
    else
      echo "Patch state changed after preflight: ${patch_file}" >&2
      exit 1
    fi
  done
}

preflight_patches "${brave_directory}" "" "${brave_patch_files[@]}"
preflight_patches "${chromium_directory}" "Chromium " "${chromium_patch_files[@]}"

if [[ -d "${overlay_directory}" ]]; then
  cp -R "${overlay_directory}/." "${brave_directory}/"
fi

apply_patches "${brave_directory}" "" "${brave_patch_files[@]}"
apply_patches "${chromium_directory}" "chromium/" "${chromium_patch_files[@]}"

echo "Synchronized Brave integration (${#brave_patch_files[@]} Brave patch(es), ${#chromium_patch_files[@]} Chromium patch(es))."
