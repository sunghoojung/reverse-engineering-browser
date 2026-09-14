#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
chromium_directory="$(cd "${brave_directory}/.." 2>/dev/null && pwd)" || chromium_directory=""
readonly chromium_directory
readonly integration_directory="${REB_BRAVE_INTEGRATION_DIRECTORY:-${repository_root}/browser/integration/brave}"
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

patch_stack_is_applied() {
  local checkout_directory="$1"
  shift
  local temporary_directory
  local temporary_index
  local -a patch_files=("$@")
  local patch_index
  temporary_directory="$(mktemp -d)"
  temporary_index="${temporary_directory}/index"

  if ! GIT_INDEX_FILE="${temporary_index}" git -C "${checkout_directory}" read-tree HEAD ||
    ! GIT_INDEX_FILE="${temporary_index}" git -C "${checkout_directory}" add -u; then
    rm -rf "${temporary_directory}"
    return 1
  fi
  for ((patch_index = ${#patch_files[@]} - 1; patch_index >= 0; patch_index--)); do
    if ! GIT_INDEX_FILE="${temporary_index}" git -C "${checkout_directory}" \
      apply --cached --reverse --check "${patch_files[patch_index]}" 2>/dev/null; then
      rm -rf "${temporary_directory}"
      return 1
    fi
    GIT_INDEX_FILE="${temporary_index}" git -C "${checkout_directory}" \
      apply --cached --reverse "${patch_files[patch_index]}"
  done
  rm -rf "${temporary_directory}"
}

preflight_patches() {
  local checkout_directory="$1"
  local patch_label="$2"
  shift 2
  local patch_file
  local needs_stack_refresh=0
  for patch_file in "$@"; do
    if git -C "${checkout_directory}" apply --check "${patch_file}" 2>/dev/null; then
      continue
    elif git -C "${checkout_directory}" apply --reverse --check \
      "${patch_file}" 2>/dev/null; then
      continue
    else
      needs_stack_refresh=1
      break
    fi
  done
  if ((needs_stack_refresh == 0)); then
    return
  fi

  if patch_stack_is_applied "${checkout_directory}" "$@"; then
    echo "Already applied: ${patch_label}patch stack"
    return 11
  fi

  # A later patch can deliberately edit lines introduced by an earlier one.
  # In an already-synchronized checkout that makes the earlier patch neither
  # forward- nor reverse-applicable. Remove the applied stack from newest to
  # oldest, verify the complete stack can be applied again, and roll back if
  # any patch is not reproducible.
  local -a patch_files=("$@")
  local -a reversed_patch_files=()
  local -a reapplied_patch_files=()
  local patch_index
  for ((patch_index = ${#patch_files[@]} - 1; patch_index >= 0; patch_index--)); do
    patch_file="${patch_files[patch_index]}"
    if git -C "${checkout_directory}" apply --reverse --check "${patch_file}" 2>/dev/null; then
      git -C "${checkout_directory}" apply --reverse "${patch_file}"
      reversed_patch_files+=("${patch_file}")
    fi
  done

  for patch_file in "${patch_files[@]}"; do
    if ! git -C "${checkout_directory}" apply --check "${patch_file}" 2>/dev/null; then
      for ((patch_index = ${#reapplied_patch_files[@]} - 1; patch_index >= 0; patch_index--)); do
        git -C "${checkout_directory}" apply --reverse "${reapplied_patch_files[patch_index]}"
      done
      for ((patch_index = ${#reversed_patch_files[@]} - 1; patch_index >= 0; patch_index--)); do
        git -C "${checkout_directory}" apply "${reversed_patch_files[patch_index]}"
      done
      echo "${patch_label}patch does not apply cleanly: ${patch_file}" >&2
      exit 1
    fi
    git -C "${checkout_directory}" apply "${patch_file}"
    reapplied_patch_files+=("${patch_file}")
  done

  echo "Refreshed ${patch_label}patch stack to preflight overlapping changes."
  return 10
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

brave_stack_refreshed=0
if preflight_patches "${brave_directory}" "" "${brave_patch_files[@]}"; then
  :
else
  preflight_status=$?
  if ((preflight_status != 10 && preflight_status != 11)); then
    exit "${preflight_status}"
  fi
  brave_stack_refreshed=1
fi
chromium_stack_refreshed=0
if ((${#chromium_patch_files[@]} > 0)); then
  if preflight_patches "${chromium_directory}" "Chromium " "${chromium_patch_files[@]}"; then
    :
  else
    preflight_status=$?
    if ((preflight_status != 10 && preflight_status != 11)); then
      exit "${preflight_status}"
    fi
    chromium_stack_refreshed=1
  fi
fi

if [[ -d "${overlay_directory}" ]]; then
  cp -R "${overlay_directory}/." "${brave_directory}/"
fi

if ((brave_stack_refreshed == 0)); then
  apply_patches "${brave_directory}" "" "${brave_patch_files[@]}"
fi
if ((${#chromium_patch_files[@]} > 0 && chromium_stack_refreshed == 0)); then
  apply_patches "${chromium_directory}" "chromium/" "${chromium_patch_files[@]}"
fi

echo "Synchronized Brave integration (${#brave_patch_files[@]} Brave patch(es), ${#chromium_patch_files[@]} Chromium patch(es))."
