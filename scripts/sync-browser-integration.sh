#!/usr/bin/env bash

set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd "${script_dir}/.." && pwd)"
readonly brave_directory="${REB_BRAVE_DIRECTORY:-${repository_root}/browser/worktree/src/brave}"
readonly integration_directory="${repository_root}/browser/integration/brave"
readonly overlay_directory="${integration_directory}/overlay"
readonly patches_directory="${integration_directory}/patches"

if ! git -C "${brave_directory}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Brave checkout is missing: ${brave_directory}" >&2
  echo "Run ./scripts/bootstrap-brave.sh first." >&2
  exit 1
fi

if [[ -d "${overlay_directory}" ]]; then
  cp -R "${overlay_directory}/." "${brave_directory}/"
fi

patch_count=0
while IFS= read -r -d '' patch_file; do
  patch_count=$((patch_count + 1))
  if git -C "${brave_directory}" apply --check "${patch_file}" 2>/dev/null; then
    git -C "${brave_directory}" apply "${patch_file}"
  elif git -C "${brave_directory}" apply --reverse --check \
    "${patch_file}" 2>/dev/null; then
    echo "Already applied: $(basename "${patch_file}")"
  else
    echo "Patch does not apply cleanly: ${patch_file}" >&2
    exit 1
  fi
done < <(find "${patches_directory}" -maxdepth 1 -type f -name '*.patch' -print0 | sort -z)

echo "Synchronized Brave integration (${patch_count} patch file(s))."
