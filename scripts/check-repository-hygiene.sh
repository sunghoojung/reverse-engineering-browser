#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly maximum_tracked_file_size=$((2 * 1024 * 1024))

cd "${repository_root}"

if [[ -n "$(git ls-files browser/worktree)" ]]; then
  echo "browser/worktree contains tracked files" >&2
  exit 1
fi

brave_revision="$(tr -d '[:space:]' <browser/config/brave-core.rev)"
chromium_revision="$(tr -d '[:space:]' <browser/config/chromium.rev)"
if [[ ! "${brave_revision}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "browser/config/brave-core.rev is not a pinned Brave release" >&2
  exit 1
fi
if [[ ! "${chromium_revision}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "browser/config/chromium.rev is not a pinned Chromium release" >&2
  exit 1
fi

while IFS= read -r patch_file; do
  if ! git apply --numstat "${patch_file}" >/dev/null; then
    echo "Malformed patch: ${patch_file}" >&2
    exit 1
  fi
done < <(git ls-files 'browser/integration/brave/patches/*.patch' \
  'browser/integration/brave/patches/**/*.patch')

while IFS= read -r tracked_file; do
  file_size="$(git cat-file -s ":${tracked_file}")"
  if ((file_size > maximum_tracked_file_size)); then
    echo "Tracked file exceeds 2 MiB: ${tracked_file} (${file_size} bytes)" >&2
    exit 1
  fi
done < <(git ls-files)

readonly secret_pattern='-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}'
if git grep -IEn -- "${secret_pattern}" -- . \
  ':(exclude)scripts/check-repository-hygiene.sh'; then
  echo "A tracked file contains a high-confidence secret pattern" >&2
  exit 1
fi

echo "Repository hygiene check passed"
