#!/usr/bin/env bash

set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd "${script_dir}/.." && pwd)"
readonly default_remote="https://github.com/sunghoojung/reverse-engineering-browser-core.git"
readonly upstream_remote="https://github.com/brave/brave-core.git"
readonly revision_file="${repository_root}/browser/config/brave-core.rev"
readonly minimum_init_free_gib=150

brave_remote="${REB_BRAVE_CORE_REMOTE:-${default_remote}}"
brave_revision="${REB_BRAVE_CORE_REVISION:-$(tr -d '[:space:]' < "${revision_file}")}"
run_init=false

usage() {
  echo "Usage: $0 [--remote URL] [--revision REF] [--init]"
  echo
  echo "Initializes brave-core at browser/worktree/src/brave."
  echo "The --init flag also runs pnpm run init and begins the large Chromium download."
}

while (($# > 0)); do
  case "$1" in
    --remote)
      if (($# < 2)); then
        echo "--remote requires a URL" >&2
        exit 2
      fi
      brave_remote="$2"
      shift 2
      ;;
    --revision)
      if (($# < 2)); then
        echo "--revision requires a branch, tag, or commit" >&2
        exit 2
      fi
      brave_revision="$2"
      shift 2
      ;;
    --init)
      run_init=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

readonly worktree_root="${REB_BRAVE_WORKTREE:-${repository_root}/browser/worktree}"
readonly brave_directory="${worktree_root}/src/brave"

if [[ -e "${brave_directory}" ]]; then
  if ! git -C "${brave_directory}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Existing path is not a Git checkout: ${brave_directory}" >&2
    exit 1
  fi

  existing_remote="$(git -C "${brave_directory}" remote get-url origin)"
  if [[ "${existing_remote}" != "${brave_remote}" ]]; then
    echo "Existing brave-core origin does not match the requested remote." >&2
    echo "Existing:  ${existing_remote}" >&2
    echo "Requested: ${brave_remote}" >&2
    exit 1
  fi

  echo "Using existing brave-core checkout: ${brave_directory}"
else
  mkdir -p "${worktree_root}/src"
  if [[ "${brave_remote}" == "${default_remote}" ]] &&
     git -C "${repository_root}" config --file .gitmodules \
       --get-regexp '^submodule\..*\.path$' 2>/dev/null |
       grep -q 'browser/worktree/src/brave'; then
    git -C "${repository_root}" submodule update --init --depth 1 \
      --recommend-shallow browser/worktree/src/brave
  else
    git clone --depth 1 --branch "${brave_revision}" "${brave_remote}" "${brave_directory}"
  fi
fi

if [[ "${brave_revision}" != "master" ]] &&
   ! git -C "${brave_directory}" merge-base --is-ancestor HEAD "${brave_revision}" 2>/dev/null; then
  git -C "${brave_directory}" fetch origin "${brave_revision}"
  git -C "${brave_directory}" checkout --detach FETCH_HEAD
fi

if [[ "${brave_remote}" != "${upstream_remote}" ]] &&
   ! git -C "${brave_directory}" remote get-url upstream >/dev/null 2>&1; then
  git -C "${brave_directory}" remote add upstream "${upstream_remote}"
fi

if git -C "${brave_directory}" remote get-url upstream >/dev/null 2>&1; then
  git -C "${brave_directory}" remote set-url --push upstream DISABLED
fi

echo "brave-core is ready at ${brave_directory}"

if [[ "${run_init}" == true ]]; then
  available_kib="$(df -Pk "${worktree_root}" | awk 'NR == 2 {print $4}')"
  required_kib=$((minimum_init_free_gib * 1024 * 1024))
  if ((available_kib < required_kib)); then
    available_gib=$((available_kib / 1024 / 1024))
    echo "Brave initialization requires at least ${minimum_init_free_gib} GiB free." >&2
    echo "Only ${available_gib} GiB is currently available." >&2
    exit 1
  fi
  if ! command -v pnpm >/dev/null 2>&1; then
    echo "pnpm is required for Brave initialization but is not installed." >&2
    exit 1
  fi
  (
    cd "${brave_directory}"
    # Chromium must become its own repository at worktree/src. Without this
    # ceiling, Git can mistake the enclosing application repository for the
    # Chromium checkout before gclient has created src/.git.
    export GIT_CEILING_DIRECTORIES="${repository_root}"
    pnpm run init
  )
else
  echo "Chromium has not been downloaded. Run this script with --init when ready."
fi
