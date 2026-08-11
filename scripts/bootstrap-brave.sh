#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly default_remote="https://github.com/brave/brave-core.git"
readonly revision_file="${repository_root}/browser/config/brave-core.rev"
readonly minimum_init_free_gib=150

if [[ -z "${DEVELOPER_DIR:-}" ]] &&
   [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi

brave_remote="${REB_BRAVE_CORE_REMOTE:-${default_remote}}"
brave_revision="${REB_BRAVE_CORE_REVISION:-$(tr -d '[:space:]' < "${revision_file}")}"
run_init=false
use_shallow_history=true

usage() {
  echo "Usage: $0 [--remote URL] [--revision REF] [--init] [--full-history]"
  echo
  echo "Prepares the pinned upstream Brave checkout at browser/worktree/src/brave."
  echo "The --init flag runs Brave initialization with shallow Chromium history."
  echo "Use --full-history with --init only when complete Chromium Git history is required."
}

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
    --full-history)
      use_shallow_history=false
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

if [[ "${use_shallow_history}" == false && "${run_init}" == false ]]; then
  echo "--full-history requires --init" >&2
  exit 2
fi

readonly worktree_root="${REB_BRAVE_WORKTREE:-${repository_root}/browser/worktree}"
readonly brave_directory="${worktree_root}/src/brave"
brave_fetch_remote="origin"

if [[ -e "${brave_directory}" ]]; then
  if ! is_git_checkout_root "${brave_directory}"; then
    echo "Existing path is not a Git checkout: ${brave_directory}" >&2
    exit 1
  fi

  brave_fetch_remote="$(
    git -C "${brave_directory}" remote -v |
      awk -v requested_url="${brave_remote}" \
        '$2 == requested_url && $3 == "(fetch)" {print $1; exit}'
  )"
  if [[ -z "${brave_fetch_remote}" ]]; then
    echo "Existing brave-core checkout does not reference the requested remote." >&2
    echo "Requested: ${brave_remote}" >&2
    exit 1
  fi

  echo "Using existing brave-core checkout: ${brave_directory}"
else
  mkdir -p "${worktree_root}/src"
  git -C "${worktree_root}/src" init -q brave
  git -C "${brave_directory}" remote add origin "${brave_remote}"
fi

git -C "${brave_directory}" fetch --quiet --depth 1 \
  "${brave_fetch_remote}" "${brave_revision}"
requested_commit="$(git -C "${brave_directory}" rev-parse 'FETCH_HEAD^{commit}')"
readonly requested_commit

if [[ -n "$(git -C "${brave_directory}" status --porcelain)" ]]; then
  current_commit="$(git -C "${brave_directory}" rev-parse HEAD)"
  if [[ "${current_commit}" != "${requested_commit}" ]]; then
    echo "Brave checkout has local changes at a different revision." >&2
    echo "Current: ${current_commit}" >&2
    echo "Requested: ${requested_commit}" >&2
    echo "Preserve or remove the local changes before switching revisions." >&2
    exit 1
  fi
  echo "Brave checkout has local integration changes at the requested revision."
else
  git -C "${brave_directory}" checkout --quiet --detach "${requested_commit}"
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
  if ! command -v corepack >/dev/null 2>&1 &&
     ! command -v pnpm >/dev/null 2>&1; then
    echo "Corepack or pnpm is required for Brave initialization." >&2
    exit 1
  fi
  (
    cd "${brave_directory}"
    # Chromium must become its own repository at worktree/src. Without this
    # ceiling, Git can mistake the enclosing application repository for the
    # Chromium checkout before gclient has created src/.git.
    export GIT_CEILING_DIRECTORIES="${repository_root}"
    declare -a init_arguments=(run init)
    if [[ "${use_shallow_history}" == true ]]; then
      init_arguments+=(-- --no-history)
    fi
    if command -v corepack >/dev/null 2>&1; then
      corepack pnpm "${init_arguments[@]}"
    else
      pnpm "${init_arguments[@]}"
    fi
  )
else
  echo "Chromium has not been downloaded. Run this script with --init when ready."
fi

echo "Apply tracked project changes with ./scripts/sync-browser-integration.sh"
