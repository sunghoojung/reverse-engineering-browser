#!/usr/bin/env bash

# Fast format and lint for files changed since the merge base with the
# default branch, plus unstaged and staged edits. This does not run Clippy
# or the native test gate. TYPECHECK=1 adds cargo check when Rust changed.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

base=""
if git rev-parse --verify --quiet origin/main >/dev/null; then
  base="$(git merge-base HEAD origin/main)"
elif git rev-parse --verify --quiet main >/dev/null; then
  base="$(git merge-base HEAD main)"
fi

changed="$(mktemp)"
trap 'rm -f "${changed}"' EXIT
{
  if [[ -n "${base}" ]]; then
    git diff --name-only "${base}"
  fi
  git diff --name-only
  git diff --name-only --cached
  git ls-files --others --exclude-standard
} | awk 'NF && !seen[$0]++' > "${changed}"

if [[ ! -s "${changed}" ]]; then
  echo "agent-preflight: no changed files"
  exit 0
fi

echo "agent-preflight: checking"
cat "${changed}"

pick() {
  local pattern="$1"
  grep -E "${pattern}" "${changed}" || true
}

failed=0
note_failure() {
  echo "agent-preflight: $1" >&2
  failed=1
}

cpp_files="$(pick '\.(c|cc|cpp|h|hpp)$')"
if [[ -n "${cpp_files}" ]]; then
  if ! command -v clang-format >/dev/null 2>&1; then
    note_failure "clang-format is not installed"
  else
    # shellcheck disable=SC2086
    clang-format --dry-run --Werror ${cpp_files}
  fi
fi

py_files="$(pick '\.py$')"
if [[ -n "${py_files}" ]]; then
  if command -v ruff >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    ruff check ${py_files}
  elif python3 -m ruff --version >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    python3 -m ruff check ${py_files}
  else
    note_failure "ruff is not installed"
  fi
fi

js_files="$(pick '\.(js|mjs|cjs)$')"
if [[ -n "${js_files}" ]]; then
  if ! command -v node >/dev/null 2>&1; then
    note_failure "node is not installed"
  else
    while IFS= read -r source; do
      [[ -n "${source}" ]] || continue
      node --check "${source}"
    done <<< "${js_files}"
  fi
fi

workflow_files="$(pick '^\.github/(workflows|actions)/')"
if [[ -n "${workflow_files}" ]]; then
  if command -v actionlint >/dev/null 2>&1; then
    actionlint
  else
    echo "agent-preflight: actionlint is not installed; CI runs it" >&2
  fi
fi

sh_files="$(pick '\.sh$')"
if [[ -n "${sh_files}" ]]; then
  if ! command -v shellcheck >/dev/null 2>&1; then
    note_failure "shellcheck is not installed"
  else
    # shellcheck disable=SC2086
    shellcheck ${sh_files}
  fi
fi

if grep -q '^apps/origin-trace-backend/.*\.rs$' "${changed}" \
  || grep -q '^apps/origin-trace-backend/Cargo\.toml$' "${changed}"; then
  cargo fmt --check --manifest-path apps/origin-trace-backend/Cargo.toml
  if [[ "${TYPECHECK:-}" == "1" ]]; then
    cargo check --locked --manifest-path apps/origin-trace-backend/Cargo.toml
  fi
fi
if grep -q '^apps/deobfuscator-worker/.*\.rs$' "${changed}" \
  || grep -q '^apps/deobfuscator-worker/Cargo\.toml$' "${changed}"; then
  cargo fmt --check --manifest-path apps/deobfuscator-worker/Cargo.toml
  if [[ "${TYPECHECK:-}" == "1" ]]; then
    cargo check --locked --manifest-path apps/deobfuscator-worker/Cargo.toml
  fi
fi

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
echo "agent-preflight: passed"
