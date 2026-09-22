#!/usr/bin/env bash

set -euo pipefail

missing_formulae=()
command -v clang-format >/dev/null 2>&1 || missing_formulae+=(clang-format)
command -v shellcheck >/dev/null 2>&1 || missing_formulae+=(shellcheck)
command -v actionlint >/dev/null 2>&1 || missing_formulae+=(actionlint)

if ((${#missing_formulae[@]} == 0)); then
  echo "REB developer tools are already installed."
  exit 0
fi

if ! command -v brew >/dev/null 2>&1; then
  printf 'Homebrew is required to install missing tools:' >&2
  printf ' %s' "${missing_formulae[@]}" >&2
  printf '\n' >&2
  exit 1
fi

echo "Installing missing REB developer tools: ${missing_formulae[*]}"
brew install "${missing_formulae[@]}"

for command_name in clang-format shellcheck actionlint; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "${command_name} is still unavailable after installation" >&2
    exit 1
  }
done

echo "REB developer tools are ready."
