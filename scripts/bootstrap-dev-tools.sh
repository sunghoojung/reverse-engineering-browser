#!/usr/bin/env bash

set -euo pipefail

readonly tools_root="${REB_DEV_TOOLS_DIR:-${XDG_DATA_HOME:-${HOME}/.local/share}/reb-tools}"
readonly clang_format_version="18.1.8"
readonly ruff_version="0.12.8"

python_tools_ready=0
if [[ -x "${tools_root}/bin/clang-format" && -x "${tools_root}/bin/ruff" ]] &&
   "${tools_root}/bin/clang-format" --version | grep -Fq "version ${clang_format_version}" &&
   [[ "$("${tools_root}/bin/ruff" --version)" == "ruff ${ruff_version}" ]]; then
  python_tools_ready=1
fi

if ((python_tools_ready == 0)); then
  command -v python3 >/dev/null 2>&1 || {
    echo "Python 3 is required to install the pinned REB developer tools." >&2
    exit 1
  }
  python3 -m venv "${tools_root}"
  "${tools_root}/bin/python" -m pip install --disable-pip-version-check \
    "clang-format==${clang_format_version}" \
    "ruff==${ruff_version}"
fi

missing_formulae=()
command -v shellcheck >/dev/null 2>&1 || missing_formulae+=(shellcheck)
command -v actionlint >/dev/null 2>&1 || missing_formulae+=(actionlint)

if ((${#missing_formulae[@]} > 0)); then
  if ! command -v brew >/dev/null 2>&1; then
    printf 'Homebrew is required to install missing tools:' >&2
    printf ' %s' "${missing_formulae[@]}" >&2
    printf '\n' >&2
    exit 1
  fi

  echo "Installing missing REB developer tools: ${missing_formulae[*]}"
  brew install "${missing_formulae[@]}"
fi

for command_name in shellcheck actionlint; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "${command_name} is still unavailable after installation" >&2
    exit 1
  }
done

echo "REB developer tools are ready in ${tools_root}/bin and Homebrew."
