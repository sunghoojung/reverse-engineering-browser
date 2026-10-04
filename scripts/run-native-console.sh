#!/usr/bin/env bash
set -euo pipefail
# Give the disposable browser its own job process group, including descendants.
set -m

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
readonly console_binary="${REB_CONSOLE_BINARY:-${repository_root}/build/reb-console}"
readonly brave_binary="${REB_BRAVE_BINARY:-}"
readonly console_repl="${REB_CONSOLE_REPL:-1}"
if [[ -z "${brave_binary}" || ! -x "${brave_binary}" || ! -x "${console_binary}" ]]; then
  echo "Set REB_BRAVE_BINARY to the rebuilt Brave executable and run make native-console." >&2
  exit 2
fi
if [[ "${console_repl}" != 0 && "${console_repl}" != 1 ]]; then
  echo "REB_CONSOLE_REPL must be 0 or 1." >&2
  exit 2
fi

# A fresh profile is the experiment boundary. Never reuse baseline cookies,
# storage, credentials, or a pre-existing research session.
umask 077
session_directory="$(mktemp -d /tmp/reb-console.XXXXXXXX)"
readonly session_directory
browser_pid=""
cleanup() {
  if [[ -n "${browser_pid}" ]]; then
    kill -- "-${browser_pid}" 2>/dev/null || true
    for _ in {1..30}; do
      kill -0 -- "-${browser_pid}" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 -- "-${browser_pid}" 2>/dev/null; then
      kill -KILL -- "-${browser_pid}" 2>/dev/null || true
    fi
    wait "${browser_pid}" 2>/dev/null || true
  fi
  rm -rf "${session_directory}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "${session_directory}/token" <<'PY'
import os
import secrets
import sys

with os.fdopen(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as token:
    token.write(secrets.token_hex(32) + "\n")
PY

echo "Opening a disposable native-console browser. Page commands may change its state." >&2
"${brave_binary}" \
  --user-data-dir="${session_directory}/profile" \
  --no-first-run \
  --no-default-browser-check \
  --password-store=basic \
  --use-mock-keychain \
  --reb-native-console \
  --reb-native-console-socket="${session_directory}/console.sock" \
  --reb-native-console-token-file="${session_directory}/token" \
  --reb-native-console-session-id=1 \
  about:blank >"${session_directory}/browser.log" 2>&1 &
browser_pid="$!"

console_arguments=(--socket "${session_directory}/console.sock" --token-file "${session_directory}/token" --session 1)
if [[ "${console_repl}" == 1 ]]; then
  console_arguments+=(--repl)
fi
"${console_binary}" "${console_arguments[@]}"
