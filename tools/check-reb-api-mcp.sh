#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
readonly launcher="${repository_root}/scripts/reb-api-mcp.sh"
readonly chooser="${script_dir}/check-reb-api-mcp.py"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
home="${tmp}/home"
root="${tmp}/sessions"
log="${tmp}/log"
out="${tmp}/out"
err="${tmp}/err"
mkdir -p "$home" "$root"
cat >"${tmp}/reb-api" <<'EOF'
#!/bin/sh
if [ -n "${REB_API_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$REB_API_LOG"
fi
exit 0
EOF
chmod 755 "${tmp}/reb-api"
fake="${tmp}/reb-api"

write_session() {
  local id=$1
  local url=$2
  mkdir -p "${root}/${id}"
  printf '%s\n' "$url" >"${root}/${id}/research-ui.endpoint"
}

run_launcher() {
  rm -f "$log" "$out" "$err"
  set +e
  env -u REB_LIVE_SESSION_ROOT \
    HOME="$home" \
    REB_API="$fake" \
    REB_API_LOG="$log" \
    "$launcher" "$@" >"$out" 2>"$err"
  status=$?
  set -e
}

assert_status() {
  local expected=$1
  [[ "$status" == "$expected" ]] || fail "status ${status}, expected ${expected}; stderr=$(cat "$err"); stdout=$(cat "$out")"
}

assert_log_absent() {
  [[ ! -e "$log" ]] || fail "reb-api was started: $(cat "$log")"
}

assert_stderr_has() {
  grep -q -F -- "$1" "$err" || fail "stderr missing [$1]: $(cat "$err")"
}

assert_stdout_lacks() {
  if grep -q -F -- "$1" "$out"; then
    fail "stdout contained [$1]: $(cat "$out")"
  fi
}

write_session 2 'http://127.0.0.1:9'
write_session 10 'http://127.0.0.1:10'
# 10 is newer. Listing must stay numeric and must not launch reb-api.
touch -d '2020-01-01T00:00:00Z' "${root}/2/research-ui.endpoint" || touch -t 202001010000 "${root}/2/research-ui.endpoint"
touch "${root}/10/research-ui.endpoint"

"$launcher" --help >"$out"
grep -q -F -- '--allow-effects' "$out"
grep -q -F -- 'not authorization' "$out"
grep -q -F -- 'newest' "$out"

run_launcher
assert_status 2
assert_log_absent
assert_stderr_has '.config/origin-trace/reb-api.endpoint'

canonical="${home}/.config/origin-trace/reb-api.endpoint"
mkdir -p "$(dirname "$canonical")"
printf 'http://127.0.0.1:11\n' >"$canonical"
for client in cursor grok codex claude t3; do
  run_launcher --print-config "$client"
  assert_status 0
  grep -q -F -- "$canonical" "$out" || fail "$client did not use canonical file"
  grep -q -F -- '--require-live' "$out" || fail "$client did not require live capture"
  assert_stdout_lacks '"--allow-effects"'
  assert_stdout_lacks 'http://127.0.0.1:11'
done
run_launcher
assert_status 0
grep -q -F -- "mcp --endpoint-file ${canonical} --require-live" "$log" || fail "canonical default was not forwarded"
printf 'http://example.test:11\n' >"$canonical"
run_launcher
assert_status 2
assert_log_absent
assert_stderr_has 'loopback'
printf 'http://127.0.0.1:11\n' >"$canonical"

run_launcher --sessions-root "$root"
assert_status 2
assert_log_absent
assert_stderr_has 'exactly one'
assert_stderr_has 'No session was selected'

run_launcher --list --sessions-root "$root"
assert_status 0
assert_log_absent
assert_stderr_has 'No session was selected'
[[ "$(sed -n '1p' "$out")" == "2"$'\t'"${root}/2/research-ui.endpoint" ]] || fail "list order: $(cat "$out")"
[[ "$(sed -n '2p' "$out")" == "10"$'\t'"${root}/10/research-ui.endpoint" ]] || fail "list order: $(cat "$out")"

run_launcher --session-id 10 --sessions-root "$root"
assert_status 0
grep -q -F -- "--endpoint-file ${root}/10/research-ui.endpoint" "$log" || fail "log=$(cat "$log")"
if grep -q -F -- "${root}/2/research-ui.endpoint" "$log"; then
  fail "selected the other session: $(cat "$log")"
fi
if grep -q -F -- '--allow-effects' "$log"; then
  fail "effects were enabled by default: $(cat "$log")"
fi

run_launcher --session-id 10 --sessions-root "$root" --allow-effects
assert_status 0
grep -q -F -- '--allow-effects' "$log" || fail "effects flag was not forwarded: $(cat "$log")"

run_launcher --session-dir "${root}/2"
assert_status 0
grep -q -F -- "--endpoint-file ${root}/2/research-ui.endpoint" "$log" || fail "log=$(cat "$log")"
if grep -q -F -- "${root}/10/" "$log"; then
  fail "session-dir consulted another session: $(cat "$log")"
fi

run_launcher --session-id 11 --sessions-root "$root"
assert_status 2
assert_log_absent
assert_stderr_has 'does not exist'
assert_stderr_has 'No other session was selected'

ln -s "${root}/2" "${root}/3"
run_launcher --session-id 3 --sessions-root "$root"
assert_status 2
assert_log_absent
assert_stderr_has 'symlink'
run_launcher --list --sessions-root "$root"
assert_status 0
if grep -q -F -- "${root}/3/" "$out"; then
  fail "list included a symlink session: $(cat "$out")"
fi

printf '%s\n' 'http://127.0.0.1:9/?native=1' >"${tmp}/handshake"
run_launcher --endpoint-file "${tmp}/handshake"
assert_status 2
assert_log_absent
assert_stderr_has 'research-ui.endpoint'
assert_stdout_lacks 'native=1'
if grep -q -F -- 'native=1' "$err"; then
  fail "handshake query was echoed: $(cat "$err")"
fi

quoted="${tmp}/session dir"
mkdir -p "$quoted"
printf '%s\n' 'http://127.0.0.1:9' >"${quoted}/research-ui.endpoint"
run_launcher --print-config cursor --session-dir "$quoted" --allow-effects
assert_status 0
assert_stderr_has 'not authorization'
assert_stdout_lacks 'http://127.0.0.1:9'
REB_CONFIG_STDOUT="$out" REB_ENDPOINT_FILE="${quoted}/research-ui.endpoint" REB_LAUNCHER="$launcher" python3 - <<'PY'
import json, os
doc = json.loads(open(os.environ["REB_CONFIG_STDOUT"], encoding="utf-8").read())
server = doc["mcpServers"]["origin-trace"]
assert server["command"] == os.environ["REB_LAUNCHER"]
args = server["args"]
assert args[args.index("--endpoint-file") + 1] == os.environ["REB_ENDPOINT_FILE"]
assert "--allow-effects" in args
assert "mcp" not in args
PY

run_launcher --print-config cursor --endpoint-file "${root}/2/research-ui.endpoint"
assert_status 0
assert_stderr_has 'Read-only tool list'
python3 -c 'import json,sys; args=json.load(open(sys.argv[1], encoding="utf-8"))["mcpServers"]["origin-trace"]["args"]; assert "--allow-effects" not in args' "$out"

run_launcher --print-config codex --endpoint-file "${root}/2/research-ui.endpoint" --allow-effects
assert_status 0
grep -q -F -- '[mcp_servers.origin-trace]' "$out" || fail "codex config: $(cat "$out")"
grep -q -F -- '--allow-effects' "$out" || fail "codex config omitted effects: $(cat "$out")"
assert_stdout_lacks 'experimental_environment'

run_launcher --print-config grok --endpoint-file "${root}/2/research-ui.endpoint" --allow-effects
assert_status 0
grep -q -F -- "command: ${launcher}" "$out" || fail "grok config: $(cat "$out")"
assert_stderr_has "bot's computer"
assert_stderr_has 'not authorization'

run_launcher --print-config t3 --endpoint-file "${root}/2/research-ui.endpoint" --allow-effects
assert_status 0
grep -q -F -- 'Shared MCP' "$out" || fail "t3 config: $(cat "$out")"
grep -q -F -- 'Do not paste the loopback' "$out" || fail "t3 config: $(cat "$out")"
grep -q -F -- '[mcp_servers.origin-trace]' "$out" || fail "t3 config: $(cat "$out")"
grep -q -F -- '"mcpServers"' "$out" || fail "t3 config: $(cat "$out")"

run_launcher --print-config claude --endpoint-file "${root}/2/research-ui.endpoint" --allow-effects
assert_status 0
assert_stderr_has 'Claude Code'
python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$out"

cat >"${tmp}/old-reb-api" <<'EOF'
#!/bin/sh
exit 2
EOF
chmod 755 "${tmp}/old-reb-api"
run_launcher --reb-api "${tmp}/old-reb-api" --endpoint-file "${root}/2/research-ui.endpoint"
assert_status 2
assert_stderr_has 'does not provide the mcp command'

REB_MCP_TEST_HOME="$home" python3 "$chooser" "$launcher" "$root" "$log" "$fake" "" >"$out" 2>"$err" || choose_status=$?
choose_status=${choose_status:-0}
[[ "$choose_status" != 0 ]] || fail "empty choose succeeded: $(cat "$err") $(cat "$out")"
[[ ! -s "$log" ]] || fail "empty choose started reb-api: $(cat "$log")"

REB_MCP_TEST_HOME="$home" python3 "$chooser" "$launcher" "$root" "$log" "$fake" "2" >"$out"
grep -q -F -- "--endpoint-file ${root}/2/research-ui.endpoint" "$log" || fail "choose log=$(cat "$log")"
if grep -q -F -- "${root}/10/research-ui.endpoint" "$log"; then
  fail "choose selected the newer session: $(cat "$log")"
fi

checkout="${repository_root}/build/sessions/live"
created_checkout=0
if [[ ! -d "$checkout" ]]; then
  mkdir -p "$checkout"
  created_checkout=1
fi
packaged="${home}/Library/Application Support/Origin Trace/sessions/live"
mkdir -p "$packaged"
run_launcher --list
assert_status 2
assert_log_absent
assert_stderr_has 'Both the packaged'
if [[ "$created_checkout" == 1 ]]; then
  rmdir "$checkout" || true
  rmdir "${repository_root}/build/sessions" || true
fi

printf 'wrapper checks passed\n'
