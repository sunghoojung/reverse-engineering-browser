#!/usr/bin/env bash

set -euo pipefail
umask 077

# Launch the only Origin Trace MCP server: `reb-api mcp`.
# After a successful health check, stdin and stdout are the stdio channel.
# Diagnostics stay on stderr. This script never selects the newest session.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root
script_path="${script_dir}/$(basename "${BASH_SOURCE[0]}")"
readonly script_path

endpoint_file=""
session_dir=""
session_id=""
sessions_root=""
base_url=""
allow_effects=0
require_live=0
timeout=""
mode="serve"
print_target=""
reb_api="${REB_API:-}"
reb_api_from_flag=0
selection_kind=""
selection_value=""
mcp_exec_args=()

die() {
  printf 'reb-api-mcp: %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Usage: reb-api-mcp.sh [--endpoint-file FILE | --session-dir DIR | --session-id ID | --base-url URL] [options]
       reb-api-mcp.sh --list [--sessions-root DIR]
       reb-api-mcp.sh --choose [--sessions-root DIR]
       reb-api-mcp.sh --print-config cursor|claude|codex|grok|t3 [--endpoint-file FILE | ...]

Resolve one researcher-selected Origin Trace endpoint and exec `reb-api mcp`.
The default tool list is read-only. `--allow-effects` also lists operations
that can change browser or stored state. That flag is not authorization,
capture redaction, or permission to send captured data to a model provider.

Without an endpoint selection, use ~/.config/origin-trace/reb-api.endpoint
and require live capture with a running or paused debugger. The live launcher
publishes this canonical file. Each reconnect reads it again. An existing MCP
connection refuses changed/missing endpoint files; it never retargets a call.

A single session, the newest directory, or a native
handshake URL with a query is not chosen for you. `--session-id` reads
`<sessions-root>/<id>/research-ui.endpoint`. Packaged sessions normally live
under ~/Library/Application Support/Origin Trace/sessions/live. A checkout
`make live` session uses build/sessions/live unless REB_LIVE_SESSION_ROOT is
set. If both roots exist, pass --sessions-root.

`--list` and `--choose` never start the server. `--choose` reads one session
id from a terminal. MCP client configs use the canonical default or an explicit
endpoint selection, because the client's stdin is the MCP channel.

`reb-api mcp` requests /api/health before advertising tools. The health
document names local store paths and is not printed. Health is reachability,
not proof of capture identity or permission to share evidence.

The stdio process must run on the same computer as the selected loopback API.
Grok Bot custom MCP runs on the bot's computer. A Mac live session is reached
from Cursor on that Mac, or from a backend on the same host as the bot.

Options:
  --allow-effects       Advertise effectful operations. Not authorization.
  --require-live        Refuse idle capture or a disconnected native capture broker.
                        get_session_context remains readable after startup until
                        the endpoint file or backend instance changes.
  --timeout SECONDS     Passed through to reb-api (default 30).
  --sessions-root DIR   Exact live-session parent directory.
  --reb-api PATH        reb-api or packaged OriginTraceAPI binary.
  --list                Print selectable session ids and endpoint files.
  --choose              Ask for a session id in the terminal, then serve.
  --print-config TARGET Print Cursor, Claude, Codex, Grok Bot, or T3 config.
EOF
}

loopback_text_ok() {
  local content=$1
  local port
  [[ -n "$content" && "$content" != *$'\n'* ]] || return 1
  [[ "$content" =~ ^http://(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})/?$ ]] || return 1
  port="${BASH_REMATCH[2]}"
  [[ "$port" == 0* ]] && return 1
  ((10#$port >= 1 && 10#$port <= 65535)) || return 1
}

file_contains_nul() {
  local file=$1
  local raw_size stripped_size
  raw_size="$(wc -c <"$file")"
  raw_size="${raw_size//[[:space:]]/}"
  stripped_size="$(tr -d '\0' <"$file" | wc -c)"
  stripped_size="${stripped_size//[[:space:]]/}"
  [[ "$raw_size" != "$stripped_size" ]]
}

endpoint_file_is_loopback() {
  local file=$1
  local size content
  [[ -f "$file" ]] || return 1
  size="$(wc -c <"$file")"
  size="${size//[[:space:]]/}"
  [[ "$size" -le 1024 ]] || return 1
  if file_contains_nul "$file"; then
    return 1
  fi
  content="$(<"$file")"
  content="${content//$'\r'/}"
  if [[ "$content" == *$'\n' ]]; then
    content="${content%$'\n'}"
  fi
  loopback_text_ok "$content"
}

require_endpoint_file() {
  local file=$1
  local size content
  if [[ ! -e "$file" ]]; then
    die "Endpoint file does not exist: ${file}. No other session was selected."
  fi
  if [[ ! -f "$file" ]]; then
    die "Endpoint path is not a file: ${file}."
  fi
  size="$(wc -c <"$file")"
  size="${size//[[:space:]]/}"
  if [[ "$size" -gt 1024 ]]; then
    die "Endpoint file ${file} is larger than 1024 bytes. No tools were advertised."
  fi
  if file_contains_nul "$file"; then
    die "Endpoint file ${file} must contain one HTTP loopback root URL. No tools were advertised."
  fi
  content="$(<"$file")"
  content="${content//$'\r'/}"
  if [[ "$content" == *$'\n' ]]; then
    content="${content%$'\n'}"
  fi
  if ! loopback_text_ok "$content"; then
    die "Endpoint file ${file} is not an HTTP loopback server root with a port. A native UI URL with a query is not the API root. Use research-ui.endpoint. No tools were advertised."
  fi
}

resolve_sessions_root() {
  local packaged checkout packaged_exists=0 checkout_exists=0
  if [[ -n "$sessions_root" ]]; then
    printf '%s' "$sessions_root"
    return
  fi
  if [[ -n "${REB_LIVE_SESSION_ROOT:-}" ]]; then
    printf '%s' "$REB_LIVE_SESSION_ROOT"
    return
  fi
  packaged="${HOME:-}/Library/Application Support/Origin Trace/sessions/live"
  checkout="${repository_root}/build/sessions/live"
  if [[ -d "$packaged" ]]; then
    packaged_exists=1
  fi
  if [[ -d "$checkout" ]]; then
    checkout_exists=1
  fi
  if [[ "$packaged_exists" == 1 && "$checkout_exists" == 1 ]]; then
    die "Both the packaged Origin Trace session root and this checkout's build/sessions/live exist. Pass --sessions-root or set REB_LIVE_SESSION_ROOT. No session was selected."
  fi
  if [[ "$packaged_exists" == 1 ]]; then
    printf '%s' "$packaged"
    return
  fi
  if [[ "$checkout_exists" == 1 ]]; then
    printf '%s' "$checkout"
    return
  fi
  die "No live session root exists. Pass --sessions-root or --endpoint-file. No session was selected."
}

list_session_rows() {
  local root=$1
  local dir id file skipped=0
  local -a rows=()
  local restore_nullglob=0
  if [[ ! -d "$root" ]]; then
    die "Session root does not exist: ${root}. No session was selected."
  fi
  if ! shopt -q nullglob; then
    shopt -s nullglob
    restore_nullglob=1
  fi
  for dir in "$root"/*; do
    if [[ -L "$dir" || ! -d "$dir" ]]; then
      continue
    fi
    id="$(basename "$dir")"
    if [[ ! "$id" =~ ^[1-9][0-9]{0,19}$ ]]; then
      continue
    fi
    file="${dir}/research-ui.endpoint"
    if [[ ! -f "$file" ]]; then
      continue
    fi
    if ! endpoint_file_is_loopback "$file"; then
      skipped=$((skipped + 1))
      continue
    fi
    rows+=("${id}"$'\t'"${file}")
  done
  if [[ "$restore_nullglob" == 1 ]]; then
    shopt -u nullglob
  fi
  if [[ "$skipped" -gt 0 ]]; then
    printf 'Skipped %s session directories whose research-ui.endpoint is not one loopback root.\n' "$skipped" >&2
  fi
  if [[ ${#rows[@]} -gt 0 ]]; then
    printf '%s\n' "${rows[@]}" | LC_ALL=C sort -n -k1,1
  fi
}

selected_endpoint_file() {
  local count=0 root dir
  if [[ -n "$endpoint_file" ]]; then
    count=$((count + 1))
  fi
  if [[ -n "$session_dir" ]]; then
    count=$((count + 1))
  fi
  if [[ -n "$session_id" ]]; then
    count=$((count + 1))
  fi
  if [[ -n "$base_url" ]]; then
    count=$((count + 1))
  fi
  if [[ "$count" == 0 && -z "$sessions_root" ]]; then
    [[ -n "${HOME:-}" ]] || die "HOME is unavailable. Pass --endpoint-file explicitly."
    endpoint_file="${HOME}/.config/origin-trace/reb-api.endpoint"
    require_live=1
    count=1
  fi
  if [[ "$count" -ne 1 ]]; then
    die "Pass exactly one of --endpoint-file, --session-dir, --session-id, or --base-url. No session was selected."
  fi
  if [[ -n "$base_url" ]]; then
    if ! loopback_text_ok "$base_url"; then
      die "Base URL is not an HTTP loopback server root with a port. No session was selected."
    fi
    selection_kind="url"
    selection_value="$base_url"
    return
  fi
  if [[ -n "$endpoint_file" ]]; then
    selection_kind="file"
    selection_value="$endpoint_file"
    return
  fi
  if [[ -n "$session_dir" ]]; then
    if [[ -L "$session_dir" ]]; then
      die "Session directory is a symlink: ${session_dir}. Pass the selected directory itself. No other session was selected."
    fi
    if [[ ! -d "$session_dir" ]]; then
      die "Session directory does not exist: ${session_dir}. No other session was selected."
    fi
    selection_kind="file"
    selection_value="${session_dir}/research-ui.endpoint"
    return
  fi
  if [[ ! "$session_id" =~ ^[1-9][0-9]{0,19}$ ]]; then
    die "Session id must be the nonzero decimal directory name. No session was selected."
  fi
  root="$(resolve_sessions_root)"
  dir="${root}/${session_id}"
  if [[ -L "$dir" ]]; then
    die "Session directory is a symlink: ${dir}. No session was selected."
  fi
  if [[ ! -d "$dir" ]]; then
    die "Session directory does not exist: ${dir}. No other session was selected."
  fi
  selection_kind="file"
  selection_value="${dir}/research-ui.endpoint"
}

resolve_reb_api() {
  local candidate
  local -a candidates=()
  if [[ -n "$reb_api" ]]; then
    printf '%s' "$reb_api"
    return
  fi
  candidates=(
    "${repository_root}/apps/origin-trace-backend/target/debug/reb-api"
    "${repository_root}/apps/origin-trace-backend/target/release/reb-api"
    "${repository_root}/build/Origin Trace.app/Contents/MacOS/OriginTraceAPI"
    "/Applications/Origin Trace.app/Contents/MacOS/OriginTraceAPI"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  done
  die "reb-api was not found. Run make origin-trace-backend or set REB_API to the built binary or OriginTraceAPI."
}

require_mcp_binary() {
  local binary=$1
  if [[ ! -x "$binary" ]]; then
    die "reb-api is not executable: ${binary}. Run make origin-trace-backend or set REB_API."
  fi
  if ! "$binary" mcp --help </dev/null >/dev/null 2>&1; then
    die "reb-api at ${binary} does not provide the mcp command. Rebuild with make origin-trace-backend. On macOS, make app-build refreshes Contents/MacOS/OriginTraceAPI. No server was started."
  fi
}

build_mcp_args() {
  mcp_exec_args=(mcp)
  if [[ "$selection_kind" == file ]]; then
    mcp_exec_args+=(--endpoint-file "$selection_value")
  else
    mcp_exec_args+=(--base-url "$selection_value")
  fi
  if [[ "$allow_effects" == 1 ]]; then
    mcp_exec_args+=(--allow-effects)
  fi
  if [[ "$require_live" == 1 ]]; then
    mcp_exec_args+=(--require-live)
  fi
  if [[ -n "$timeout" ]]; then
    mcp_exec_args+=(--timeout "$timeout")
  fi
}

serve_mcp() {
  local binary
  selected_endpoint_file
  if [[ "$selection_kind" == file ]]; then
    require_endpoint_file "$selection_value"
  fi
  binary="$(resolve_reb_api)"
  require_mcp_binary "$binary"
  build_mcp_args
  exec "$binary" "${mcp_exec_args[@]}"
}

health_check() {
  local binary timeout="${timeout:-5}"
  binary="$(resolve_reb_api)"
  require_mcp_binary "$binary"
  build_mcp_args
  # MCP startup never prints the health body or local store paths. Keep its
  # bounded endpoint/state diagnostic on stderr, and never emit stdio content.
  if ! "$binary" "${mcp_exec_args[@]}" </dev/null >/dev/null; then
    die "Selected loopback API did not pass the MCP health preflight. No config was written."
  fi
}

effects_note() {
  if [[ "$allow_effects" == 1 ]]; then
    printf 'Write-capable tool list. --allow-effects is not authorization, capture redaction, or permission to send captured data to a model provider.\n' >&2
  else
    printf 'Read-only tool list. Add --allow-effects for write-capable tools. That flag is not authorization.\n' >&2
  fi
}

json_quote() {
  local value=$1
  local escaped=${value//\\/\\\\}
  escaped=${escaped//\"/\\\"}
  escaped=${escaped//$'\n'/\\n}
  escaped=${escaped//$'\r'/\\r}
  escaped=${escaped//$'\t'/\\t}
  printf '"%s"' "$escaped"
}

reject_control_chars() {
  local value=$1
  case "$value" in
  *$'\n'* | *$'\r'* | *$'\t'*)
    die "A selected path contains a control character. No config was written."
    ;;
  esac
}

print_mcp_json() {
  local arg joined=""
  local -a encoded=()
  for arg in "$@"; do
    encoded+=("$(json_quote "$arg")")
  done
  if [[ ${#encoded[@]} -gt 0 ]]; then
    joined=$(IFS=,; printf '%s' "${encoded[*]}")
  fi
  printf '{\n  "mcpServers": {\n    "origin-trace": {\n      "command": %s,\n      "args": [%s]\n    }\n  }\n}\n' \
    "$(json_quote "$script_path")" \
    "$joined"
}

print_codex_toml() {
  local arg first=1
  printf '[mcp_servers.origin-trace]\ncommand = %s\nargs = [' "$(json_quote "$script_path")"
  for arg in "$@"; do
    if [[ "$first" == 1 ]]; then
      first=0
    else
      printf ', '
    fi
    printf '%s' "$(json_quote "$arg")"
  done
  printf ']\n'
}

print_config() {
  local -a client_args=()
  build_mcp_args
  client_args=("${mcp_exec_args[@]:1}")
  reject_control_chars "$script_path"
  reject_control_chars "$selection_value"
  effects_note
  case "$print_target" in
  cursor)
    printf 'Write this object to ~/.cursor/mcp.json or .cursor/mcp.json on the session machine. Do not use --list or --choose here.\n' >&2
    print_mcp_json "${client_args[@]}"
    ;;
  claude)
    printf 'Use this object as Claude Code .mcp.json mcpServers, or the same command and args with claude mcp add --transport stdio, on the session machine.\n' >&2
    print_mcp_json "${client_args[@]}"
    ;;
  codex)
    printf 'Add this table to ~/.codex/config.toml on the session machine. Do not set experimental_environment = "remote" or a URL.\n' >&2
    print_codex_toml "${client_args[@]}"
    ;;
  grok)
    cat <<'EOF' >&2
Ask Grok Bot to add a custom stdio MCP server with AddMcpServer using this command and args, and no url.
The process runs on the bot's computer, which must host the live session. A Mac-only Origin Trace session is not reachable from a cloud bot.
EOF
    printf 'name: origin-trace\ncommand: %s\nargs:\n' "$script_path"
    local arg
    for arg in "${client_args[@]}"; do
      printf '  - %s\n' "$(json_quote "$arg")"
    done
    ;;
  t3)
    cat <<'EOF'
# T3 Code providers use the MCP configuration of the agent they launch, on the
# environment machine that hosts the live session. Do not paste the loopback
# API into Settings → Integrations → Shared MCP servers: that shipped form is
# a name, URL, and headers, and this server is stdio. If the installed build
# has a command field under Settings → Providers or environment MCP, use the
# command and args below. --allow-effects is not authorization.
#
# Codex provider: CODEX_HOME config.toml (often ~/.codex/config.toml)
EOF
    print_codex_toml "${client_args[@]}"
    printf '\n# Claude provider, and Cursor or other providers that read ~/.cursor/mcp.json\n'
    print_mcp_json "${client_args[@]}"
    ;;
  *)
    die "Unknown --print-config target. Use cursor, claude, codex, grok, or t3."
    ;;
  esac
}

run_list() {
  local root rows
  if [[ -n "$endpoint_file$session_dir$session_id$base_url" ]]; then
    die "--list does not select a session. Omit endpoint arguments, then pass the chosen id."
  fi
  root="$(resolve_sessions_root)"
  printf 'No session was selected. Pass --session-id with one id below.\n' >&2
  rows="$(list_session_rows "$root")"
  if [[ -z "$rows" ]]; then
    die "No selectable session was found under ${root}."
  fi
  printf '%s\n' "$rows"
}

run_choose() {
  local root rows choice row id file=""
  if [[ -n "$endpoint_file$session_dir$session_id$base_url" ]]; then
    die "--choose reads the id from the terminal. Omit endpoint arguments."
  fi
  if [[ ! -t 0 ]]; then
    die "--choose needs a terminal so the selection is explicit. Pass --session-id or --endpoint-file in an MCP config. No session was selected."
  fi
  root="$(resolve_sessions_root)"
  rows="$(list_session_rows "$root")"
  if [[ -z "$rows" ]]; then
    die "No selectable session was found under ${root}. No session was selected."
  fi
  printf 'Type a session id from this list. Enter alone selects nothing.\n' >&2
  printf '%s\n' "$rows" >&2
  printf 'End of session list.\n' >&2
  if ! IFS= read -r choice; then
    die "No session was selected."
  fi
  if [[ ! "$choice" =~ ^[1-9][0-9]{0,19}$ ]]; then
    die "That was not a listed session id. No session was selected."
  fi
  while IFS= read -r row; do
    id="${row%%$'\t'*}"
    if [[ "$choice" == "$id" ]]; then
      file="${row#*$'\t'}"
      break
    fi
  done <<<"$rows"
  if [[ -z "$file" ]]; then
    die "Session id ${choice} was not in the list. No session was selected."
  fi
  endpoint_file=$file
  session_dir=""
  session_id=""
  base_url=""
  serve_mcp
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --endpoint-file)
      [[ $# -ge 2 ]] || die "--endpoint-file needs a path."
      [[ -z "$endpoint_file" ]] || die "Pass --endpoint-file once."
      endpoint_file=$2
      shift 2
      ;;
    --require-live)
      require_live=1
      shift
      ;;
    --session-dir)
      [[ $# -ge 2 ]] || die "--session-dir needs a directory."
      [[ -z "$session_dir" ]] || die "Pass --session-dir once."
      session_dir=$2
      shift 2
      ;;
    --session-id)
      [[ $# -ge 2 ]] || die "--session-id needs an id."
      [[ -z "$session_id" ]] || die "Pass --session-id once."
      session_id=$2
      shift 2
      ;;
    --sessions-root)
      [[ $# -ge 2 ]] || die "--sessions-root needs a directory."
      [[ -z "$sessions_root" ]] || die "Pass --sessions-root once."
      sessions_root=$2
      shift 2
      ;;
    --base-url)
      [[ $# -ge 2 ]] || die "--base-url needs a URL."
      [[ -z "$base_url" ]] || die "Pass --base-url once."
      base_url=$2
      shift 2
      ;;
    --allow-effects)
      allow_effects=1
      shift
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "--timeout needs a number of seconds."
      [[ -z "$timeout" ]] || die "Pass --timeout once."
      timeout=$2
      [[ "$timeout" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--timeout must be a positive number of seconds."
      shift 2
      ;;
    --reb-api)
      [[ $# -ge 2 ]] || die "--reb-api needs a path."
      [[ "$reb_api_from_flag" == 0 ]] || die "Pass --reb-api once."
      reb_api_from_flag=1
      reb_api=$2
      shift 2
      ;;
    --list)
      [[ "$mode" == serve ]] || die "Pass only one of --list, --choose, or --print-config."
      mode=list
      shift
      ;;
    --choose)
      [[ "$mode" == serve ]] || die "Pass only one of --list, --choose, or --print-config."
      mode=choose
      shift
      ;;
    --print-config)
      [[ $# -ge 2 ]] || die "--print-config needs a target."
      [[ "$mode" == serve ]] || die "Pass only one of --list, --choose, or --print-config."
      mode=print
      print_target=$2
      case "$print_target" in
      cursor | claude | codex | grok | t3) ;;
      *) die "Unknown --print-config target. Use cursor, claude, codex, grok, or t3." ;;
      esac
      shift 2
      ;;
    *)
      die "Unknown argument. Run with --help. No session was selected."
      ;;
    esac
  done
}

main() {
  parse_args "$@"
  case "$mode" in
  list) run_list ;;
  choose) run_choose ;;
  print)
    selected_endpoint_file
    if [[ "$selection_kind" == file ]]; then
      require_endpoint_file "$selection_value"
    fi
    health_check
    print_config
    ;;
  serve) serve_mcp ;;
  *) die "Unknown mode." ;;
  esac
}

main "$@"
