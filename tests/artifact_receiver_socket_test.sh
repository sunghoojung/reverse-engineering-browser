#!/usr/bin/env bash

set -euo pipefail

if (($# != 2)); then
  echo "Usage: $0 RECEIVER PRODUCER" >&2
  exit 2
fi

readonly receiver="$1"
readonly producer="$2"
test_root="$(mktemp -d)"
readonly test_root
receiver_pid=""
test_succeeded=false

cleanup() {
  if [[ "${test_succeeded}" != true ]]; then
    echo "artifact_receiver_socket_test failed" >&2
    find "${test_root}" -name '*.err' -type f -maxdepth 2 -print -exec sed 's/^/  /' {} \; >&2 || true
  fi
  if [[ -n "${receiver_pid}" ]] && kill -0 "${receiver_pid}" 2>/dev/null; then
    kill "${receiver_pid}" 2>/dev/null || true
    wait "${receiver_pid}" 2>/dev/null || true
  fi
  rm -rf "${test_root}"
}
trap cleanup EXIT

readonly token_path="${test_root}/session.token"
umask 077
printf '%064d\n' 0 >"${token_path}"

wait_for_socket() {
  local socket_path="$1"
  for _ in {1..100}; do
    if [[ -S "${socket_path}" ]]; then
      return 0
    fi
    if ! kill -0 "${receiver_pid}" 2>/dev/null; then
      return 1
    fi
    sleep 0.05
  done
  return 1
}

readonly accepted_socket="${test_root}/accepted.sock"
readonly accepted_store="${test_root}/accepted"
"${receiver}" --store "${accepted_store}" --socket "${accepted_socket}" \
  --token-file "${token_path}" --session-id 41 \
  >"${test_root}/accepted.out" 2>"${test_root}/accepted.err" &
receiver_pid=$!
wait_for_socket "${accepted_socket}"
test -S "${accepted_socket}"
case "$(uname -s)" in
  Darwin) socket_mode="$(stat -f '%Lp' "${accepted_socket}")" ;;
  Linux) socket_mode="$(stat -c '%a' "${accepted_socket}")" ;;
  *) echo "Unsupported operating system: $(uname -s)" >&2; exit 1 ;;
esac
test "${socket_mode}" = 600
"${producer}" --socket "${accepted_socket}" --token-file "${token_path}" --session-id 41
wait "${receiver_pid}"
receiver_pid=""
test ! -e "${accepted_socket}"
test "$(wc -l <"${accepted_store}/manifest.jsonl" | tr -d ' ')" = 3
grep -Fq '"session_id":"41"' "${accepted_store}/manifest.jsonl"
grep -Fq 'accepted=3' "${test_root}/accepted.err"

readonly mismatch_socket="${test_root}/mismatch.sock"
"${receiver}" --store "${test_root}/mismatch" --socket "${mismatch_socket}" \
  --token-file "${token_path}" --session-id 42 \
  >"${test_root}/mismatch.out" 2>"${test_root}/mismatch.err" &
receiver_pid=$!
wait_for_socket "${mismatch_socket}"
if "${producer}" --socket "${mismatch_socket}" --token-file "${token_path}" --session-id 43 \
  >"${test_root}/mismatch-producer.out" 2>"${test_root}/mismatch-producer.err"; then
  echo "Artifact producer unexpectedly passed mismatched session authentication" >&2
  exit 1
fi
if wait "${receiver_pid}"; then
  echo "Artifact receiver unexpectedly accepted a mismatched session" >&2
  exit 1
fi
receiver_pid=""
grep -Fq 'Artifact authentication rejected' "${test_root}/mismatch.err"
test ! -e "${mismatch_socket}"

readonly limited_socket="${test_root}/limited.sock"
"${receiver}" --store "${test_root}/limited" --socket "${limited_socket}" \
  --token-file "${token_path}" --session-id 44 --max-artifact-bytes 16 --max-store-bytes 64 \
  >"${test_root}/limited.out" 2>"${test_root}/limited.err" &
receiver_pid=$!
wait_for_socket "${limited_socket}"
if "${producer}" --socket "${limited_socket}" --token-file "${token_path}" --session-id 44 \
  >"${test_root}/limited-producer.out" 2>"${test_root}/limited-producer.err"; then
  echo "Artifact producer unexpectedly received an accepted acknowledgment" >&2
  exit 1
fi
if wait "${receiver_pid}"; then
  echo "Artifact receiver unexpectedly accepted an oversized artifact" >&2
  exit 1
fi
receiver_pid=""
grep -Fq 'too_large=1' "${test_root}/limited.err"
grep -Fq 'acknowledged incorrectly' "${test_root}/limited-producer.err"
test ! -e "${limited_socket}"
test ! -e "${test_root}/limited/manifest.jsonl"

test_succeeded=true
echo "artifact_receiver_socket_test passed"
