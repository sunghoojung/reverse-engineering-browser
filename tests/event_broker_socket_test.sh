#!/usr/bin/env bash

set -euo pipefail

if (($# != 3)); then
  echo "Usage: $0 BROKER PRODUCER EXPECTED_PAYLOAD_HEX" >&2
  exit 2
fi

readonly broker="$1"
readonly producer="$2"
readonly expected_payload_hex="$3"
test_root="$(mktemp -d)"
readonly test_root
broker_pid=""

cleanup() {
  if [[ -n "${broker_pid}" ]] && kill -0 "${broker_pid}" 2>/dev/null; then
    kill "${broker_pid}" 2>/dev/null || true
    wait "${broker_pid}" 2>/dev/null || true
  fi
  rm -rf "${test_root}"
}
trap cleanup EXIT

readonly socket_path="${test_root}/broker.sock"
readonly token_path="${test_root}/token"
readonly store_path="${test_root}/events.jsonl"

"${broker}" --store "${store_path}" --socket "${socket_path}" \
  --token-file "${token_path}" --session-id 1 \
  >"${test_root}/broker.out" 2>"${test_root}/broker.err" &
broker_pid=$!

for _ in {1..100}; do
  if [[ -S "${socket_path}" && -f "${token_path}" ]]; then
    break
  fi
  sleep 0.05
done
test -S "${socket_path}"
test -f "${token_path}"
test "$(stat -f '%Lp' "${token_path}" 2>/dev/null || stat -c '%a' "${token_path}")" = 600

"${producer}" --socket "${socket_path}" --token-file "${token_path}" \
  --session-id 1
wait "${broker_pid}"
broker_pid=""

test "$(wc -l < "${store_path}" | tr -d ' ')" = 7
test "$(grep -c "\"payload\":\"${expected_payload_hex}\"" "${store_path}")" = 2
grep -Fq 'accepted=7 invalid=0 sequence_gaps=0' "${test_root}/broker.err"
test ! -e "${socket_path}"

echo "event_broker_socket_test passed"
