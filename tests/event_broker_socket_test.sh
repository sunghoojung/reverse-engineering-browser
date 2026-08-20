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
test_succeeded=false

cleanup() {
  if [[ "${test_succeeded}" != true ]]; then
    echo "event_broker_socket_test failed" >&2
    if [[ -f "${test_root}/broker.err" ]]; then
      echo "Broker stderr:" >&2
      sed 's/^/  /' "${test_root}/broker.err" >&2
    fi
    if [[ -f "${test_root}/broker.out" ]]; then
      echo "Broker stdout:" >&2
      sed 's/^/  /' "${test_root}/broker.out" >&2
    fi
  fi
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

if "${broker}" --store "${test_root}/overflow.jsonl" \
  --socket "${test_root}/overflow.sock" --token-file "${test_root}/overflow-token" \
  --session-id 3 --category-mask 256 --duration-seconds 18446744073 \
  >"${test_root}/overflow.out" 2>"${test_root}/overflow.err"; then
  echo "Broker unexpectedly accepted an overflowing duration" >&2
  exit 1
fi
grep -Fq 'Session duration overflows the monotonic clock' "${test_root}/overflow.err"
test ! -e "${test_root}/overflow.jsonl"

"${broker}" --store "${store_path}" --socket "${socket_path}" \
  --token-file "${token_path}" --session-id 1 --category-mask 256 \
  --duration-seconds 60 \
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
case "$(uname -s)" in
  Darwin)
    token_mode="$(stat -f '%Lp' "${token_path}")"
    ;;
  Linux)
    token_mode="$(stat -c '%a' "${token_path}")"
    ;;
  *)
    echo "Unsupported operating system: $(uname -s)" >&2
    exit 1
    ;;
esac
readonly token_mode
test "${token_mode}" = 600

"${producer}" --socket "${socket_path}" --token-file "${token_path}" \
  --session-id 1
wait "${broker_pid}"
broker_pid=""

test "$(wc -l < "${store_path}" | tr -d ' ')" = 4
test "$(grep -c "\"payload\":\"${expected_payload_hex}\"" "${store_path}")" = 2
test "$(grep -c '\"category\":\"network\"' "${store_path}")" = 4
grep -Fq 'accepted=4 invalid=0 category_rejected=9 expired=0 sequence_gaps=0' \
  "${test_root}/broker.err"
test ! -e "${socket_path}"

readonly batch_socket_path="${test_root}/batch.sock"
readonly batch_token_path="${test_root}/batch-token"
readonly batch_store_path="${test_root}/batch-events.jsonl"
readonly batch_input_path="${test_root}/batch-events.bin"

"${broker}" --store "${batch_store_path}" --socket "${batch_socket_path}" \
  --token-file "${batch_token_path}" --session-id 1 --category-mask 2047 \
  --duration-seconds 60 --capacity 1 \
  >"${test_root}/batch-broker.out" 2>"${test_root}/batch-broker.err" &
broker_pid=$!

for _ in {1..100}; do
  if [[ -S "${batch_socket_path}" && -f "${batch_token_path}" ]]; then
    break
  fi
  sleep 0.05
done
test -S "${batch_socket_path}"
"${producer}" >"${batch_input_path}"
python3 - "${batch_socket_path}" "${batch_token_path}" "${batch_input_path}" <<'PY'
import socket
import struct
import sys
from pathlib import Path

socket_path, token_path, event_path = sys.argv[1:]
token = bytes.fromhex(Path(token_path).read_text(encoding="ascii").strip())
hello = struct.pack("=IHHQ32s16s", 0x52454249, 1, 64, 1, token, bytes(16))
events = Path(event_path).read_bytes() * 40
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect(socket_path)
    connection.sendall(hello + events)
PY
wait "${broker_pid}"
broker_pid=""

test "$(wc -l < "${batch_store_path}" | tr -d ' ')" = 520
grep -Fq 'accepted=520 invalid=0 category_rejected=0 expired=0 sequence_gaps=0' \
  "${test_root}/batch-broker.err"
test ! -e "${batch_socket_path}"

readonly expired_socket_path="${test_root}/expired.sock"
readonly expired_token_path="${test_root}/expired-token"
readonly expired_store_path="${test_root}/expired-events.jsonl"

"${broker}" --store "${expired_store_path}" --socket "${expired_socket_path}" \
  --token-file "${expired_token_path}" --session-id 2 --category-mask 256 \
  --duration-seconds 1 \
  >"${test_root}/expired-broker.out" 2>"${test_root}/expired-broker.err" &
broker_pid=$!

for _ in {1..100}; do
  if [[ -S "${expired_socket_path}" && -f "${expired_token_path}" ]]; then
    break
  fi
  sleep 0.05
done
test -S "${expired_socket_path}"
wait "${broker_pid}"
broker_pid=""

test "$(wc -l < "${expired_store_path}" | tr -d ' ')" = 0
grep -Fq 'Capture session expired' "${test_root}/expired-broker.err"
grep -Fq 'accepted=0 invalid=0 category_rejected=0 expired=0 sequence_gaps=0' \
  "${test_root}/expired-broker.err"
test ! -e "${expired_socket_path}"

test_succeeded=true
echo "event_broker_socket_test passed"
