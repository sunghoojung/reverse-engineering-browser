#!/usr/bin/env bash

# Print mode=full|rust|docs to GITHUB_OUTPUT. Pull requests consult the
# allowlist; every other event stays on the full gate. A broken classifier
# or a diff that edits the skip logic cannot report a narrower mode.

set -euo pipefail

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "GITHUB_OUTPUT is required" >&2
  exit 1
fi

write_mode() {
  local mode="$1"
  case "${mode}" in
    full | rust | docs) ;;
    *)
      echo "refusing unexpected CI scope ${mode}" >&2
      exit 1
      ;;
  esac
  echo "mode=${mode}" >> "${GITHUB_OUTPUT}"
  echo "CI scope: ${mode}"
}

if [[ "${GITHUB_EVENT_NAME}" != "pull_request" ]]; then
  echo "Full gate: ${GITHUB_EVENT_NAME} does not use path filtering."
  write_mode full
  exit 0
fi

if [[ -z "${BASE_SHA:-}" || -z "${HEAD_SHA:-}" ]]; then
  echo "Full gate: pull request base or head SHA is missing." >&2
  write_mode full
  exit 0
fi

changed="$(mktemp)"
trap 'rm -f "${changed}"' EXIT
git diff --name-only "${BASE_SHA}...${HEAD_SHA}" > "${changed}"
echo "Changed paths:"
head -n 200 "${changed}"
count="$(grep -c . "${changed}" || true)"
if ((count > 200)); then
  echo "... ${count} paths total"
fi

mode="$(python3 tools/ci-scope.py --from-file "${changed}")"
if grep -Eq '^(tools/ci-scope\.py|tools/ci-scope-test\.py|tools/ci-scope-decision\.sh|\.github/workflows/ci\.yml|\.github/actions/ci-)' "${changed}"; then
  echo "Full gate: this diff edits CI skip logic."
  mode="full"
fi
write_mode "${mode}"
