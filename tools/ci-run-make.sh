#!/usr/bin/env bash

# Build independent C++ outputs with one compile per core, then run the
# requested Make goal on a single job. `make -j check` would also start the
# several Cargo invocations that `check` depends on, and those oversubscribe
# the runner. Sanitizer builds use another directory; the inner Make inherits
# this jobserver and does not repeat the default-directory C++ build.

set -euo pipefail

goal="${1:?usage: ci-run-make.sh check|e2e|app-build|quickjs-binding-check|sanitize}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  cores="$(sysctl -n hw.ncpu)"
else
  cores="$(nproc)"
fi

case "${goal}" in
  sanitize)
    exec make -j"${cores}" sanitize
    ;;
  check | e2e | app-build | quickjs-binding-check)
    make -j"${cores}" cpp-build
    exec make "${goal}"
    ;;
  *)
    echo "unknown CI make goal: ${goal}" >&2
    exit 2
    ;;
esac
