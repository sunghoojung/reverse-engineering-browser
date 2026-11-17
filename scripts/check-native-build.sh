#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
build_directory="$(mktemp -d "${TMPDIR:-/tmp}/reb-native-build.XXXXXX")"
readonly build_directory
trap 'rm -rf "${build_directory}"' EXIT
cd "${repository_root}"

make --no-print-directory BUILD_DIR="${build_directory}" demo artifact-producer
"${build_directory}/reb-event-demo" >/dev/null
"${build_directory}/reb-artifact-producer" >/dev/null

# A second build must do no work, including with an absolute build directory.
make --question BUILD_DIR="${build_directory}" demo artifact-producer

# An unrelated header must not invalidate the demo's build graph.
make --question --what-if=include/reb/artifact.hpp BUILD_DIR="${build_directory}" demo

# The same header must invalidate its consumer through compiler-generated dependencies.
status=0
make --question --what-if=include/reb/artifact.hpp \
  BUILD_DIR="${build_directory}" artifact-producer || status=$?
if [[ "${status}" -ne 1 ]]; then
  echo "Artifact header change should require rebuilding its consumer (status ${status})" >&2
  exit 1
fi

# On macOS the app's Info.plist sets the deployment target of every object.
if [[ "$(uname -s)" == "Darwin" ]]; then
  status=0
  make --question --what-if=apps/research-ui/macos/Info.plist \
    BUILD_DIR="${build_directory}" demo || status=$?
  if [[ "${status}" -ne 1 ]]; then
    echo "An Info.plist change should rebuild native objects for its minimum macOS (status ${status})" >&2
    exit 1
  fi
fi

echo "Native build dependency check passed"
