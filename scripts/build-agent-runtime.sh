#!/usr/bin/env bash
# Builds the agent dock's LangGraph bundle from the pinned lockfile:
# apps/research-ui/agent-runtime/package-lock.json. Install scripts never run.
# Usage: scripts/build-agent-runtime.sh [output directory]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package="${repo_root}/apps/research-ui/agent-runtime"
output="${1:-${repo_root}/build/agent-runtime}"

if ! command -v npm >/dev/null 2>&1; then
  echo "build-agent-runtime: npm is required to install the pinned agent runtime packages" >&2
  exit 1
fi
npm ci --prefix "${package}" --ignore-scripts --no-audit --no-fund --loglevel=error
node "${package}/build.mjs" "${output}"
