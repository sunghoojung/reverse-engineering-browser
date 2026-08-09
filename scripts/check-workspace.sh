#!/usr/bin/env bash

set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd "${script_dir}/.." && pwd)"

readonly required_paths=(
  "AGENTS.md"
  ".gitmodules"
  "workspace.json"
  "apps/research-ui/README.md"
  "apps/mcp-server/README.md"
  "browser/README.md"
  "browser/config/brave-core.rev"
  "include/reb/event.hpp"
  "protocol/README.md"
  "services/event-broker/README.md"
)

missing_count=0
for relative_path in "${required_paths[@]}"; do
  if [[ ! -e "${repository_root}/${relative_path}" ]]; then
    echo "Missing workspace path: ${relative_path}" >&2
    missing_count=$((missing_count + 1))
  fi
done

if ((missing_count > 0)); then
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  python3 -m json.tool "${repository_root}/workspace.json" >/dev/null
fi

if git -C "${repository_root}" check-ignore browser/worktree/example >/dev/null 2>&1; then
  echo "Workspace scaffold check passed"
else
  echo "browser/worktree is not ignored by Git" >&2
  exit 1
fi
