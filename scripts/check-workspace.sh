#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd "${script_dir}/.." && pwd)"
readonly repository_root

readonly required_paths=(
  "AGENTS.md"
  "CONTRIBUTING.md"
  "README.md"
  ".agents/skills/reb-brave-verify/SKILL.md"
  ".agents/skills/reb-ui-e2e/SKILL.md"
  ".agents/skills/reb-validation/SKILL.md"
  "workspace.json"
  "docs/README.md"
  "docs/architecture/technical-architecture.md"
  "docs/architecture/system-architecture.md"
  "docs/architecture/system-architecture.svg"
  "docs/product/feature-list.md"
  "docs/product/feature-catalog.md"
  "apps/research-ui/README.md"
  "browser/README.md"
  "browser/config/brave-core.rev"
  "browser/config/chromium.rev"
  "browser/integration/brave/README.md"
  "browser/integration/brave/patches/0001-register-native-probe-component.patch"
  "browser/integration/brave/patches/0002-observe-native-network-lifecycle.patch"
  "browser/integration/brave/patches/chromium/0001-record-renderer-network-initiators.patch"
  "browser/integration/brave/patches/chromium/0003-ignore-page-debugger-statements.patch"
  "browser/integration/brave/overlay/components/reverse_engineering_browser/browser/native_network_capture_sink.cc"
  "scripts/sync-browser-integration.sh"
  "scripts/brave-toolchain.sh"
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
  if [[ -n "$(git -C "${repository_root}" ls-files browser/worktree)" ]]; then
    echo "browser/worktree contains tracked files" >&2
    exit 1
  fi
  echo "Workspace scaffold check passed"
else
  echo "browser/worktree is not ignored by Git" >&2
  exit 1
fi
