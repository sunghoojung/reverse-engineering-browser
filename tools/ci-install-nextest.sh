#!/usr/bin/env bash

# Install a checksum-pinned cargo-nextest and select it for the whole Rust
# suites in `make check` (REB_RUST_TEST_RUNNER=nextest). cargo test runs one
# test binary at a time; nextest runs the tests of every binary at once, each
# in its own process. Local `make check` keeps cargo test unless asked.

set -euo pipefail

version="0.9.150"
bindir="${HOME}/.local/share/reb-ci/bin"
install -d "${bindir}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset="cargo-nextest-${version}-x86_64-unknown-linux-musl.tar.gz"
    checksum="84f0f9ba75d0b6fa117bc418d49747ba78e20e4583057f6fa628f1b17c17234d"
    ;;
  Darwin-arm64 | Darwin-x86_64)
    asset="cargo-nextest-${version}-universal-apple-darwin.tar.gz"
    checksum="82a759b4d218d38359424196ab244c470e8f7c7d149c814fbbeef4d67c3c301a"
    ;;
  *)
    echo "No pinned cargo-nextest binary for $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

archive="${RUNNER_TEMP:-/tmp}/cargo-nextest.tar.gz"
workdir="${RUNNER_TEMP:-/tmp}/cargo-nextest-extract"
rm -rf "${workdir}"
mkdir -p "${workdir}"
curl --fail --location --silent --show-error --retry 3 \
  --output "${archive}" \
  "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${version}/${asset}"
python3 - "${archive}" "${checksum}" <<'PY'
import hashlib
import pathlib
import sys
digest = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if digest != sys.argv[2]:
    raise SystemExit(f"cargo-nextest checksum mismatch: {digest}")
PY
tar -xzf "${archive}" -C "${workdir}"
if [[ ! -f "${workdir}/cargo-nextest" ]]; then
  echo "cargo-nextest archive did not contain the binary" >&2
  exit 1
fi
install -m 0755 "${workdir}/cargo-nextest" "${bindir}/cargo-nextest"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${bindir}" >> "${GITHUB_PATH}"
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "REB_RUST_TEST_RUNNER=nextest" >> "${GITHUB_ENV}"
fi
"${bindir}/cargo-nextest" nextest --version
