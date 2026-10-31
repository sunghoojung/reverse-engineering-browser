#!/usr/bin/env bash

# Install a checksum-pinned sccache and export CXX to a single g++ shim.
# The Makefile already disables sccache for dependency-file generation.
# Make's built-in compiler name is g++, so the shim has to be that command.

set -euo pipefail

version="0.19.0"
bindir="${HOME}/.local/share/reb-ci/bin"
install -d "${bindir}" "${HOME}/.cache/sccache"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset="sccache-v${version}-x86_64-unknown-linux-musl.tar.gz"
    checksum="aa73c7270c997894038c0d8f0d297865f57569e1687883322bc431713d4bb9dd"
    ;;
  Darwin-arm64)
    asset="sccache-v${version}-aarch64-apple-darwin.tar.gz"
    checksum="a35a0b7d622618774bc1bb8102d72562dfb21e619f88b153b370d7f89bc286af"
    ;;
  *)
    echo "No pinned sccache binary for $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

archive="${RUNNER_TEMP:-/tmp}/sccache.tar.gz"
workdir="${RUNNER_TEMP:-/tmp}/sccache-extract"
rm -rf "${workdir}"
mkdir -p "${workdir}"
curl --fail --location --silent --show-error \
  --output "${archive}" \
  "https://github.com/mozilla/sccache/releases/download/v${version}/${asset}"
python3 - "${archive}" "${checksum}" <<'PY'
import hashlib
import pathlib
import sys
digest = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if digest != sys.argv[2]:
    raise SystemExit(f"sccache checksum mismatch: {digest}")
PY
tar -xzf "${archive}" -C "${workdir}"
binary=""
while IFS= read -r candidate; do
  binary="${candidate}"
  break
done < <(find "${workdir}" -type f -name sccache)
if [[ -z "${binary}" ]]; then
  echo "sccache archive did not contain a binary" >&2
  exit 1
fi
install -m 0755 "${binary}" "${bindir}/sccache"
# Make's built-in $(CXX) is g++, and `CXX ?=` does not replace it. Point CXX
# at this single executable so recipe shells and Python subprocesses both
# reach sccache without splitting the compiler into two argv words.
cat > "${bindir}/g++" <<EOF
#!/bin/sh
exec "${bindir}/sccache" /usr/bin/g++ "\$@"
EOF
chmod 0755 "${bindir}/g++"

if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${bindir}" >> "${GITHUB_PATH}"
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "RUSTC_WRAPPER=sccache"
    echo "CARGO_INCREMENTAL=0"
    echo "CXX=${bindir}/g++"
    echo "SCCACHE_DIR=${HOME}/.cache/sccache"
    echo "SCCACHE_CACHE_SIZE=500M"
  } >> "${GITHUB_ENV}"
fi
export PATH="${bindir}:${PATH}"
sccache --version
