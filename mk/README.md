# Build organization

Run `make` from the repository root. The root [Makefile](../Makefile) defines
the default goal and includes these files in order:

| File | Responsibility |
| --- | --- |
| `config.mk` | Compiler flags, build directories, source lists for lint, platform defaults |
| `native.mk` | Explicit native link dependencies, compilation, generated header dependencies |
| `workflows.mk` | Product launch, evidence fixtures, local services, Brave integration commands |
| `quality.mk` | Build regression check, linters, sanitizers, cleanup |

Existing command names and executable paths remain the public interface.
Implementation objects mirror source paths inside `BUILD_DIR`; compiler-generated
`.d` files track direct and transitive project headers. Only the decoder
executable adds zlib to its link command. `make native-probe-compile` compiles
the tracked browser queue without a separate test source.

`make bootstrap-dev-tools` installs the same pinned `clang-format` and Ruff
versions used by CI into `~/.local/share/reb-tools`, and installs missing
`shellcheck` and `actionlint` formulae with Homebrew. Make prefers those pinned
local tools automatically. `make deob-benchmark` builds the Rust worker and runs
the bounded semantic corpus with timing, memory, transformation, and
changed-source coverage evidence.

`make lint` checks formatting and Clippy warnings for both Rust manifests.
The deobfuscation worker includes all targets so its regression-test code is
checked along with the production executable.

Use a separate build directory for a different compiler or set of flags:

```sh
make BUILD_DIR=build/debug OPT_CXXFLAGS='-O0 -g' all
```

Make does not detect changes to command-line flag values in an existing build
directory. Changes to the native rules or compiler configuration files do
invalidate native objects. `make sanitize` uses its own clean build directory.

`make native-build-test` runs `scripts/check-native-build.sh`, which builds and
runs two independent executables in a
temporary directory, checks that a repeat build does no work, and verifies that
an artifact header change invalidates its consumer without rebuilding the event
demo. `make check` includes this regression check, the deobfuscation semantic
benchmark, and the backend and deobfuscator worker's Rust test suites. It also
runs the source-facts HTTP/CLI integration test against the built Rust/Oxc worker;
`CARGO_TARGET_DIR` is honored when locating that helper.

`make native-proxy-policy-check` compiles and runs the preparation-only native
proxy/container policy suite without Chromium, Cargo, sockets, or a browser.
It is included in `make check` and `make sanitize`; it does not establish real
browser routing or isolation. See the versioned native proxy-container contract.

`origin-trace-backend` builds the Rust HTTP service, VM analyzer, and API CLI.
`ui` starts that service after deterministic evidence generation. `backend-e2e`
uses a disposable Chromium-compatible profile and synthetic localhost fixtures;
set `ORIGIN_TRACE_TEST_BROWSER` for a nonstandard browser executable. App builds
bundle Rust executables and static UI assets, with no Python runtime dependency.
