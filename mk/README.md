# Build organization

Run `make` from the repository root. The root [Makefile](../Makefile) defines
the default goal and includes these files in order:

| File | Responsibility |
| --- | --- |
| `config.mk` | Compiler flags, build directories, source lists for lint, platform defaults |
| `native.mk` | Explicit native link dependencies, compilation, generated header dependencies |
| `workflows.mk` | Product launch, evidence fixtures, local services, Brave integration commands |
| `quality.mk` | Unit tests, build regression checks, linters, sanitizers, cleanup |

Existing command names and executable paths remain the public interface.
Implementation objects mirror source paths inside `BUILD_DIR`; compiler-generated
`.d` files track direct and transitive project headers. Only the native probe
queue test links the tracked browser queue implementation. Only decoder targets
add zlib to their link commands.

Use a separate build directory for a different compiler or set of flags:

```sh
make BUILD_DIR=build/debug OPT_CXXFLAGS='-O0 -g' test
```

Make does not detect changes to command-line flag values in an existing build
directory. Changes to the native rules or compiler configuration files do
invalidate native objects. `make sanitize` uses its own clean build directory.

`make native-build-test` builds and runs two independent executables in a
temporary directory, checks that a repeat build does no work, and verifies that
an artifact header change invalidates its consumer without rebuilding the event
demo. `make check` includes this regression check.
