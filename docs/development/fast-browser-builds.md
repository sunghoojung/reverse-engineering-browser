# Fast local Brave builds

Use the existing macOS development output for repeated Origin Trace browser
iterations. Keep the output as a component build with Siso enabled, then add
these overrides after the generated-args import in
`browser/worktree/src/out/Component_arm64/args.gn`:

```gn
cc_wrapper = "sccache"
symbol_level = 0
blink_symbol_level = 0
v8_symbol_level = 0
use_lld = false
use_clang_modules = false
```

Install the cache once with Homebrew:

```sh
brew install sccache
sccache --start-server
```

Regenerate the output after changing GN arguments:

```sh
REB_BRAVE_DIRECTORY=/absolute/path/to/browser/worktree/src/brave \
  ./scripts/brave-toolchain.sh gen
```

Then use the focused probe target during iteration:

```sh
REB_BRAVE_DIRECTORY=/absolute/path/to/browser/worktree/src/brave \
  make brave-probe-check
```

`is_component_build=true` keeps incremental links small, `symbol_level=0`
removes large debug information, and `use_lld=false` selects Apple's linker
for local arm64 macOS links. `use_clang_modules=false` is needed because
`sccache` bypasses Clang header-module compilations. The Brave integration
keeps Siso's `chromium_src` source redirection active when `cc_wrapper` is
`sccache`, and mirrors the patched Brave Siso module into Chromium's generated
root during browser synchronization. It also patches the extended BitInt
frontend option to an equivalent cacheable spelling only when `cc_wrapper` is
`sccache`; normal builds retain the original option.

After changing the Siso or Brave integration patches, the first probe build may
recompile affected upstream objects so the redirected source inputs are
recorded; the toolchain helper refreshes those source timestamps once when the
Siso redirect configuration is newer than the existing objects. Later builds
reuse those objects through Siso and `sccache`.

The first build after changing GN arguments is cold. Later compilations with the
same compiler, flags, and inputs can reuse cached objects. Check the result with:

```sh
sccache --show-stats
```

The default macOS cache is local and bounded to 10 GiB. Keep the cache outside
the repository, and never commit the generated `out/` directory.
