---
name: reb-brave-verify
description: Maintain, refresh, build, and verify this repository's pinned Brave fork, overlays, and ordered Brave/Chromium/V8 patches. Use for browser bootstrap, upstream upgrades, patch regeneration, cache/toolchain diagnosis, and compilation evidence.
---

# Maintain and Verify the Brave Integration

Keep project changes reproducible from the tracked upstream pins, then verify
at the strongest available layer. This is the repository's single Brave skill;
use `reb-validation` for the remaining repository gate.

## Establish the task and ownership

1. Read [AGENTS.md](../../../AGENTS.md), [browser/README.md](../../../browser/README.md),
   and [the integration guide](../../../browser/integration/brave/README.md).
2. Inspect the project diff and all three files in `browser/config/`: Brave,
   Chromium, and V8. Record the integration commit, pin values, resolved upstream
   commits, and status of each independent checkout. Do not infer V8 from the
   Chromium tag or use moving upstream HEAD as a reproducible baseline.
3. Classify the request as verification, local iteration, an upstream refresh,
   or a complete build candidate. A verification or skill-writing task does not
   authorize a version bump, large source download, or full build.
4. Complete authored files belong in the mirrored overlay; minimal upstream
   edits belong in the appropriate ordered patch stack. Generated checkouts,
   output directories, caches, and private captures never belong in commits.

Inspect ignored overlay destinations as well as Git status. Known integration
changes can be expected; unexplained changes, mismatched revisions, and edited
overlay destinations are stop conditions for overwriting operations. Preserve
those files and report them; do not reset, clean, stash, or switch the user's
upstream tree implicitly.

For an upstream refresh or patch regeneration, read
[the maintenance procedure](references/fork-maintenance.md). It adapts the
article's replay-and-reexport idea to this repository's existing three-stack
integration, rather than adding a second patch repository or exporter.

## Select the existing build path

- Complete source candidate: follow
  [the integrated build guide](../../../docs/development/integrated-brave-build.md)
  and `scripts/build-integrated-brave.sh`. This guarded path owns checkout-state
  receipts, pin checks, disk reserves, browser compilation, foundation checks,
  and companion packaging. Its current supported host is Apple silicon macOS
  with full Xcode. A small Linux workspace can review and test repository code;
  it cannot establish this path's browser-build result.
  The guide's explicit `adopt` command supports tooling-only or exactly
  equivalent patch-routing handoffs after verifying the old receipt against
  unchanged upstream inputs. Preserve the old receipt; production input changes
  and unknown upstream edits still require a fresh checkout.
- Focused native iteration: use `make brave-doctor`, then `make brave-probe-check`
  or `make brave-foundation-check` as appropriate on the initialized supported
  host. Inspect the helper's target list: probe-check compiles selected objects
  and checks generated bindings; foundation-check also runs the separate proxy
  adapter suite. Neither proves full-browser runtime acceptance.
- Portable distribution: follow
  [the distribution guide](../../../docs/development/brave-distribution.md) and
  `reb-release`. A component development output is not a portable release.

Read the actual [toolchain helper](../../../scripts/brave-toolchain.sh) before
using its modes. `gen`, `probe-check`, and `foundation-check` synchronize and can
change the checkout. The low-level `build` mode calls Brave's build command; it
does not provide the guarded wrapper's full preflight/acceptance sequence.
Never switch global Xcode selection or accept a license as a build workaround.

## Prove reproduction and compilation

1. Inspect bootstrap and sync behavior for the affected change. Confirm mirrored
   overlay paths and their parent/build wiring at the pinned revision. New
   authored files need valid destinations, not pre-existing upstream files.
2. Verify ordered replay on a disposable, pinned, Brave-initialized baseline.
   Check Brave, Chromium, and V8 separately; a raw Chromium tag lacks Brave's
   own initialized patch state. The sync script has no read-only dry-run mode:
   overlapping-stack preflight can reverse/reapply patches, and copying overlays
   overwrites their destinations. Do not claim it is an atomic three-tree
   transaction or run it as a harmless diagnostic on unexplained local edits.
3. Apply production integration only through `scripts/sync-browser-integration.sh`
   or the wrapper that invokes it, then repeat sync and check the resulting
   content is unchanged. Keep exploratory patch regeneration in disposable
   trees; never leave a hand-edited generated tree as the deliverable.
4. Run `make brave-doctor` and, where available, the focused native check. Run
   bundled `gn format --dry-run` on changed GN files and compile affected targets.
   A full candidate additionally needs the wrapper and its runtime checklist.
5. Review disabled, bounded, non-blocking and observational capture behavior;
   exercise failure, capacity, expiration, malformed input and sequence-gap
   behavior when relevant. Dormant worker/proxy foundations remain dormant.

## Control resources without changing the product

Use [fast-browser-builds.md](../../../docs/development/fast-browser-builds.md)
for this repository's macOS component/Siso/sccache profile. Preserve the generated
args import and Brave source-redirection patches. Do not paste generic Chromium
`out/Release`, codec/branding, linker, or executor settings over this profile.

Record host/SDK/toolchain versions, output path, effective GN args and import,
job limit, and cache settings with the source identity. Matching inputs make
rebuilds explainable; this does not assert bit-for-bit reproducible binaries.
Check free space on the actual build disk before downloads: the integrated
wrapper requires 150 GiB for first/init/unproven builds and, for verified repeats,
max(50 GiB, current output size). Follow its receipt-based decision, not a manual
bypass. The guide recommends 200–250 GiB for headroom.

Use `REB_BRAVE_JOBS` with the guarded wrapper or focused check to bound compile
concurrency; the wrapper translates it for the full Brave build. The bare
helper's `build` mode does not automatically consume that variable. Inspect
memory/swap and linker pressure before choosing a limit; CPU count alone is not
a memory budget. Pause competing builds/indexers rather than repeatedly OOMing.
Keep compiler caches bounded and outside Git, compare `sccache --show-stats`
before/after a representative rebuild, and preserve separate incompatible
profiles. A changed compiler, flags or pin may legitimately produce a cold
cache. Diagnose the first failure before deleting output or purging caches;
never delete another task's work to make space.

## Report evidence honestly

Report integration commit, three pins and resolved commits, upstream dirty-state
result, ordered replay/idempotence, toolchain/GN configuration, doctor, focused
native targets, affected/full compilation, runtime acceptance, and repository
gates. Give each layer passed, failed, unavailable, or skipped with its exact
reason and first actionable failure. Separate static checks, compile/link proof,
runtime behavior, and release packaging. Neither CI nor a successful cache hit
proves an unrun browser build. Finish with the specific remaining gate or next
safe action; do not mark an upstream refresh complete without replay/build
and relevant runtime evidence.
