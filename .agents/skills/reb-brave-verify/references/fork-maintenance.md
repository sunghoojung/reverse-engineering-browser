# Upstream refresh and patch regeneration

Read this for a requested pin upgrade or an integration patch that must be
regenerated. The tracked overlay and patches are the deliverable; an edited
`browser/worktree` is not. Commands below are a procedure for an authorized
maintenance task, not permission to start a large download or upgrade.

## Choose and record a compatible baseline

1. Start a dedicated project branch. Record current project SHA, three pins,
   resolved upstream SHAs, patch ordering and overlay inventory. Keep the last
   working commit/build evidence available for comparison and rollback.
2. Choose an explicit Brave release/tag or immutable commit. Inspect that
   revision's `package.json` Chromium dependency and its resolved Chromium DEPS
   V8 revision. Review release/security changes, build prerequisites and the
   APIs touched by this integration. Do not select three independent latest
   versions. Record upstream URLs and the old-to-new revision mapping in the PR.
3. Check Node/pnpm, SDK/Xcode, bundled compiler/Python and build-tool requirements
   at that candidate revision. Review any change to the repository helpers'
   expectations. Do not upgrade host tools or change global settings implicitly.
4. Prepare a separate disposable workspace with sufficient disk on a supported
   build host. On the candidate branch, update the three pin files coherently,
   then use the repository bootstrap with `--init` only when initialization is
   authorized. Default shallow history is sufficient; full history is opt-in
   for an investigation that actually needs it. Keep the existing working
   checkout intact. A pin mismatch must not be bypassed with environment
   overrides to make validation look green.

Brave initialization installs its own Chromium/V8 modifications and dependencies.
Record that known baseline before applying REB's patches. Brave's `sync` and
`update_patches` commands maintain Brave's own upstream patch system; they do
not export this repository's `browser/integration/brave/patches/` automatically.
Do not run a forced Brave sync over a project-integrated working tree.

## Replay, resolve, regenerate, prove

The existing sync script sorts `*.patch` lexically within each of these roots:

- `browser/integration/brave/patches/`: paths relative to `src/brave`
- `browser/integration/brave/patches/chromium/`: paths relative to `src`
- `browser/integration/brave/patches/v8/`: paths relative to `src/v8`

Inspect patch headers and explicit paths before each operation. Preserve order;
a later patch may intentionally depend on an earlier patch. Individual
`git apply --check` calls against one unchanged baseline do not prove the stack.
Use a disposable initialized tree (or an isolated index for a non-mutating
ordered check) to advance through each earlier patch before checking the next.
Never use the production sync command as a read-only preflight.

For each conflict, identify the upstream rename/API/ownership change and decide
whether to adapt or retire the hook. A patch becoming unnecessary requires
behavioral evidence, not deletion merely because it no longer applies. Check
`chromium_src` overrides, generated binding hooks, GN dependencies, Mojo/ABI
contracts, and the Siso source-redirection integration where affected.

Regenerate a changed patch against the exact state immediately before that
patch, including Brave initialization and earlier REB patches. In the disposable
checkout, checkpoint that baseline locally, resolve only the intended files,
and review an explicit-path diff, for example:

```sh
# From the applicable disposable Brave, Chromium, or V8 repository.
# BASE is the recorded pre-patch checkpoint, not an arbitrary upstream HEAD.
git diff --binary --full-index "$BASE" -- path/to/upstream_file > /tmp/reb-candidate.patch
```

New complete REB-authored files remain in the overlay. If a patch genuinely
introduces a new upstream-owned file, ensure the diff includes it (ordinary
`git diff` omits untracked files); stage only that explicitly reviewed path in
the disposable tree and compare the correct index/base. Avoid broad `git add -A`
or whole-tree exports that accidentally capture Brave's own patches, dependency
changes, toolchain files, generated files, or private data.

Inspect the candidate patch, replace the corresponding tracked patch only when
it is complete, and replay the whole series from the recorded clean baseline.
A changed early patch requires replay of later dependent patches. Compare the
replayed touched-file contents to the intended resolved tree; use file hashes
or explicit diffs, not just a zero exit status. Verify overlay copies, run sync
twice, and confirm the second pass changes no content. Keep exploratory edits
out of the final generated tree; recreate through the tracked sync path.

The current sync implementation is not a global rollback transaction. If it
fails after a stack refresh, inspect all three tree diffs. Stop on a partly
applied or unexplained state; reconstruct the disposable trial from the known
baseline rather than resetting a working checkout or blindly rerunning hooks.
Do not manufacture a new integrated-build receipt to bless unexplained edits.

## Validate and hand off the upgrade

- Run the repository gate from `AGENTS.md` and focused script regression tests
  when bootstrap/sync/state logic changes. Synthetic fixtures prove script
  behavior, not compatibility with the actual new upstream source.
- On the initialized supported host, run doctor, GN formatting for changed GN,
  focused probe/foundation compilation and affected tests, then the integrated
  build wrapper and runtime acceptance checklist. Review new upstream behavior
  for capture/privacy regressions and recheck disabled-by-default operation.
- Report pinned replay, compile, runtime, and packaging separately. If the host
  or dependencies are unavailable, leave the PR draft with the exact missing
  gate; do not describe a pin-only edit as a working upgraded browser.
- Keep pins, corresponding overlay/patch adaptation, and helper/documentation
  updates together in the reviewed candidate. Rollback means returning to the
  previous complete source/pin/patch set and its compatible build output, not
  mixing old patches with new pins. Preserve the old checkout until acceptance.
- Record known security/update exposure if an upgrade is blocked. An older
  functioning build is useful for comparison, not proof it is safe for browsing.

## Sources and how they apply

- [Forking Chromium: maintaining your fork](https://yacinesellami.com/blog/forking-chromium/#post-build-maintaining-your-fork)
  motivates explicit upstream baselines, reviewable patches, replay before
  re-export, and verification of exported content. Its sample tooling warns it
  is not battle-tested. Do not import its scripts or separate patch-repository
  layout into this existing integration.
- [Brave Core README](https://github.com/brave/brave-core/blob/master/README.md)
  documents Brave's initialization/build/dependency synchronization lifecycle.
  Consult the selected revision's README and package metadata for actual
  prerequisites; moving master is context, not the build pin.
- [Brave Chromium rebases](https://github.com/brave/brave-browser/wiki/Chromium-rebases)
  describes patch conflict resolution, toolchain changes, override checks, and
  build/test validation. It targets Brave upstream maintainers. REB ordinarily
  selects a coherent Brave release rather than independently rebasing Brave
  onto a different Chromium version.

Repository scripts and the linked subsystem guides own executable commands.
The sources supply rationale, not an alternate build pipeline or authority to
relax the repository's safety and validation gates.
