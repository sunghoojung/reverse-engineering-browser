# Cooperative workspace writer lease v1

API Collection and Local Analyst (including investigation notebooks) use one
atomic JSON file per library. `expected_generation` prevents stale replacement
only when the generation read and complete publication share the same writer
lease. The Rust HTTP backend and the native `reb://` Swift handlers both implement
this protocol. The document schema and generation numbers are unchanged.

## Transaction and aliases

Each replacement, including a no-op, opens the actual parent directory and pins
its file descriptor. Relative paths and parent-directory symlink aliases reach
the same directory and writer lock. The final store must be a user-owned regular
file with one link; final symlinks and hard links are refused. An absent store is
the existing empty generation zero. A moved or retargeted parent path cannot
redirect an already admitted transaction's reads or writes to another directory.

The permanent sibling `<store filename>.reb-workspace-lock-v1` is an empty,
user-owned, single-link regular file with exactly `0600` permissions. Every
transaction opens its own descriptor with no-follow, nonblocking and close-on-exec
flags, then acquires `flock(LOCK_EX | LOCK_NB)`. It verifies that the named entry
still identifies the locked inode. The sidecar is never renamed or removed.
Locking the JSON inode instead would be incorrect because publication replaces it.

The parent must be owned by the current user and not writable by group or others.
New parent directories are created privately. Stores directly in shared writable
directories are refused; place them in a private subdirectory. The lock suffix and
all filenames starting `.reb-workspace-` are reserved (case-folded) and cannot name a workspace.
Malformed, linked, nonregular or unsafe lock objects fail closed. No lock file is
a credential, evidence record or stale PID file; an empty leftover is intentional.

While holding the lease, the writer rereads the bounded document, validates it,
checks `expected_generation`, builds the candidate and compares for a no-op. A
no-op preserves its generation, timestamps and file bytes. A changed candidate
is written into an exclusively created private temporary in the pinned directory;
file synchronization precedes `renameat`, and checked directory synchronization
follows it. Temporary names are in the reserved namespace. Normal failure cleans
only an unpublished temporary. A process crash may leave a private temporary,
but closing/crashing releases the advisory lease automatically. No automatic
replay, merge or repair is performed.

All transaction filesystem operations use the pinned directory descriptor.
Ordinary reads remain lock-free atomic snapshots and may observe the complete
old or new generation while a writer publishes. They never need to wait for a
competing writer. Filesystem I/O itself can still block.

## Outcomes and limits

- A held lease immediately returns HTTP `409`: a busy workspace, not a save.
  Rust reports `state_conflict`; native handlers retain their existing error
  envelope. The caller can reload and explicitly choose whether to save later.
- A mismatched generation returns the existing stale-generation `409`; no bytes
  are replaced. Retrying an old request after another writer commits stays stale.
- Corrupt, oversized or unsafe files remain unchanged and report a readable error.
- Publication followed by failed directory synchronization is an uncertain save,
  not a rollback. Rust reports `command_outcome_unknown`; native errors say the
  save may have occurred. Reload must establish the saved contents before another
  decision. No failed response is permission to retry a mutation automatically.

This is cooperative exclusion for updated Rust and Swift writers on supported
local Unix filesystems with BSD-style `flock`, `openat`, atomic same-directory rename
and directory synchronization. macOS and Linux are the supported targets. Other
platforms fail closed for writes. Network/distributed filesystems and arbitrary
external editors, old app versions, same-user lock unlink/replacement or directory
permission changes are outside the guarantee. A lock does not authenticate a
writer. File/directory `fsync` checks do not establish a universal power-loss
promise (in particular, no new macOS `F_FULLFSYNC` guarantee is introduced).

## Verification

Backend tests exercise independent stores, actual concurrent HTTP processes for
both libraries, exact winning receipts, immediate busy and stale outcomes, no-op
and corrupt-file preservation, aliases, pinned-parent retargeting, crash release,
private permissions and hostile filesystem entries. The macOS app-build gate
compiles and runs `NativeWorkspaceLeaseChecks.swift` without a UI, then invokes
`workspace_native_lock_interoperability` against the actual Rust backend with
that compiled helper. This proves both implementations use the same OS lease;
it does not activate capture or run a Brave build.
