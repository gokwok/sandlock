//! Backend-agnostic recovery of preserved COW-branch storage.
//!
//! When a transaction (or a plain [`Sandbox`](crate::sandbox::Sandbox) whose
//! branch action is [`Keep`](crate::sandbox::BranchAction::Keep)) cannot
//! reclaim its change set — a commit that could not take the workdir lock, a
//! merge that failed partway, or work deliberately kept for inspection — the
//! change set is left on disk instead of thrown away. This module is the
//! backend-neutral entry point for finding and reading that preserved work; it
//! deliberately does not name the COW backend that produced it.
//!
//! Recovery is broader than transactions: a plain `Sandbox` with
//! [`BranchAction::Keep`](crate::sandbox::BranchAction::Keep) also preserves
//! work, which is why this lives in its own module rather than under
//! `transaction`.
//!
//! # A running merge looks like an interrupted one
//!
//! [`list_preserved`] reports every preserved branch under a storage base,
//! including a merge that is *still running*: a commit writes its
//! [`PreserveReason::MergeInterrupted`] marker before the first destructive
//! step. The marker's [`pid`](PreservedBranch::pid) is what separates the two —
//! a sweep that *acts* on a branch, rather than only reporting it, must check
//! that pid is not a live process first.
//!
//! # Durability of the default storage
//!
//! With no explicit `fs_storage`, preserved work lands in a stable per-user base
//! (`$XDG_RUNTIME_DIR/sandlock-cow` when available, otherwise a securely-created
//! `$TMPDIR/sandlock-cow-<uid>`), so [`list_preserved`] on that base spans a
//! user's dead pids. `$XDG_RUNTIME_DIR` is nonetheless **session-scoped**:
//! `systemd-logind` removes `/run/user/<uid>` on last-session-exit and it is a
//! size-limited tmpfs. A daemon or any cross-session recovery MUST therefore set
//! an explicit, durable, disk-backed `fs_storage` rather than rely on the
//! default.
//!
//! The same caveat scopes the marker's crash-durability. The marker is written
//! atomically and fsynced (file, then its directory entry) at the one moment it
//! is the crash record for a merge in flight. A `SIGKILL` or a panic never
//! needed that — the page cache survives — so it changes behaviour only on
//! power loss or a kernel panic, and on the tmpfs default there is nothing left
//! to recover from after either. It buys something real only with a disk-backed
//! `fs_storage`, and even there the upper it names is written by the COW copy
//! path and by the child with no sync of its own.
//!
//! # Applying a preserved change set
//!
//! Order is not free: **deletions first, then the upper**. An addition under a
//! path the run also deleted only lands correctly if the deletion has already
//! emptied that path, which is the same order the merge itself uses.
//!
//! The marker's `deleted=` lines are the OUTSTANDING deletions as of the last
//! durable write, not the branch's whole whiteout history. The history lives in
//! the append-only `deleted.log` beside the upper and must NOT be used here: a
//! `MergeInterrupted` branch may have had part of its upper published and
//! drained already, and re-applying a whiteout over a path that landed destroys
//! it. That is why interrupted-merge recovery remains report-only. The
//! exception is a [`PreserveReason::Detached`] branch, which was persisted
//! before any commit attempt and can be passed to [`crate::FsBranch::reopen`].

pub use crate::cow::seccomp::{list_preserved, read_preserved, PreserveReason, PreservedBranch};
