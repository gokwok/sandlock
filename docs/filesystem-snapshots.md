# Immutable filesystem snapshots

Sandlock's Rust API can turn a directory or a COW branch view into a durable,
immutable `FsSnapshot`. A snapshot can be reopened after a controller restart,
inspected without starting a sandbox, and reused as the stable lower for any
number of independent `FsBranch` instances.

This is a filesystem primitive. Sandlock does not assign application revision
meaning, track an exploration graph, select a result, or publish a chosen tree
into another workspace.

## Model

Each active snapshot-backed branch has exactly two logical layers:

```text
immutable FsSnapshot lower + mutable FsBranch upper + whiteouts
```

Deeper logical histories use `checkpoint -> snapshot -> branch`, not a stack
of live COW layers. `FsBranch::checkpoint` materializes the merged view into a
new snapshot through private staging and an atomic rename. It does not modify
the lower, clear the upper, or resolve the branch.

`FsBranch::commit` is deliberately denied for a snapshot-backed branch because
its lower is immutable. Explicit publication into another destination is a
separate concern and is not part of this API.

## Rust API

Capture and reopen an immutable source:

```rust
use sandlock_core::{FsBranch, FsSnapshot};

let snapshot = FsSnapshot::capture("/workspace", "/var/lib/controller/snapshots")?;
let descriptor = snapshot.descriptor().clone();

// Persist `descriptor` in the trusted controller's state.
let snapshot = FsSnapshot::reopen(descriptor)?;
let mut branch = FsBranch::from_snapshot(
    &snapshot,
    "/var/lib/controller/branches",
)?;

let checkpoint = branch.checkpoint("/var/lib/controller/snapshots")?;
// `branch` remains pending and reusable here.
branch.abort()?;
```

If the controller crashes after atomic publication but before recording the
descriptor, `FsSnapshot::discover(snapshot_storage)` enumerates complete,
reopenable snapshots without exposing Sandlock's private layout. A
`SnapshotError::Published` also carries the descriptor when publication
succeeded but its final durability confirmation failed.

Directory permission modes are stored as snapshot metadata while the private
backend tree keeps owner traversal permissions. Inspection, diff, export, and
derived checkpoints report and reproduce the captured modes without temporarily
widening permissions on a shared immutable lower.

When a `Sandbox` owns the branch, configure its `workdir` to the snapshot root
and create the branch through the sandbox so its COW storage and quota apply:

```rust
let mut sandbox = Sandbox::builder()
    .fs_read("/usr")
    .fs_read(snapshot.root_dir())
    .workdir(snapshot.root_dir())
    .fs_storage("/var/lib/controller/branches")
    .build()?;

let mut branch = sandbox.create_fs_branch_from_snapshot(&snapshot)?;
sandbox.run_in_branch(&mut branch, &["sh", "-c", "make test"]).await?;
let checkpoint = branch.checkpoint("/var/lib/controller/snapshots")?;
```

The snapshot storage and branch storage paths are trusted backend state. Do not
grant them to sandboxed processes. The snapshot root itself should only receive
a read grant; COW writes are redirected into the branch upper.

## Attached checkpoint boundary

An attached branch is owned by the sandbox and cannot be inspected by taking
its physical upper. Stop the complete managed process group first, then capture
through the returned `PauseGuard`:

```rust
let guard = sandbox.pause_and_wait(Duration::from_secs(5)).await?;
let checkpoint = guard
    .checkpoint_attached_fs_branch("/var/lib/controller/snapshots")
    .await?;

// The caller decides whether and when execution resumes.
guard.resume()?;
```

The guard keeps the process group stopped for the entire copy and temporarily
suspends Sandlock's CPU throttle so it cannot issue `SIGCONT` behind the guard.
The checkpoint
performs blocking filesystem I/O while it owns the branch state, so controllers
should invoke it from a worker/runtime context where that blocking is acceptable.
Writers outside the managed process group are not stopped by Sandlock.

## Consistency and durability

Capture and checkpoint use this success boundary:

1. copy the complete lower into a private staging directory;
2. for a branch, apply whiteouts and then the upper to staging;
3. fsync regular files, directories, lease metadata, and snapshot metadata;
4. atomically rename staging to its final snapshot directory;
5. fsync the storage directory before returning the descriptor.

An unpublished staging directory is removed after an ordinary failure and is
never accepted by `FsSnapshot::reopen`. Sandlock compares source metadata before
and after a copy and returns `SnapshotError::SourceChanged` when it detects a
concurrent mutation. Open regular files are also checked against the path before
and after copying to reject path swaps. This is best-effort detection, not a
global filesystem write lock:
the controller must quiesce every writer it manages before capture.

`FsSnapshotDescriptor` and persisted branch records are opaque handles for a
trusted controller. Every open snapshot handle and snapshot-backed branch holds
a filesystem lease. `FsSnapshot::destroy` rejects concurrent handles, live
branches, and durable persisted branches. Crash-released handle leases and
unpublished orphan branches are reclaimed conservatively. Persisting and
reopening an `FsBranch` preserves its snapshot lease.

## Inspection and export

The snapshot API provides:

- `stat(path)` for entry type, permission mode, length, and symlink target;
- `read_range(path, offset, max_bytes)` for bounded binary reads;
- `list(path, offset, max_entries)` for bounded deterministic listings;
- `diff(other, max_changes)` for the first bounded structured change page;
- `diff_after(other, cursor, max_changes)` to continue from `next_path`;
- `materialize(destination)` for atomic full-tree export to a new path;
- `destroy()` for explicit, lease-aware storage reclamation.

All input paths are snapshot-relative. Absolute paths and `..` components are
rejected, final symlinks are not followed by `stat` or `read_range`, and a
symlinked parent cannot escape the snapshot root.

Inspection applies hard entry, path-byte, and diff-content budgets in addition
to caller result limits. Exceeding a budget returns
`SnapshotError::LimitExceeded`; it never silently returns a partial tree.
Materialization stages under mode `0700`, creates regular files as `0600`, then
applies captured modes. If the destination rename succeeds but parent-directory
fsync fails, `SnapshotError::Materialized` reports the published destination
instead of presenting the operation as side-effect free.
Likewise, snapshot deletion returns `SnapshotError::Destroyed` if the tree was
removed but the parent-directory durability barrier could not be confirmed.

## Typed derivation

`FsSnapshot::derive` applies an ordered, bounded `SnapshotMutation` batch to a
private copy of the immutable base and publishes a new snapshot through the
same durability boundary as capture/checkpoint. The base never changes.

Supported mutations are regular-file put/remove and directory make/remove.
Regular-file payloads are trusted controller files opened without following
their final symlink and checked for replacement while copied. Mutation count,
aggregate payload bytes, relative paths, modes, duplicate targets, symlink
parents and entry types are validated before publication. This API does not
assign application revision identity or provide a payload upload protocol.

## Scoped comparison

`FsSnapshot::compare_requirements` compares two immutable trees under bounded
generic filesystem scopes:

- `Content`: exact state of one path;
- `Entries`: immediate child names and kinds;
- `TreeEntries`: recursive descendant names and kinds;
- `TreeContent`: recursive exact kinds, modes, symlink targets and file bytes.

The caller supplies dependencies. Sandlock does not infer tool reads, ignore
files, query semantics or application cache keys. Requirements, scanned entries,
path bytes and compared content bytes all have explicit caller limits.

## Snapshot delta

`FsSnapshot::delta_to` prepares a complete bounded BASE-to-TARGET
`SnapshotDelta`. It rejects a delta that exceeds changed-path/replacement-byte
limits, overlaps caller-supplied protected paths, or contains symlinks when the
selected generic policy disables them.

`SnapshotDelta::apply_to_directory` takes the same per-workdir commit lock used
by ordinary COW commits, validates every changed destination path against BASE,
and then applies only those paths. Unrelated destination changes are preserved.
`Initial` mode rejects conflicts before writing; `Resume` accepts paths already
equal to TARGET and converges an earlier partial application.

The operation is not a cross-path atomic filesystem transaction. Each file
replacement is atomic, but an I/O failure after the first mutation returns
`SnapshotError::DeltaApplyIncomplete`. A durable controller must keep the
destination quiescent, persist its own operation journal, and retry the same
BASE/TARGET delta with `Resume` before allowing its managed writer to continue.
Sandlock keeps no application operation registry or daemon.

## Paused attached branch delta

`PauseGuard::apply_attached_fs_delta` keeps the managed process group stopped
and holds the branch operation gate across three steps:

1. checkpoint the current attached merged view into caller-owned validation
   storage;
2. validate changed paths and generic declared requirements against BASE;
3. write the delta into the existing upper/whiteout state without detaching or
   replacing the branch.

The temporary validation snapshot is destroyed before the method returns. The
guard still owns `resume` or a kill that never briefly resumes user code. A failed upper mutation can leave a partial but
checkpointable branch; the controller must retain the stopped boundary and
derive a remainder delta during recovery.

## Filesystem fidelity in the first implementation

The first implementation preserves regular-file bytes, directory structure,
symlink targets, and permission/special mode bits. It accepts non-UTF-8 names
when capturing, inspecting, diffing, and materializing a snapshot. Existing
seccomp COW branch paths and whiteouts are UTF-8, so a branch checkpoint rejects
a non-UTF-8 upper or deletion path instead of publishing an incomplete view.

Hard-linked regular files are captured as independent regular files. Sparse
allocation, ownership, timestamps, xattrs, ACLs, file flags, and hardlink
identity are not preserved. FIFOs, sockets, and device nodes are rejected with
`SnapshotError::UnsupportedFileType`. Snapshot capture requires the controller
to have read and traversal access to the complete source tree.

## Linux tests

Snapshot storage unit tests run without starting a sandbox. Branch behavior and
the attached writer boundary require Linux seccomp user notification:

```bash
cargo test -p sandlock-core snapshot:: --lib -- --test-threads=1
cargo test -p sandlock-core branch::tests --lib -- --test-threads=1
cargo test -p sandlock-core --test integration test_workspace_snapshot \
  -- --test-threads=1
```
