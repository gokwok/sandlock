# Explicit COW branch resolution

Sandlock normally resolves a copy-on-write (COW) filesystem branch when
the sandbox is dropped: a successful run commits according to `on_exit`,
and an error aborts according to `on_error`. Explicit branch resolution
separates those two events. The Action may finish while its filesystem
changes remain private, and a controller can later choose exactly one of:

- **commit** — merge the staged changes into `workdir`;
- **abort** — discard the staged changes.

This is intended for speculative Action execution. A controller can start
likely tool calls while an Agent is still reasoning, wait for the actual
tool decision, commit the matching branch, and abort the others. It is also
useful whenever command completion and publication must be separate steps.

Explicit branch resolution is available through:

| Surface | Entry point | Ownership model |
|---|---|---|
| Rust API | `Sandbox::create_fs_branch` / `Sandbox::run_in_branch` | The caller owns a reusable `FsBranch` handle |
| Rust compatibility API | `Sandbox::run_pending` / `Sandbox::take_pending_branch` | `PendingBranch` is an alias for `FsBranch` |
| CLI | `sandlock run --defer-commit` | The CLI process owns the branch and waits on a decision fd |

The Python, Go, and C APIs do not currently expose `FsBranch`
directly. They can orchestrate the CLI protocol as a subprocess.

### Relationship to `Transaction`

`Transaction` and `FsBranch` share Sandlock's internal COW branch, commit
lock, merge, preservation, and recovery machinery, but expose different
ownership semantics:

- `Transaction` executes a fixed list of stages sequentially over one shared
  upper and resolves it automatically when the stage set finishes.
- `FsBranch` lets the caller retain the upper between arbitrary Actions,
  switch between independent branches, and choose when to commit or abort.
- `--defer-commit` is the one-Action CLI form of that external decision gate.

Use `Transaction` when the stage graph and success policy are known before
execution. Use `FsBranch` or `--defer-commit` when an Agent or controller must
make the publication decision after the Action has already completed.

## Lifecycle

The branch lifecycle is deliberately small:

```text
              Action exits
                  |
                  v
Pending/Open -> Running
      ^           |
      |-----------|
      |
      +-- commit --> Committed
      +-- abort  --> Aborted
```

While the branch is `Pending`:

- the Action and its seccomp supervisor have already been reaped;
- the real `workdir` has not been changed by that branch;
- staged file contents remain in the on-disk COW upper directory;
- the owner retains only the branch handle and metadata in memory.

`Pending` normally remains owned by its Rust handle. A controller that needs
to stop may call `FsBranch::persist`, retain the returned `PreservedBranch`
record, and pass it to `FsBranch::reopen` in a later process. Persistence is
available only before a commit attempt and records the conflict-detection
baseline as well as the upper and deletions. Sandlock still provides no branch
registry or daemon; the controller owns the durable record and storage path.

## Filesystem boundary

Explicit resolution covers only writes intercepted under `workdir`. A path
made writable outside `workdir` is not part of this branch and may be changed
immediately by the Action. Configure the sandbox so every path that must be
speculative is inside `workdir`.

An `FsBranch` records the lower-layer state of each path when the branch first
modifies it. Commit fails with `BranchError::Conflict` if one of those paths
changed in the lower layer. Branches that modify disjoint paths may therefore
commit in sequence. This is write-conflict detection, not snapshot isolation:
unmodified reads follow the live lower directory, and Sandlock does not track
read dependencies. Conflict validation runs after taking the same per-workdir
commit lock used by `Transaction`, immediately before the merge begins.

Commit is a filesystem merge, not an atomic transaction. A failed commit
leaves the handle pending, but some paths may already have been copied into
the real workdir. Retrying or aborting the handle does not roll those paths
back.

## Rust API

### Reusable `FsBranch`

Create branches independently of command execution, then run any number of
serial Actions against each branch:

```rust
use sandlock_core::Sandbox;

let mut sandbox = Sandbox::builder()
    .fs_read("/usr")
    .fs_read("/lib")
    .fs_read_if_exists("/lib64")
    .fs_read("/bin")
    .fs_write("/workspace")
    .workdir("/workspace")
    .build()?;

let mut branch_a = sandbox.create_fs_branch()?;
let mut branch_b = sandbox.create_fs_branch()?;

sandbox.run_in_branch(&mut branch_a, &["sh", "-c", "npm install"]).await?;
sandbox.run_in_branch(&mut branch_b, &["sh", "-c", "cargo build"]).await?;
sandbox.run_in_branch(&mut branch_a, &["sh", "-c", "npm test"]).await?;

branch_a.commit()?;
branch_b.commit()?; // succeeds only if its modified lower paths are unchanged
```

Selecting another branch is just passing a different `FsBranch` handle to
`run_in_branch`; Sandlock has no workspace registry or implicit current
branch. A branch supports one running Action at a time and retains filesystem
state only. `commit` and `abort` remain terminal operations.

`FsBranch::conflicts()` returns the relative paths that currently fail lower
state validation. Conflict detection uses filesystem identity and metadata; it
does not perform content merges or identify a stale output derived from a file
that the Action only read.

### `Sandbox::run_pending`

`run_pending` is the one-shot entry point. It starts the Action with captured
stdout/stderr, waits for it, reaps the supervisor, and returns both the
`RunResult` and retained branch:

```rust
use sandlock_core::Sandbox;

let mut sandbox = Sandbox::builder()
    .fs_read("/usr")
    .fs_read("/lib")
    .fs_read_if_exists("/lib64")
    .fs_read("/bin")
    .fs_write("/workspace")
    .workdir("/workspace")
    .build()?;

let pending = sandbox
    .run_pending(&[
        "sh",
        "-c",
        "printf 'generated\n' > /workspace/result.txt",
    ])
    .await?;

let (result, mut branch) = pending.into_parts();

if action_was_selected && result.success() {
    branch.commit()?;
} else {
    branch.abort()?;
}
```

`run_pending` requires:

- an effective `workdir`;
- the seccomp supervisor (`no_supervisor` must be false);
- a fresh `Sandbox` lifecycle, like the regular `run` method.

The sandbox's `on_exit` and `on_error` settings are not applied. Ownership
of the COW branch is transferred to the returned `PendingBranch`.

### Result and branch types

`PendingRunResult` contains two public fields and can also be split with
`into_parts()`:

```rust
pub struct PendingRunResult {
    pub run_result: RunResult,
    pub branch: PendingBranch,
}
```

The retained branch exposes:

| Method | Result |
|---|---|
| `state()` | `BranchState::Pending`, `Committed`, `Aborted`, `Persisted`, `Attached`, or `Kept` |
| `workdir()` | Lower directory that receives a successful commit |
| `upper_dir()` | On-disk staging directory; removed after resolution |
| `changes()` | Added, modified, and deleted paths relative to `workdir` |
| `conflicts()` | Modified paths whose lower-layer state has changed |
| `commit()` | Merge the branch into `workdir` |
| `abort()` | Discard the branch |
| `persist()` | Release the branch into durable storage for a later process |
| `keep()` | Preserve the branch for manual recovery without merging it |
| `reopen()` | Recover a branch returned by `persist()` |

Change inspection is optional:

```rust
for change in branch.changes()? {
    println!("{change}"); // for example: "M  src/main.rs"
}
```

`changes()` scans the branch. Avoid calling it on a large dependency install
unless the controller actually needs the path list.

Calling `changes`, `commit`, or `abort` after the branch has been resolved
returns `BranchError::AlreadyResolved`. A failed commit or abort leaves the
handle in `BranchState::Pending`.

If `persist()` or `keep()` publishes its recovery marker but a later directory
sync fails, it returns `BranchError::Published` carrying the recovery record.
The source handle is resolved because the marker is already claimable.

### Live process attachment

`Sandbox::attach_fs_branch` moves an existing pending branch into the next
process created by that sandbox. This works with the ordinary interactive and
PTY lifecycle APIs. After the process has stopped,
`Sandbox::take_attached_fs_branch` returns the same branch with its accumulated
changes. The caller must recover that handle before reusing the sandbox.
The source handle reports `BranchState::Attached` during this interval.

An on-disk `Attached` marker is an ownership warning, not a recoverable
handoff. A controller must not reopen, apply, or remove it merely because the
recorded PID exited: sandbox descendants can outlive that process and retain
writable descriptors into the upper. `take_attached_fs_branch` first kills and
drains the constrained process group before removing this warning. Dropping the
sandbox preserves the upper and leaves the warning in place; recovery then
requires operator proof that no descendant can still access it.

### Drop behavior

Dropping an unresolved `PendingRunResult` or `PendingBranch` attempts to abort
the branch:

```rust
let pending = sandbox.run_pending(&command).await?;
drop(pending); // staged changes are discarded
```

This is a fail-closed guard for early returns and `?` propagation. It is
best-effort cleanup: process termination that skips destructors, such as
`SIGKILL`, cannot run the abort path.

### Manual lifecycle with `take_pending_branch`

Use `take_pending_branch` when the caller already manages the two-phase
sandbox lifecycle, needs inherited stdio, or performs bookkeeping between
start and wait:

```rust
let mut sandbox = Sandbox::builder()
    .fs_read("/usr")
    .fs_read("/lib")
    .fs_read_if_exists("/lib64")
    .fs_read("/bin")
    .workdir("/workspace")
    .build()?;

sandbox.create_interactive(&["make", "build"]).await?;
sandbox.start()?;
let result = sandbox.wait().await?;
let mut branch = sandbox.take_pending_branch()?;

if result.success() {
    branch.commit()?;
} else {
    branch.abort()?;
}
```

`take_pending_branch` returns:

- `BranchError::NotReady` if the Action has not reached the stopped state;
- `BranchError::Unavailable` when no retained COW branch exists.

Taking the branch releases the stopped sandbox runtime. The returned handle
is lightweight and owns the staged filesystem state.

### Speculative winner selection

Independent sandboxes may run concurrently against the same lower workdir.
Each receives its own COW upper directory:

```rust
let mut candidate_a = template.clone().with_name("candidate-a");
let mut candidate_b = template.with_name("candidate-b");

let action_a = candidate_a.run_pending(&["sh", "-c", "make candidate-a"]);
let action_b = candidate_b.run_pending(&["sh", "-c", "make candidate-b"]);

let (pending_a, pending_b) = tokio::try_join!(action_a, action_b)?;
let (_, mut branch_a) = pending_a.into_parts();
let (_, mut branch_b) = pending_b.into_parts();

// The Agent selected candidate B. Publish exactly one branch.
branch_b.commit()?;
branch_a.abort()?;
```

The complete runnable example is
[`speculative_branches.rs`](../crates/sandlock-core/examples/speculative_branches.rs):

```bash
cargo run -p sandlock-core --example speculative_branches
```

## CLI

### Synopsis

Deferred CLI resolution adds three flags to `sandlock run`:

```bash
sandlock run \
  --workdir /workspace \
  --defer-commit \
  --decision-fd 3 \
  --status-fd 4 \
  -- command
```

| Flag | Direction | Description |
|---|---|---|
| `--defer-commit` | n/a | Retain the completed COW branch for an explicit decision |
| `--status-fd FD` | Sandlock → controller | Write one JSON line when the branch is pending |
| `--decision-fd FD` | Controller → Sandlock | Read one `commit` or `abort` line |

Both control descriptors must be open when Sandlock starts, must be distinct,
and must be numbered 3 or higher. File descriptors 0, 1, and 2 remain the
Action's stdin, stdout, and stderr. The control descriptors are duplicated
with `FD_CLOEXEC`, and the sandbox child closes unrelated descriptors before
exec, so the Action cannot send its own status or decision.

`--defer-commit` requires an effective `workdir` and conflicts with:

- `--dry-run`;
- `--no-supervisor`;
- `--on-exit`;
- `--on-error`.

### Wire protocol

The protocol has one status message and one decision:

1. Sandlock runs the Action with its normal inherited stdio.
2. The Action exits and the supervisor is reaped.
3. Sandlock detaches the COW branch and writes one newline-delimited JSON
   status message.
4. Sandlock blocks on `decision-fd`; the real workdir is still unchanged.
5. The controller writes `commit\n` or `abort\n`.
6. Sandlock resolves the branch and exits.

A normal exit produces:

```json
{"state":"pending","exit_code":0}
```

An Action terminated by a signal includes the signal number:

```json
{"state":"pending","exit_code":-1,"signal":9}
```

The status intentionally does not include the branch's changed-path list.
Large Actions such as package installation may stage tens of thousands of
paths; scanning and serializing them on the ready path would add latency and
could block on the status pipe.

The only valid decisions are:

```text
commit
```

and:

```text
abort
```

Leading and trailing whitespace is ignored, but no other decision value is
accepted.

### Exit and failure behavior

After a successful commit or abort, Sandlock returns the Action's numeric
exit code. When the Action has no numeric exit code, the CLI returns 1.

The CLI fails and attempts to abort any still-pending branch when:

- `status-fd` cannot be written;
- `decision-fd` reaches EOF before a decision;
- the decision is neither `commit` nor `abort`;
- the requested branch operation fails.

If `--timeout` expires before the pending state is reached, Sandlock exits
with 124 and aborts the branch without sending a pending status message.

The CLI process must remain alive until the decision. Normal error unwinding
and decision EOF run the abort guard. `SIGKILL` bypasses process cleanup and
may leave the temporary upper directory behind.

### Python controller

The following controller creates the two pipes, waits for the pending event,
and then publishes the branch:

```python
import json
import os
import subprocess

status_read, status_write = os.pipe()
decision_read, decision_write = os.pipe()

process = subprocess.Popen(
    [
        "sandlock", "run",
        "-r", "/usr", "-r", "/lib", "-r", "/lib64", "-r", "/bin",
        "--workdir", "/workspace",
        "--defer-commit",
        "--decision-fd", str(decision_read),
        "--status-fd", str(status_write),
        "--",
        "sh", "-c", "make build",
    ],
    pass_fds=(decision_read, status_write),
)

os.close(decision_read)
os.close(status_write)

with os.fdopen(status_read) as status_stream:
    status = json.loads(status_stream.readline())

assert status["state"] == "pending"

# The Agent's reasoning result selects this speculative Action.
os.write(decision_write, b"commit\n")
os.close(decision_write)

exit_code = process.wait()
```

On systems without `/lib64`, omit that read path. Production controllers
should also close the decision writer and reap the process on every error
path.

The complete example exercises both commit and abort and verifies that the
real workdir remains unchanged before each decision:

```bash
cargo build -p sandlock-cli
python3 crates/sandlock-cli/examples/deferred_commit.py
```

See
[`deferred_commit.py`](../crates/sandlock-cli/examples/deferred_commit.py)
for the full controller.

## Tests

The branch lifecycle and CLI protocol require a real Linux kernel with
seccomp user notification:

```bash
# FsBranch lifecycle unit tests
cargo test -p sandlock-core branch::tests -- --test-threads=1

# Real COW commit/abort integration tests
cargo test -p sandlock-core --test integration pending_branch -- --test-threads=1

# CLI fd protocol and end-to-end commit/abort tests
cargo test -p sandlock-cli deferred -- --test-threads=1

# Standalone controller example
python3 crates/sandlock-cli/examples/deferred_commit.py
```

On macOS, run these commands in the project's Orb Linux environment.

## Operational guidance

- Start each speculative Action in its own `Sandbox` or `sandlock run`
  process. A branch has exactly one owner.
- Keep the real workdir unchanged while reasoning and speculative Actions
  are in flight.
- Serialize commits that target the same lower workdir.
- Disjoint write sets may commit sequentially; overlapping writes conflict.
- Abort losers promptly to release their upper directories.
- Treat commit failure as potentially partial.
- Put every path whose changes must be reversible under `workdir`.
- Use `changes()` only when path-level inspection is worth its scan cost.

This feature retains filesystem state only. It does not retain the Action's
process, memory, open files, sockets, or other application state, and it is
separate from Sandlock checkpoint/resume.
