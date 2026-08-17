//! Freeze sandbox threads of an execve caller before exposing argv.
//!
//! # Why
//!
//! Per `seccomp_unotify(2)`, after the supervisor responds with
//! `Continue`, the kernel re-reads the syscall's user-memory pointers
//! before executing the syscall. For execve, that means the kernel
//! re-reads `pathname` and the argv array from child memory. Any task
//! that can write to that memory in the window between the supervisor's
//! inspection and the kernel's re-read can defeat the decision
//! `policy_fn` made on the values it saw.
//!
//! Two distinct task classes can write that memory:
//! 1. Sibling threads of the calling tid (same TGID; share `mm_struct`
//!    by definition).
//! 2. Peer processes in other TGIDs that alias the same pages via
//!    `MAP_SHARED` mappings (memfd, SysV shm, shared file mmap), or
//!    that share the calling task's `mm_struct` via
//!    `clone(CLONE_VM)` without `CLONE_THREAD`.
//!
//! `freeze_sandbox_for_execve` closes both classes. Every process-creating
//! fork-like syscall is traced for one ptrace fork/clone/vfork event and the
//! child is registered in
//! `ProcessIndex` before it can run user code. The exec freeze can
//! therefore enumerate every tracked TGID, walk `/proc/<tgid>/task`,
//! and `PTRACE_SEIZE` + `PTRACE_INTERRUPT` every TID that could mutate
//! argv.
//!
//! # Sibling vs peer cleanup
//!
//! Sibling threads (same TGID as the caller) are killed by the kernel
//! during execve's `de_thread` step when execve is allowed, so the pinned
//! freeze worker does not detach them on the allow path — their ptrace state
//! is reaped along with the threads. If the policy callback denies execve
//! after argv inspection, that same worker detaches both siblings and peers
//! because `de_thread` will not run.
//!
//! Peer threads (different TGID) survive execve. The worker retains ptrace
//! ownership across the asynchronous policy verdict and `NOTIF_SEND`, then
//! performs `PTRACE_DETACH` on the same OS thread that seized them. This is
//! required because Linux ptrace ownership belongs to a tracer task; moving
//! cleanup to another Tokio worker can leave a parent in `ptrace_stop`.
//!
//! # Failure modes (strict)
//!
//! The freeze is an invariant: if the supervisor exposed argv to
//! `policy_fn` and the callback returned Allow, the kernel must re-read
//! the same memory the supervisor inspected. We refuse to silently
//! degrade — if the freeze cannot be established, the supervisor
//! denies the execve with `EPERM` rather than letting it proceed
//! without TOCTOU protection.
//!
//! - `PTRACE_SEIZE` returns `ESRCH` for a sibling that exited between
//!   enumeration and seize. Treated as success: there is no thread to
//!   race.
//! - Any other ptrace failure (YAMA `ptrace_scope` >= 2 outside the
//!   parent chain, another tracer attached, kernel resource limits)
//!   produces an error; siblings already frozen during the partial
//!   attempt are detached so they resume normally; the caller fails
//!   the syscall closed.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::sync::Arc;

/// Read the `State:` field from `/proc/<tid>/status`. Returns the
/// single-character state code (`R`, `S`, `D`, `T`, `t`, `Z`, `X`)
/// or `None` if the file or line is unreadable.
fn read_task_state(tid: i32) -> Option<char> {
    let status = fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    let line = status.lines().find(|l| l.starts_with("State:"))?;
    // Format is "State:\t<char> (<word>)" — find the first non-space
    // character after the colon.
    line.split_whitespace().nth(1).and_then(|s| s.chars().next())
}

/// What `seize_and_interrupt` did with one tid.
#[derive(Debug, PartialEq, Eq)]
enum SeizeOutcome {
    /// Confirmed ptrace-stopped; must be detached later.
    Frozen,
    /// No attachment exists (already exited, or held in an uninterruptible
    /// kernel wait without ever being seized): nothing to release.
    NotNeeded,
    /// Seized with the interrupt queued, but the task entered an
    /// uninterruptible kernel wait before stopping. It cannot run user code
    /// (so it cannot mutate argv), and it will trap into ptrace-stop the
    /// moment its wait clears. The caller must reap and detach it AFTER the
    /// execve response is sent — for the vfork parent, the wait clears only
    /// once that very execve resolves.
    PendingStop,
}

/// `PTRACE_SEIZE` + `PTRACE_INTERRUPT` a single tid and reap the confirmed
/// ptrace-stop without ever blocking unboundedly.
///
/// # Why the reap must be bounded
///
/// A task in `TASK_UNINTERRUPTIBLE` (`State: D`) — most commonly the vfork
/// parent of the execve caller, suspended in `kernel_clone` until its child
/// execs — cannot enter ptrace-stop until its kernel wait clears. For vfork
/// specifically, the wait won't clear until we send Continue, but we can't
/// send Continue while we're blocked in `waitpid` for that exact task: an
/// unbounded waitpid here deadlocks the whole supervisor. The pre-check on
/// `/proc/<tid>/status` catches a task already parked in `D`, but it RACES
/// the tracee — the vfork parent can pass the check runnable and park
/// before the interrupt lands (seen in the wild under CPU load). So after
/// arming the interrupt the reap polls with `WNOHANG`, and a task observed
/// in `D` is handed back as [`SeizeOutcome::PendingStop`] instead of being
/// waited for.
///
/// On a partial-progress failure (PTRACE_SEIZE succeeded but
/// PTRACE_INTERRUPT did not), the function detaches itself before
/// returning so the caller doesn't have to track partial state.
fn seize_and_interrupt(tid: i32) -> io::Result<SeizeOutcome> {
    // Fast path: the kernel is already holding this task; it cannot mutate
    // user memory and does not need an attachment.
    if let Some('D' | 'Z' | 'X') = read_task_state(tid) {
        return Ok(SeizeOutcome::NotNeeded);
    }

    let ret = unsafe {
        libc::ptrace(libc::PTRACE_SEIZE as libc::c_uint, tid, 0, 0)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(SeizeOutcome::NotNeeded); // already exited
        }
        if matches!(read_task_state(tid), Some('Z' | 'X')) {
            return Ok(SeizeOutcome::NotNeeded);
        }
        return Err(err);
    }
    // PTRACE_SEIZE succeeded; from here, any error path must DETACH
    // before returning so we don't leave the task traced-but-running.

    let ret = unsafe {
        libc::ptrace(libc::PTRACE_INTERRUPT as libc::c_uint, tid, 0, 0)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(SeizeOutcome::NotNeeded);
        }
        return Err(err);
    }

    // Bounded reap. A runnable task stops within a scheduling quantum; the
    // budget only exists so a starved box still converges. `__WALL` because
    // siblings are threads, which waitpid(2) ignores by default.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let mut status: i32 = 0;
        let r = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
        if r == tid {
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Ok(SeizeOutcome::NotNeeded);
            }
            if libc::WIFSTOPPED(status) {
                return Ok(SeizeOutcome::Frozen);
            }
        } else if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                // Reaped elsewhere or gone: nothing left to hold.
                return Ok(SeizeOutcome::NotNeeded);
            }
        }
        if read_task_state(tid) == Some('D') {
            return Ok(SeizeOutcome::PendingStop);
        }
        if std::time::Instant::now() >= deadline {
            let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("tid {tid} did not enter ptrace-stop within the freeze budget"),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Detach a previously-frozen task. Used to roll back partial
/// progress when a later task refuses to be frozen, and to release
/// peer tasks after the kernel has re-read execve argv.
fn detach(tid: i32) {
    let _ = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
}

/// Enumerate every TID in a TGID via `/proc/<tgid>/task/`. Linux
/// resolves `/proc/<any_tid>/task` to the same directory, so this
/// works whether `tgid` is the leader's PID or any TID in the group.
fn list_threads_of_tgid(tgid: i32) -> io::Result<Vec<i32>> {
    let dir = fs::read_dir(format!("/proc/{}/task", tgid))?;
    let mut tids = Vec::new();
    for entry in dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if let Ok(tid) = name_str.parse::<i32>() {
            tids.push(tid);
        }
    }
    Ok(tids)
}

/// Read the TGID containing `tid`, as an `io::Result` so a missing or
/// unparseable value aborts the freeze instead of silently narrowing it
/// to one task.
fn read_tgid_of_tid(tid: i32) -> io::Result<i32> {
    crate::seccomp::state::read_tgid_of_tid(tid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no usable Tgid: line in /proc/<tid>/status",
        )
    })
}

/// Outcome of a sandbox-wide freeze.
#[derive(Debug, Default)]
pub(crate) struct SandboxFreeze {
    /// Sibling TIDs in the caller's TGID. These die in `de_thread` if
    /// execve is allowed, but must be detached if execve is denied
    /// after `policy_fn` inspected argv.
    pub sibling_tids: Vec<i32>,
    /// TIDs in *other* TGIDs that were ptrace-stopped. These survive
    /// execve and must be detached so they can resume normal
    /// execution.
    pub peer_tids: Vec<i32>,
    /// TIDs seized with a queued interrupt that had entered an
    /// uninterruptible kernel wait before stopping (the vfork parent racing
    /// the freeze). Kernel-held for the duration of the freeze window; must
    /// be reaped by the pinned worker after the execve response is sent.
    pub pending_tids: Vec<i32>,
}

/// A freeze that could not be completed. Carries any tasks that were left
/// with a queued interrupt and could not be released during rollback (they
/// had not entered ptrace-stop yet); the pinned worker reaps them after the
/// deny response, for the same reason the freeze itself could not wait.
#[derive(Debug)]
pub(crate) struct FreezeError {
    pub error: io::Error,
    pub pending_tids: Vec<i32>,
}

impl std::fmt::Display for FreezeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

enum ExecFreezeCommand {
    Finish { exec_continued: bool },
}

/// Pinned-thread owner for one exec argv freeze.
///
/// Linux records ptrace ownership against the tracer *task*, not merely its
/// thread group. The seccomp notification future awaits the policy callback
/// while peers are frozen and may resume on another Tokio worker. Keeping the
/// complete SEIZE/INTERRUPT/WAIT/DETACH lifecycle in one dedicated OS thread
/// prevents a cross-worker `PTRACE_DETACH` from failing with ESRCH and leaving
/// a parent permanently in `ptrace_stop` beside a zombie child. Thread exit is
/// also the kernel-level last-resort detach boundary if cleanup itself fails.
pub(crate) struct ExecFreezeTrace {
    cmd_tx: std::sync::mpsc::SyncSender<ExecFreezeCommand>,
    join: Option<std::thread::JoinHandle<io::Result<()>>>,
    caller_tid: i32,
    processes: Arc<crate::seccomp::state::ProcessIndex>,
    signaled: bool,
}

impl Drop for ExecFreezeTrace {
    fn drop(&mut self) {
        if !self.signaled {
            let _ = self.cmd_tx.send(ExecFreezeCommand::Finish {
                exec_continued: false,
            });
        }
    }
}

/// Result of arming a pinned exec freeze. A failed freeze still returns its
/// trace owner so partial/pending attachments can be released after the
/// seccomp denial response is sent.
pub(crate) struct ExecFreezePreparation {
    pub trace: ExecFreezeTrace,
    pub failure: Option<String>,
}

struct ExecFreezeActivity(Arc<crate::seccomp::state::ProcessIndex>);

impl Drop for ExecFreezeActivity {
    fn drop(&mut self) {
        self.0.exec_freeze_finished();
    }
}

/// Freeze peers on one dedicated OS thread and retain that same thread until
/// the caller has sent the execve response and asks it to detach.
pub(crate) async fn prepare_exec_freeze(
    processes: Arc<crate::seccomp::state::ProcessIndex>,
    caller_tid: i32,
) -> io::Result<ExecFreezePreparation> {
    let worker_processes = Arc::clone(&processes);
    let (prepared_tx, prepared_rx) = tokio::sync::oneshot::channel::<Option<String>>();
    let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<ExecFreezeCommand>(1);
    let join = std::thread::Builder::new()
        .name("sandlock-exec-freeze".to_owned())
        .spawn(move || {
            worker_processes.exec_freeze_started();
            let _activity = ExecFreezeActivity(Arc::clone(&worker_processes));
            let freeze = freeze_sandbox_for_execve(&worker_processes, caller_tid);
            let failure = freeze.as_ref().err().map(ToString::to_string);
            if prepared_tx.send(failure).is_err() {
                cleanup_exec_freeze(freeze, false)?;
                return Ok(());
            }
            let exec_continued = matches!(
                cmd_rx.recv(),
                Ok(ExecFreezeCommand::Finish {
                    exec_continued: true
                })
            );
            cleanup_exec_freeze(freeze, exec_continued)
        })?;

    match prepared_rx.await {
        Ok(failure) => Ok(ExecFreezePreparation {
            trace: ExecFreezeTrace {
                cmd_tx,
                join: Some(join),
                caller_tid,
                processes,
                signaled: false,
            },
            failure,
        }),
        Err(_) => {
            let _ = join_exec_freeze_thread(join).await;
            Err(io::Error::other(
                "exec freeze worker exited before reporting readiness",
            ))
        }
    }
}

/// Release a pinned exec freeze after the seccomp response has been sent.
/// Cleanup is bounded; if the owner cannot detach, the complete caller process
/// group is killed before one final reap attempt so the supervisor never
/// silently returns while retaining a live ptrace attachment.
pub(crate) async fn finish_exec_freeze(
    mut trace: ExecFreezeTrace,
    exec_continued: bool,
) -> io::Result<()> {
    const CLEANUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
    const KILLED_CLEANUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

    trace.signaled = true;
    let caller_tid = trace.caller_tid;
    let processes = Arc::clone(&trace.processes);
    let _ = trace
        .cmd_tx
        .send(ExecFreezeCommand::Finish { exec_continued });
    let join = trace.join.take().expect("exec freeze join handle");
    let mut join = tokio::task::spawn_blocking(move || join_exec_freeze_thread_blocking(join));
    match tokio::time::timeout(CLEANUP_DEADLINE, &mut join).await {
        Ok(result) => result.map_err(|error| {
            io::Error::other(format!("exec freeze join task failed: {error}"))
        })?,
        Err(_) => {
            kill_execution_group(caller_tid);
            emit_exec_freeze_diagnostic(
                &processes,
                caller_tid,
                "cleanup_timeout",
                "pinned exec freeze worker exceeded its cleanup deadline",
            );
            match tokio::time::timeout(KILLED_CLEANUP_DEADLINE, &mut join).await {
                Ok(result) => {
                    result.map_err(|error| {
                        io::Error::other(format!("exec freeze join task failed: {error}"))
                    })??;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "exec freeze cleanup required terminating the execution group",
                    ))
                }
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "exec freeze worker did not terminate after execution-group kill",
                )),
            }
        }
    }
}

async fn join_exec_freeze_thread(
    join: std::thread::JoinHandle<io::Result<()>>,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || join_exec_freeze_thread_blocking(join))
        .await
        .map_err(|error| io::Error::other(format!("exec freeze join task failed: {error}")))?
}

fn join_exec_freeze_thread_blocking(
    join: std::thread::JoinHandle<io::Result<()>>,
) -> io::Result<()> {
    join.join()
        .map_err(|_| io::Error::other("exec freeze worker panicked"))?
}

fn cleanup_exec_freeze(
    freeze: Result<SandboxFreeze, FreezeError>,
    exec_continued: bool,
) -> io::Result<()> {
    let mut cleanup_error = None;
    let mut record = |result: io::Result<()>| {
        if let Err(error) = result {
            if cleanup_error.is_none() {
                cleanup_error = Some(error);
            }
        }
    };
    match freeze {
        Ok(freeze) => {
            if exec_continued {
                record(detach_tids_checked(&freeze.peer_tids));
            } else {
                record(detach_tids_checked(&freeze.sibling_tids));
                record(detach_tids_checked(&freeze.peer_tids));
            }
            record(reap_pending_checked(&freeze.pending_tids));
        }
        Err(error) => record(reap_pending_checked(&error.pending_tids)),
    }
    cleanup_error.map_or(Ok(()), Err)
}

fn detach_tids_checked(tids: &[i32]) -> io::Result<()> {
    let mut first_error = None;
    for &tid in tids {
        let ret = unsafe { libc::ptrace(libc::PTRACE_DETACH, tid, 0, 0) };
        if ret < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) && first_error.is_none() {
                first_error = Some(io::Error::new(
                    error.kind(),
                    format!("detach ptrace tid {tid}: {error}"),
                ));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn reap_pending_checked(pending: &[i32]) -> io::Result<()> {
    for &tid in pending {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut status: i32 = 0;
            let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
            if result == tid {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    break;
                }
                if libc::WIFSTOPPED(status) {
                    detach_tids_checked(&[tid])?;
                    break;
                }
            } else if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("tid {tid} did not reach its pending ptrace stop"),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    Ok(())
}

fn kill_execution_group(caller_tid: i32) {
    let process_group = std::fs::read_to_string(format!("/proc/{caller_tid}/stat"))
        .ok()
        .and_then(|stat| stat.rsplit_once(") ").map(|(_, fields)| fields.to_owned()))
        .and_then(|fields| fields.split_whitespace().nth(2)?.parse::<i32>().ok());
    if let Some(process_group) = process_group {
        let _ = unsafe { libc::killpg(process_group, libc::SIGKILL) };
    }
    let _ = unsafe { libc::kill(caller_tid, libc::SIGKILL) };
}

/// Emit a machine-readable snapshot whenever argv-freeze setup or cleanup is
/// unhealthy. This complements spawn-denial diagnostics with the ptrace state
/// that commonly explains a later EAGAIN.
pub(crate) fn emit_exec_freeze_diagnostic(
    processes: &crate::seccomp::state::ProcessIndex,
    caller_tid: i32,
    phase: &str,
    error: &str,
) {
    let mut tasks = Vec::new();
    for pid in processes.pids_snapshot() {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        tasks.push(serde_json::json!({
            "pid": pid,
            "state": field("State:").and_then(|value| value.chars().next()),
            "parentPid": field("PPid:").and_then(|value| value.parse::<i32>().ok()),
            "tracerPid": field("TracerPid:").and_then(|value| value.parse::<i32>().ok()),
            "threads": field("Threads:").and_then(|value| value.parse::<usize>().ok()),
        }));
    }
    let diagnostic = serde_json::json!({
        "event": "ptrace_freeze_failed",
        "scope": "execution_domain",
        "source": "exec_argv_freeze",
        "phase": phase,
        "error": error,
        "callerTid": caller_tid,
        "trackedTasks": tasks.len(),
        "activeCreationTraces": processes.active_creation_traces(),
        "activeExecFreezes": processes.active_exec_freezes(),
        "activePtraceTrackers": processes.active_ptrace_trackers(),
        "tasks": tasks,
    });
    eprintln!("sandlock: execution_domain_diagnostic {diagnostic}");
}

/// Freeze every sandbox thread that could mutate execve argv before
/// the supervisor reads it for `policy_fn` and before the kernel
/// re-reads it.
///
/// Walks every TGID in `processes`, enumerates each TGID's threads via
/// `/proc/<tgid>/task/`, and `PTRACE_SEIZE` + `PTRACE_INTERRUPT`s
/// every TID except `caller_tid`. Sibling threads of `caller_tid` and
/// peer threads in other TGIDs are both covered. `processes` is
/// complete for `policy_fn` runs because process-creating fork-like syscalls
/// are tracked before new children can run.
///
/// Strict semantics: if any task refuses to be frozen, every
/// already-frozen task is detached and the error is propagated. The
/// caller is expected to deny the execve with `EPERM`, preserving the
/// invariant that exposed argv is always TOCTOU-safe.
///
/// On success, returns the sibling and peer TIDs that were frozen. The
/// caller detaches peers after an allowed execve, or detaches all TIDs
/// after a denied execve.
pub(crate) fn freeze_sandbox_for_execve(
    processes: &crate::seccomp::state::ProcessIndex,
    caller_tid: i32,
) -> Result<SandboxFreeze, FreezeError> {
    let no_pending = |error| FreezeError { error, pending_tids: Vec::new() };
    let caller_tgid = read_tgid_of_tid(caller_tid).map_err(no_pending)?;
    let mut tgids: HashSet<i32> = processes.pids_snapshot();
    tgids.insert(caller_tgid);

    let mut sibling_tids: Vec<i32> = Vec::new();
    let mut peer_tids: Vec<i32> = Vec::new();
    let mut pending_tids: Vec<i32> = Vec::new();

    for tgid in &tgids {
        // /proc/<tgid>/task may disappear if the TGID exited between
        // snapshot and walk — that's fine, no threads to freeze.
        let tids = match list_threads_of_tgid(*tgid) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for tid in tids {
            if tid == caller_tid {
                continue;
            }
            match seize_and_interrupt(tid) {
                Ok(SeizeOutcome::Frozen) => {
                    if *tgid == caller_tgid {
                        sibling_tids.push(tid);
                    } else {
                        peer_tids.push(tid);
                    }
                }
                Ok(SeizeOutcome::PendingStop) => pending_tids.push(tid),
                Ok(SeizeOutcome::NotNeeded) => continue,
                Err(e) => {
                    // Roll back: detach every task we already froze
                    // (siblings + peers) so they resume normally. Pending
                    // tasks cannot be detached until they stop, which
                    // requires the caller's response to go out first —
                    // hand them back through the error.
                    for t in &sibling_tids {
                        detach(*t);
                    }
                    for t in &peer_tids {
                        detach(*t);
                    }
                    return Err(FreezeError { error: e, pending_tids });
                }
            }
        }
    }

    Ok(SandboxFreeze {
        sibling_tids,
        peer_tids,
        pending_tids,
    })
}

/// Helper called from the dispatch hot path. Returns true if the
/// notification is for an execve-class syscall whose Continue response
/// requires freezing siblings.
pub(crate) fn requires_freeze_on_continue(syscall_nr: i64) -> bool {
    syscall_nr == libc::SYS_execve || syscall_nr == libc::SYS_execveat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::state::ProcessIndex;

    #[test]
    fn list_threads_of_tgid_includes_self() {
        // Our own /proc/self/task always exists and always contains
        // at least our own tid.
        let our_tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        let tids = list_threads_of_tgid(our_tid).unwrap();
        assert!(tids.contains(&our_tid));
    }

    #[test]
    fn requires_freeze_only_for_exec() {
        assert!(requires_freeze_on_continue(libc::SYS_execve));
        assert!(requires_freeze_on_continue(libc::SYS_execveat));
        assert!(!requires_freeze_on_continue(libc::SYS_openat));
        assert!(!requires_freeze_on_continue(libc::SYS_connect));
    }

    /// Regression test for the cross-process TOCTOU concern raised on
    /// issue #27 (Changaco): a peer process in the sandbox — different
    /// TGID, possibly aliasing argv pages via shared memory — must also
    /// be frozen before the kernel re-reads execve argv. Sibling-thread
    /// freeze alone does not cover this. In real policy_fn runs,
    /// fork-like syscall tracking registers peer processes before they
    /// can run; this unit test mirrors that completed registration.
    ///
    /// # Why we spawn a separate "caller" process
    ///
    /// In production, `freeze_sandbox_for_execve` runs in the supervisor
    /// process and `caller_tid` is the sandboxed child's tid — i.e. the
    /// supervisor and the execve caller are in *different* TGIDs, and
    /// every TID the freeze walks is a descendant of the supervisor.
    /// Under YAMA `ptrace_scope=1` (the Ubuntu/Debian default), that
    /// descendant relationship is exactly what makes PTRACE_SEIZE
    /// permitted without any privilege.
    ///
    /// If this test instead used the test thread's own tid as
    /// `caller_tid`, `caller_tgid` would be the cargo test binary's
    /// TGID, the freeze would walk the test binary's sibling threads
    /// (libtest workers, runtime helpers), and PTRACE_SEIZE would be
    /// rejected with EPERM by YAMA — sibling threads are not
    /// descendants of each other. That would force the test to require
    /// privileges sandlock itself does not require. So we spawn a
    /// dedicated "caller" sleep to play the sandboxed-process role,
    /// matching production topology.
    #[test]
    fn freeze_sandbox_includes_peer_process() {
        use std::process::{Command, Stdio};

        // The "execve caller" — stands in for the sandboxed process.
        // Its tid is a descendant of the test process (the parent), so
        // ptracing into its TGID is YAMA-allowed under ptrace_scope=1.
        let mut caller = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn caller sleep");
        let caller_tid = caller.id() as i32;

        let mut peer = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn peer sleep");
        let peer_pid = peer.id() as i32;

        // Give both children a moment to actually be running.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let processes = ProcessIndex::new();
        processes
            .register(peer_pid)
            .expect("register peer in ProcessIndex");

        let outcome = freeze_sandbox_for_execve(&processes, caller_tid)
            .expect("freeze_sandbox_for_execve");

        // Peer's TID is its own TGID (single-threaded sleep), and it's
        // a different TGID from the execve caller, so it should be in peer_tids.
        assert!(
            outcome.peer_tids.contains(&peer_pid),
            "peer pid {} should be in peer_tids: {:?}",
            peer_pid,
            outcome.peer_tids
        );

        // Verify the peer is actually ptrace-stopped via /proc.
        let status = std::fs::read_to_string(format!("/proc/{}/status", peer_pid))
            .expect("read peer status");
        let state_line = status
            .lines()
            .find(|l| l.starts_with("State:"))
            .expect("State: line");
        assert!(
            state_line.contains("t (tracing stop)") || state_line.contains("T (stopped)"),
            "peer should be ptrace-stopped, got: {}",
            state_line
        );

        // Cleanup: detach the peer so it can resume and be killed.
        detach_tids_checked(&outcome.peer_tids).expect("detach frozen peer");
        let _ = peer.kill();
        let _ = peer.wait();
        let _ = caller.kill();
        let _ = caller.wait();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pinned_exec_freeze_detaches_after_async_policy_handoff() {
        use std::process::{Command, Stdio};

        let mut caller = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn caller sleep");
        let caller_tid = caller.id() as i32;
        let mut peer = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn peer sleep");
        let peer_pid = peer.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(50));

        let processes = Arc::new(ProcessIndex::new());
        processes
            .register(peer_pid)
            .expect("register peer in ProcessIndex");
        let preparation = prepare_exec_freeze(Arc::clone(&processes), caller_tid)
            .await
            .expect("prepare pinned exec freeze");
        assert!(preparation.failure.is_none(), "{:?}", preparation.failure);
        assert_eq!(processes.active_exec_freezes(), 1);

        let status = std::fs::read_to_string(format!("/proc/{peer_pid}/status"))
            .expect("read frozen peer status");
        let tracer = status
            .lines()
            .find_map(|line| line.strip_prefix("TracerPid:"))
            .and_then(|value| value.trim().parse::<i32>().ok())
            .unwrap_or_default();
        assert!(tracer > 0, "peer must be owned by the pinned ptrace worker");

        // Model the async policy callback boundary that used to let the
        // notification future resume on a different Tokio worker.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        finish_exec_freeze(preparation.trace, false)
            .await
            .expect("finish pinned exec freeze");
        assert_eq!(processes.active_exec_freezes(), 0);
        let status = std::fs::read_to_string(format!("/proc/{peer_pid}/status"))
            .expect("read detached peer status");
        assert!(status.lines().any(|line| line == "TracerPid:\t0"), "{status}");

        let _ = peer.kill();
        let _ = peer.wait();
        let _ = caller.kill();
        let _ = caller.wait();
    }
}
