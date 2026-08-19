// Domain-specific state structs — each domain is locked independently so
// handlers only contend on the state they actually need. Per-process
// state is bundled into a single `PerProcessState` owned by
// `ProcessIndex`; cleanup on exit is just dropping the entry's `Arc`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex as AsyncMutex, OwnedRwLockReadGuard, RwLock as AsyncRwLock};

/// Resource-limit runtime state shared across notification handlers.
pub struct ResourceState {
    /// Live concurrent process count — the root process plus every reserved
    /// fork slot that has not yet been released by rollback or process exit.
    pub proc_count: u32,
    /// Fork-notification IDs owning a process-count slot.  Both failed-fork
    /// rollback and pidfd exit cleanup remove from this set before decrementing,
    /// making the credit exactly-once even when cleanup paths race.
    pub process_slots: HashSet<u64>,
    /// Peak concurrent process count observed since sandbox start.
    pub peak_proc_count: u32,
    /// Maximum allowed concurrent processes.
    pub max_processes: u32,
    /// Number of fork-like syscalls rejected because the concurrent-process
    /// budget was full. Used to rate-limit quota diagnostics while retaining
    /// the total denial count in each emitted message.
    pub process_limit_denials: u64,
    /// Estimated anonymous memory usage (bytes).
    pub mem_used: u64,
    /// Peak anonymous memory usage observed since sandbox start (bytes).
    pub peak_mem_used: u64,
    /// Maximum allowed anonymous memory (bytes).
    pub max_memory_bytes: u64,
    /// Whether fork notifications should be held (checkpoint/freeze).
    pub hold_forks: bool,
    /// Notification IDs held during a checkpoint freeze.
    pub held_notif_ids: Vec<u64>,
    /// Exponentially-weighted load average.
    pub load_avg: crate::procfs::LoadAvg,
    /// Instant when the supervisor started (for uptime reporting).
    pub start_instant: std::time::Instant,
}

impl ResourceState {
    /// Create a new resource state with the given limits.
    pub fn new(max_memory_bytes: u64, max_processes: u32) -> Self {
        Self {
            proc_count: 0,
            process_slots: HashSet::new(),
            peak_proc_count: 1, // root process always exists; handle_fork counts children only
            max_processes,
            process_limit_denials: 0,
            mem_used: 0,
            peak_mem_used: 0,
            max_memory_bytes,
            hold_forks: false,
            held_notif_ids: Vec::new(),
            load_avg: crate::procfs::LoadAvg::new(),
            start_instant: std::time::Instant::now(),
        }
    }
}

// ============================================================
// ProcfsState — /proc virtualization state
// ============================================================

/// /proc virtualization runtime state. Per-notification process state
/// lives in `ProcessIndex`; per-process getdents caches live in
/// `PerProcessState::procfs_dir_cache`. This struct only holds truly
/// global virtualization state.
pub struct ProcfsState {
    /// Base address of the last vDSO we patched (0 = not yet patched).
    pub vdso_patched_addr: u64,
}

impl ProcfsState {
    pub fn new() -> Self {
        Self {
            vdso_patched_addr: 0,
        }
    }
}

// ============================================================
// PidKey — stable per-process identity
// ============================================================

/// Stable process identity. Numeric pid plus the start_time that
/// distinguishes a specific process instance from any future recycle
/// of the same pid slot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PidKey {
    /// Numeric PID observed by seccomp notification.
    pub pid: i32,
    /// Process start time from /proc/<pid>/stat field 22.
    pub start_time: u64,
}

/// Read the thread-group leader pid (TGID) containing `tid` from
/// `/proc/<tid>/status`. `None` when the task is gone or /proc is
/// unreadable; callers decide what that means for them.
pub(crate) fn read_tgid_of_tid(tid: i32) -> Option<i32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", tid)).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Read the parent pid (field 4 of `/proc/<pid>/stat`) for `pid`.
/// `None` when the task is gone or /proc is unreadable.
pub(crate) fn read_ppid(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past "pid (comm)": comm may contain spaces and parens, but the
    // last ") " in the line ends it. The first token after it is the state,
    // and the parent pid follows.
    let rest = stat.rsplit_once(") ")?.1;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Read the process start time (field 22 of /proc/<pid>/stat) for `pid`.
/// Returns None if the process is gone or /proc is not readable.
pub(crate) fn read_pid_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // Skip past "pid (comm)" — comm may contain spaces and parens, but the
    // last ") " in the line ends the comm field.
    let rest = stat.rsplit_once(") ")?.1;
    // The first token after "(comm) " is field 3; field 22 is therefore nth(19).
    rest.split_whitespace().nth(19)?.parse().ok()
}

// ============================================================
// PerProcessState — bundled per-process supervisor state
// ============================================================

/// All per-process supervisor state for one tracked child. One
/// instance lives per `PidKey`, owned by `ProcessIndex` behind an
/// `Arc<AsyncMutex<…>>`. Cleanup on process exit is one operation:
/// `ProcessIndex::unregister` drops the index's `Arc`, and the
/// supervisor's per-handler clones drop along with their tasks.
#[derive(Default)]
pub struct PerProcessState {
    /// Logical cwd while the process is chdir'd into a COW-only
    /// directory. None means "use kernel-reported cwd".
    pub virtual_cwd: Option<String>,
    /// Recorded brk base for memory accounting. None until first brk.
    pub brk_base: Option<u64>,
    /// Anonymous memory (bytes) charged to this address space and not
    /// yet credited back. Only the thread-group leader's entry carries a
    /// charge: threads share one address space, so all accounting for a
    /// task is routed to its leader via [`ProcessIndex::addr_space_state`].
    /// Credited back to the global total when the address space goes away
    /// (exec replaces it, or the process exits).
    pub mem_charged: u64,
    /// COW directory dirent cache. Keyed by child's fd; value is
    /// (host target path, sorted dirent bytes left to return).
    /// Entries are invalidated when the fd is reused for a different
    /// directory.
    pub cow_dir_cache: HashMap<u32, (String, Vec<Vec<u8>>)>,
    /// /proc directory dirent cache. Keyed by (child fd, target
    /// path); same drain-on-EOF semantics as cow_dir_cache.
    pub procfs_dir_cache: HashMap<(u32, String), Vec<Vec<u8>>>,
}

// ============================================================
// ProcessIndex — tracked processes + per-process state
// ============================================================

/// Registry for tracked sandbox processes plus their per-process
/// supervisor state.
///
/// The top-level process and threads can be populated lazily from seccomp
/// notifications. Process-creating fork-like syscalls are traced for one
/// ptrace creation event so each child is inserted with its quota slot and
/// pidfd before it can run user code; this also makes the index complete for
/// argv-safety freezes.
///
/// Maps the kernel's numeric `pid` (the value that arrives in seccomp
/// notifications) to the canonical `PidKey` plus an
/// `Arc<AsyncMutex<PerProcessState>>` holding everything per-process.
/// Held behind an internal `std::sync::RwLock` so the read-mostly hot
/// paths (`key_for`, `contains`, `entry_for`, `/proc` virtualization)
/// avoid an async mutex on every notification, and so `ProcessIndex`
/// doesn't need its own outer wrapper in `SupervisorCtx`. Lock guards
/// are `!Send` and the compiler will reject holding one across an
/// `.await`, which keeps callers honest.
///
/// Ownership of each child's pidfd lives with the per-child watcher
/// task, not with this index. That keeps the kernel fd alive for as
/// long as the `AsyncFd` registration in the tokio IO driver does,
/// and avoids a race where dropping the fd from the index could
/// deregister a recycled fd from epoll.
pub struct ProcessIndex {
    inner: std::sync::RwLock<HashMap<i32, ProcessEntry>>,
    /// Fork-like syscalls currently owned by a one-shot ptrace tracker.
    active_creation_traces: std::sync::atomic::AtomicUsize,
    /// Exec argv freezes currently owned by a pinned ptrace worker.
    active_exec_freezes: std::sync::atomic::AtomicUsize,
}

/// A task's current directory as the sandbox believes it to be: the
/// path `getcwd` should report, in whatever namespace the child sees
/// (the virtual path under chroot, the real path otherwise).
///
/// `None` means the task has never moved, so the kernel's own cwd is
/// still authoritative. Shared behind an `Arc` the way the kernel
/// shares `fs_struct`, so a chdir in one thread is seen by its
/// siblings. Kept outside `PerProcessState` (and behind a std mutex)
/// because path resolution reads it from synchronous helpers.
pub type SharedCwd = Arc<std::sync::Mutex<Option<PathBuf>>>;

/// The virtual executable path associated with one process image.
///
/// Threads share the same cell because they share one executable image. A
/// forked process receives a new cell initialized from its parent, matching
/// the kernel's copy-on-fork semantics. Keeping the cell in `ProcessIndex`
/// binds it to a stable [`PidKey`] and lets ordinary process cleanup discard
/// it without a second lifecycle registry.
type SharedExecutable = Arc<std::sync::Mutex<ExecutableState>>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecutableRecord {
    virtual_path: PathBuf,
    device: u64,
    inode: u64,
    kernel_path: PathBuf,
}

#[derive(Default)]
struct ExecutableState {
    current: Option<ExecutableRecord>,
    pending: Option<ExecutableRecord>,
}

fn executable_record_matches(record: &ExecutableRecord, pid: i32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let proc_exe = format!("/proc/{pid}/exe");
    let Ok(metadata) = std::fs::metadata(&proc_exe) else {
        return false;
    };
    let Ok(kernel_path) = std::fs::read_link(proc_exe) else {
        return false;
    };
    metadata.dev() == record.device
        && metadata.ino() == record.inode
        && kernel_path == record.kernel_path
}

fn resolve_executable(cell: &SharedExecutable, pid: i32) -> Option<ExecutableRecord> {
    let mut state = cell.lock().ok()?;
    if let Some(pending) = state.pending.take() {
        if executable_record_matches(&pending, pid) {
            state.current = Some(pending);
        }
    }
    // A successful script exec replaces the process image with the kernel's
    // shebang interpreter, not with the script inode staged above. In that
    // case the inherited/current record is stale as well. Drop it so the
    // chroot procfs handler falls back to the actual interpreter identity.
    // A failed exec still leaves the previous image in place, so its current
    // record continues to match and is preserved.
    if state
        .current
        .as_ref()
        .is_some_and(|current| !executable_record_matches(current, pid))
    {
        state.current = None;
    }
    state.current.clone()
}

#[derive(Clone)]
struct ProcessEntry {
    key: PidKey,
    /// Thread-group leader of this task; equals `key.pid` for a
    /// single-threaded process. Read once at registration and kept
    /// outside the async mutex so address-space lookups need only the
    /// index's read lock.
    tgid: i32,
    state: Arc<AsyncMutex<PerProcessState>>,
    cwd: SharedCwd,
    executable: SharedExecutable,
    /// Fork-notification ID whose quota slot belongs to this process.  The
    /// top-level sandbox process and lazily discovered threads have no slot.
    process_slot: Option<u64>,
}

impl ProcessIndex {
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(HashMap::new()),
            active_creation_traces: std::sync::atomic::AtomicUsize::new(0),
            active_exec_freezes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn creation_trace_started(&self) {
        self.active_creation_traces
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn creation_trace_finished(&self) {
        self.active_creation_traces
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn active_creation_traces(&self) -> usize {
        self.active_creation_traces
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn exec_freeze_started(&self) {
        self.active_exec_freezes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn exec_freeze_finished(&self) {
        self.active_exec_freezes
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn active_exec_freezes(&self) -> usize {
        self.active_exec_freezes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn active_ptrace_trackers(&self) -> usize {
        self.active_creation_traces()
            .saturating_add(self.active_exec_freezes())
    }

    /// Register a process by reading its start_time once and
    /// allocating its `PerProcessState`. Returns the canonical key,
    /// or None if the process is already gone. The caller is
    /// responsible for keeping the pidfd alive — the per-child
    /// watcher task does this via `AsyncFd<OwnedFd>`.
    pub fn register(&self, pid: i32) -> Option<PidKey> {
        self.register_with_process_slot(pid, None).map(|registered| registered.0)
    }

    /// Register a process and attach the quota reservation made for the fork
    /// that created it. Returns the stable key plus any quota slot displaced
    /// from a stale entry with the same numeric PID. The caller must release a
    /// displaced slot. The current slot travels with the stable `PidKey`, so
    /// PID reuse cannot release a newer process's quota charge.
    pub fn register_with_process_slot(
        &self,
        pid: i32,
        process_slot: Option<u64>,
    ) -> Option<(PidKey, Option<u64>)> {
        let start_time = read_pid_start_time(pid)?;
        let key = PidKey { pid, start_time };
        // Unreadable /proc means the task is its own address space as far
        // as accounting is concerned: better local than misrouted.
        let tgid = read_tgid_of_tid(pid).unwrap_or(pid);
        let entry = ProcessEntry {
            key,
            tgid,
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            cwd: self.inherited_cwd(pid, tgid),
            executable: self.inherited_executable(pid, tgid),
            process_slot,
        };
        let displaced_process_slot = self
            .inner
            .write()
            .ok()?
            .insert(pid, entry)
            .and_then(|displaced| displaced.process_slot);
        Some((key, displaced_process_slot))
    }

    /// The cwd cell a task starts life with.
    ///
    /// A thread joins its leader's cell, because the kernel hands
    /// pthreads a shared `fs_struct` and one thread's chdir moves its
    /// siblings. Anything else copies the parent's current value, which
    /// is what `fork(2)` does. Thread-group membership stands in for
    /// `CLONE_FS` here, the same approximation `addr_space_state` makes
    /// for `CLONE_VM`: a bare `clone(CLONE_FS)` without `CLONE_THREAD`
    /// gets a private copy instead of sharing. An untracked parent
    /// leaves the child at None, which falls back to the kernel's cwd.
    fn inherited_cwd(&self, pid: i32, tgid: i32) -> SharedCwd {
        let ppid = if tgid == pid { read_ppid(pid) } else { None };
        let Ok(guard) = self.inner.read() else {
            return SharedCwd::default();
        };
        if tgid != pid {
            if let Some(leader) = guard.get(&tgid) {
                return Arc::clone(&leader.cwd);
            }
        }
        let parent_cwd = ppid
            .and_then(|p| guard.get(&p))
            .and_then(|e| e.cwd.lock().ok().and_then(|c| c.clone()));
        Arc::new(std::sync::Mutex::new(parent_cwd))
    }

    /// The executable-image cell a task starts life with.
    ///
    /// A thread shares its leader's image. A process created by fork copies
    /// the parent's current virtual path so a later exec in either process
    /// cannot rename the other's `/proc/<pid>/exe` view.
    fn inherited_executable(&self, pid: i32, tgid: i32) -> SharedExecutable {
        let ppid = if tgid == pid { read_ppid(pid) } else { None };
        let Ok(guard) = self.inner.read() else {
            return SharedExecutable::default();
        };
        if tgid != pid {
            if let Some(leader) = guard.get(&tgid) {
                return Arc::clone(&leader.executable);
            }
        }
        let parent = ppid.and_then(|parent| {
            guard
                .get(&parent)
                .map(|entry| (parent, entry.key, Arc::clone(&entry.executable)))
        });
        drop(guard);
        let current = parent.and_then(|(parent, key, cell)| {
            if read_pid_start_time(parent) == Some(key.start_time) {
                resolve_executable(&cell, parent)
            } else {
                None
            }
        });
        Arc::new(std::sync::Mutex::new(ExecutableState {
            current,
            pending: None,
        }))
    }

    /// The cwd cell to read or write for `pid`.
    ///
    /// A task without an entry of its own falls back to its
    /// thread-group leader: `pidfd_open` on a non-leader tid needs
    /// `PIDFD_THREAD` (Linux 6.9), so `register_pid_if_new` can leave a
    /// thread unregistered. Since threads share one `fs_struct`, the
    /// leader's cell is the correct answer for them, not an
    /// approximation. Only that miss pays for the extra /proc read.
    fn cwd_cell(&self, pid: i32) -> Option<SharedCwd> {
        if let Ok(guard) = self.inner.read() {
            if let Some(entry) = guard.get(&pid) {
                return Some(Arc::clone(&entry.cwd));
            }
        }
        let tgid = read_tgid_of_tid(pid)?;
        if tgid == pid {
            return None;
        }
        let guard = self.inner.read().ok()?;
        guard.get(&tgid).map(|e| Arc::clone(&e.cwd))
    }

    /// The cwd this task believes it is in, or None when the task is
    /// untracked or has never moved.
    pub fn virtual_cwd(&self, pid: i32) -> Option<PathBuf> {
        let cell = self.cwd_cell(pid)?;
        let cwd = cell.lock().ok()?.clone();
        cwd
    }

    /// Record where this task now believes it is. Silently does nothing
    /// for an untracked pid: the fallback is the kernel's own cwd.
    pub fn set_virtual_cwd(&self, pid: i32, cwd: PathBuf) {
        if let Some(cell) = self.cwd_cell(pid) {
            if let Ok(mut slot) = cell.lock() {
                *slot = Some(cwd);
            }
        }
    }

    /// Forget a synthetic cwd so the next path operation re-reads the
    /// kernel's successfully installed cwd from `/proc`.
    pub fn clear_virtual_cwd(&self, pid: i32) {
        if let Some(cell) = self.cwd_cell(pid) {
            if let Ok(mut slot) = cell.lock() {
                *slot = None;
            }
        }
    }

    /// Return the tracked virtual executable for the current incarnation of
    /// `pid`. `None` means the task is untracked or has not passed through the
    /// chroot exec rewrite yet.
    pub(crate) fn virtual_executable(&self, pid: i32) -> Option<PathBuf> {
        let (key, cell) = {
            let guard = self.inner.read().ok()?;
            let entry = guard.get(&pid)?;
            (entry.key, Arc::clone(&entry.executable))
        };
        if read_pid_start_time(pid) != Some(key.start_time) {
            return None;
        }
        resolve_executable(&cell, pid).map(|record| record.virtual_path)
    }

    /// Stage a chroot exec rewrite for one stable process identity.
    ///
    /// The next lookup compares `/proc/<pid>/exe` with the pinned fd before
    /// promoting this candidate to current. A failed kernel exec therefore
    /// preserves the old image, while a recycled numeric PID cannot receive
    /// the candidate because the entry's [`PidKey`] must still match.
    pub(crate) fn stage_virtual_executable(
        &self,
        key: PidKey,
        executable: PathBuf,
        executable_fd: std::os::unix::io::RawFd,
    ) -> bool {
        use std::os::unix::fs::MetadataExt;
        if read_pid_start_time(key.pid) != Some(key.start_time) {
            return false;
        }
        let Ok(metadata) = std::fs::metadata(format!("/proc/self/fd/{executable_fd}")) else {
            return false;
        };
        let Ok(kernel_path) = std::fs::read_link(format!("/proc/self/fd/{executable_fd}")) else {
            return false;
        };
        let pending = ExecutableRecord {
            virtual_path: executable,
            device: metadata.dev(),
            inode: metadata.ino(),
            kernel_path,
        };
        let cell = {
            let Ok(guard) = self.inner.read() else {
                return false;
            };
            let Some(entry) = guard.get(&key.pid).filter(|entry| entry.key == key) else {
                return false;
            };
            Arc::clone(&entry.executable)
        };
        // A process can exec again without reading `/proc/self/exe` between
        // images. Resolve the previous candidate against the image that is
        // still running before replacing it with this new attempt.
        let _ = resolve_executable(&cell, key.pid);
        let Ok(mut slot) = cell.lock() else {
            return false;
        };
        slot.pending = Some(pending);
        true
    }

    /// Look up the canonical PidKey for a notification's raw pid.
    /// Returns None if this pid was never registered (e.g. pidfd_open
    /// failed at fork) — callers should fall back to a no-op.
    pub fn key_for(&self, pid: i32) -> Option<PidKey> {
        self.inner.read().ok()?.get(&pid).map(|e| e.key)
    }

    /// Look up both the PidKey and the per-process state handle for
    /// `pid`. Returns None if the pid isn't tracked. The caller locks
    /// the returned `Arc<AsyncMutex<…>>` to read or mutate.
    pub fn entry_for(&self, pid: i32) -> Option<(PidKey, Arc<AsyncMutex<PerProcessState>>)> {
        self.inner
            .read()
            .ok()?
            .get(&pid)
            .map(|e| (e.key, Arc::clone(&e.state)))
    }

    /// Per-address-space state for `pid`: the thread-group leader's
    /// entry when `pid` is a thread, otherwise its own. Memory
    /// accounting keys off this because threads share one address
    /// space — charging each thread separately would let every thread's
    /// first brk go free and would credit a live heap back when one
    /// thread exits. Falls back to the task's own entry when the leader
    /// is untracked.
    pub fn addr_space_state(&self, pid: i32) -> Option<Arc<AsyncMutex<PerProcessState>>> {
        let guard = self.inner.read().ok()?;
        let entry = guard.get(&pid)?;
        if entry.tgid != pid {
            if let Some(leader) = guard.get(&entry.tgid) {
                return Some(Arc::clone(&leader.state));
            }
        }
        Some(Arc::clone(&entry.state))
    }

    /// Cheap tracked-process test — used by /proc virtualization to
    /// gate access to `/proc/<pid>/...` paths and by getdents filtering.
    pub fn contains(&self, pid: i32) -> bool {
        self.inner
            .read()
            .map(|g| g.contains_key(&pid))
            .unwrap_or(false)
    }

    /// Whether `pid` still names the tracked process incarnation rather than
    /// a task that reused the same numeric PID after delayed cleanup.
    pub(crate) fn contains_current(&self, pid: i32) -> bool {
        self.key_for(pid)
            .is_some_and(|key| read_pid_start_time(pid) == Some(key.start_time))
    }

    /// Number of tracked processes (for /proc/loadavg total).
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Largest tracked pid (for /proc/loadavg last_pid).
    pub fn max_pid(&self) -> Option<i32> {
        self.inner.read().ok()?.keys().copied().max()
    }

    /// Snapshot the set of tracked pids. Used by getdents filtering
    /// where the caller needs O(1) lookups inside a loop and would
    /// otherwise have to re-acquire the read lock per entry.
    pub fn pids_snapshot(&self) -> HashSet<i32> {
        self.inner
            .read()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Remove a process from the index and return its quota slot, if any. The
    /// per-process state's `Arc` reference held by the index drops here;
    /// remaining clones (e.g. a handler that's mid-execution for that pid) will drop
    /// when they go out of scope, and the inner `PerProcessState`
    /// frees automatically.
    pub fn unregister(&self, key: PidKey) -> Option<u64> {
        if let Ok(mut g) = self.inner.write() {
            // Only clear if the entry still points at this key. A PID
            // recycled with a fresh start_time may already have
            // overwritten the entry via register(); we must not stomp it.
            if g.get(&key.pid).map(|e| e.key) == Some(key) {
                return g.remove(&key.pid).and_then(|entry| entry.process_slot);
            }
        }
        None
    }

    /// Defensive sweep: identify entries whose process is gone (or whose
    /// start_time has changed). A low-frequency backstop passes the returned
    /// keys through unified cleanup so memory and process quota are both
    /// credited exactly once.
    pub fn dead_keys(&self) -> Vec<PidKey> {
        let candidates: Vec<(i32, PidKey)> = match self.inner.read() {
            Ok(g) => g.iter().map(|(p, e)| (*p, e.key)).collect(),
            Err(_) => return Vec::new(),
        };
        let mut dead = Vec::new();
        for (pid, key) in candidates {
            match read_pid_start_time(pid) {
                Some(st) if st == key.start_time => continue,
                _ => dead.push(key),
            }
        }
        dead
    }
}

impl Default for ProcessIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// CowState — copy-on-write filesystem state (global only)
// ============================================================

/// Global COW state. Per-process COW state (virtual cwd, dir cache)
/// lives in `PerProcessState`.
pub struct CowState {
    /// Seccomp-based COW branch (None if COW disabled).
    pub branch: Option<crate::cow::seccomp::SeccompCowBranch>,
    /// Spans complete notification operations, including blocking copy-up I/O.
    /// A checkpoint takes the exclusive side after stopping the process group.
    pub(crate) operation_gate: Arc<AsyncRwLock<()>>,
}

impl CowState {
    pub fn new() -> Self {
        Self {
            branch: None,
            operation_gate: Arc::new(AsyncRwLock::new(())),
        }
    }
}

/// Enter one notification operation that can observe or mutate COW state.
///
/// The returned owned guard deliberately outlives the short `CowState` mutex
/// acquisition and stays held while handlers perform copy-up I/O outside that
/// mutex. Attached checkpoint takes the exclusive side of the same gate.
pub(crate) async fn enter_cow_operation(
    cow: &Arc<AsyncMutex<CowState>>,
) -> OwnedRwLockReadGuard<()> {
    let gate = Arc::clone(&cow.lock().await.operation_gate);
    gate.read_owned().await
}

// ============================================================
// NetworkState — network policy and port remapping state
// ============================================================

/// Network policy and port-remapping state. Holds one
/// `NetworkPolicy` per L4 protocol — the on-behalf handler picks the
/// matching one based on the dup'd fd's `SO_PROTOCOL`.
pub struct NetworkState {
    /// Allowlist for TCP destinations (`tcp://...` and bare-form rules;
    /// bare specs expand to a TCP + UDP pair at parse time).
    pub tcp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allowlist for UDP destinations (`udp://...` and bare-form rules).
    pub udp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Allowlist for ICMP destinations (`icmp://...` rules). ICMP rules
    /// carry no ports, so every entry uses `PortAllow::Any` and the
    /// effective check is IP-only.
    pub icmp_policy: crate::seccomp::notif::NetworkPolicy,
    /// Port binding and remapping tracker.
    pub port_map: crate::port_remap::PortMap,
    /// `--net-deny-bind`: TCP ports the sandbox may NOT bind (default-allow
    /// denylist). The on-behalf `bind()` handler rejects a TCP bind to any
    /// port in this set with `EACCES`; empty = no bind denylist.
    pub bind_deny_ports: HashSet<u16>,
    /// Per-PID network overrides from policy_fn (IP-only via the legacy
    /// `restrict_network(ips)` API; any port is permitted to listed IPs).
    pub pid_ip_overrides: std::sync::Arc<std::sync::RwLock<HashMap<u32, HashSet<std::net::IpAddr>>>>,
    /// HTTP ACL proxy address (None if HTTP ACL not active).
    pub http_acl_addr: Option<std::net::SocketAddr>,
    /// TCP ports to intercept and redirect to the HTTP ACL proxy.
    pub http_acl_ports: HashSet<u16>,
    /// Shared map for recording original destination IPs on proxy redirect.
    pub http_acl_orig_dest: Option<crate::transparent_proxy::OrigDestMap>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            tcp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            udp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            icmp_policy: crate::seccomp::notif::NetworkPolicy::Unrestricted,
            port_map: crate::port_remap::PortMap::new(),
            bind_deny_ports: HashSet::new(),
            pid_ip_overrides: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            http_acl_addr: None,
            http_acl_ports: HashSet::new(),
            http_acl_orig_dest: None,
        }
    }

    /// Get the effective network policy for a PID and protocol.
    ///
    /// Priority: per-PID override > live policy (from PolicyFnState) >
    /// the per-protocol allowlist for `protocol`.
    /// PID/live overrides are IP-only — any port is permitted to listed
    /// IPs (legacy `policy_fn` semantics) — and they apply across all
    /// protocols, since the legacy API didn't distinguish them.
    pub fn effective_network_policy(
        &self,
        pid: u32,
        protocol: crate::sandbox::Protocol,
        live_policy: Option<&std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    ) -> crate::seccomp::notif::NetworkPolicy {
        use crate::sandbox::Protocol;
        use crate::seccomp::notif::{NetworkPolicy, PortAllow};
        let ip_only_allow = |ips: &HashSet<std::net::IpAddr>| {
            let per_ip = ips.iter().map(|&ip| (ip, PortAllow::Any)).collect();
            NetworkPolicy::AllowList {
                per_ip,
                cidrs: Vec::new(),
                any_ip_ports: HashSet::new(),
            }
        };
        if let Ok(overrides) = self.pid_ip_overrides.read() {
            if let Some(ips) = overrides.get(&pid) {
                return ip_only_allow(ips);
            }
        }
        if let Some(lp) = live_policy {
            if let Ok(live) = lp.read() {
                if !live.allowed_ips.is_empty() {
                    return ip_only_allow(&live.allowed_ips);
                }
            }
        }
        match protocol {
            Protocol::Tcp => self.tcp_policy.clone(),
            Protocol::Udp => self.udp_policy.clone(),
            Protocol::Icmp => self.icmp_policy.clone(),
        }
    }
}

// ============================================================
// TimeRandomState — deterministic time/random state
// ============================================================

/// Time offset and deterministic random state.
pub struct TimeRandomState {
    /// Clock offset for time virtualization.
    pub time_offset: Option<i64>,
    /// Deterministic PRNG state (seeded from policy).
    pub random_state: Option<rand_chacha::ChaCha8Rng>,
}

impl TimeRandomState {
    pub fn new(time_offset: Option<i64>, random_state: Option<rand_chacha::ChaCha8Rng>) -> Self {
        Self { time_offset, random_state }
    }
}

// ============================================================
// DeniedSet — denied paths plus captured file identities
// ============================================================

/// The filesystem deny set: path prefixes plus the file-handle identities
/// captured when each path was denied.
///
/// The path set is the primary, race-free boundary enforced at `open`. The
/// identity set makes the deny robust against namespace games (hardlinks,
/// renames, and pre-existing aliases): a [`FileId`] is the kernel file handle,
/// which encodes the inode and a generation number, so it travels with the
/// file's identity rather than the name used to reach it and is immune to
/// inode reuse. An open is denied if the opened file's identity matches, no
/// matter which path led to it. With `AT_HANDLE_FID` the kernel encodes an
/// identity FID for essentially every filesystem (generic inode FID where
/// NFS-export ops are absent); the rare path that still fails captures no
/// identity and relies on the always-on path prefix.
#[derive(Default)]
pub struct DeniedSet {
    paths: std::sync::RwLock<HashSet<String>>,
    ids: std::sync::RwLock<HashSet<FileId>>,
}

/// A file's stable identity: its kernel file handle, keyed by the superblock
/// device so identical handles from different filesystems cannot collide.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct FileId {
    dev: u64,
    handle_type: i32,
    handle: Vec<u8>,
}

/// Identity of a path, following symlinks (the open will resolve to the same
/// target). `None` if it cannot be resolved or no handle can be encoded. The
/// `(handle_type, handle)` FID comes from [`crate::sys::fs::file_handle`]; it is
/// keyed by the superblock `dev` so handles from different filesystems cannot
/// collide.
pub(crate) fn file_id_of_path(path: &str) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).ok()?.dev();
    let c = std::ffi::CString::new(path).ok()?;
    let (handle_type, handle) =
        crate::sys::fs::file_handle(libc::AT_FDCWD, &c, libc::AT_SYMLINK_FOLLOW)?;
    Some(FileId { dev, handle_type, handle })
}

/// Identity of an open fd.
pub(crate) fn file_id_of_fd(fd: std::os::unix::io::RawFd) -> Option<FileId> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let empty = std::ffi::CString::new("").ok()?;
    let (handle_type, handle) = crate::sys::fs::file_handle(fd, &empty, libc::AT_EMPTY_PATH)?;
    Some(FileId { dev: st.st_dev as u64, handle_type, handle })
}

impl DeniedSet {
    /// Deny `path` (and its subtree, by prefix). Also captures the file's
    /// handle identity if it exists now, so the deny still applies after the
    /// file is hardlinked or renamed to a non-denied name.
    pub fn deny(&self, path: &str) {
        if let Ok(mut p) = self.paths.write() {
            p.insert(path.to_string());
        }
        if let Some(id) = file_id_of_path(path) {
            if let Ok(mut i) = self.ids.write() {
                i.insert(id);
            }
        }
    }

    /// Stop denying `path`, dropping its captured identity too (best-effort:
    /// only if the path still resolves). A leftover identity would only ever
    /// over-deny, which is fail-safe.
    pub fn allow(&self, path: &str) {
        if let Ok(mut p) = self.paths.write() {
            p.remove(path);
        }
        if let Some(id) = file_id_of_path(path) {
            if let Ok(mut i) = self.ids.write() {
                i.remove(&id);
            }
        }
    }

    /// True if `path` is at or beneath a denied path (lexical prefix).
    pub fn is_path_denied(&self, path: &str) -> bool {
        self.paths.read().map_or(false, |denied| {
            let path = std::path::Path::new(path);
            denied
                .iter()
                .any(|d| path.starts_with(std::path::Path::new(d)))
        })
    }

    /// True if `id` is a denied file identity (catches hardlinks, renames, and
    /// pre-existing aliases regardless of the path used).
    pub(crate) fn is_id_denied(&self, id: &FileId) -> bool {
        self.ids.read().map_or(false, |s| s.contains(id))
    }

    /// Whether any deny rule is in effect.
    pub fn is_empty(&self) -> bool {
        self.paths.read().map_or(true, |p| p.is_empty())
            && self.ids.read().map_or(true, |i| i.is_empty())
    }

    /// Snapshot of the currently-denied path prefixes (sorted, deduped).
    /// Used by the control-socket `config` verb to reflect dynamic
    /// `policy_fn`-issued `deny_path()` calls in the effective policy.
    pub fn denied_paths(&self) -> Vec<String> {
        self.paths.read().map_or(Vec::new(), |p| {
            let mut v: Vec<String> = p.iter().cloned().collect();
            v.sort();
            v.dedup();
            v
        })
    }
}

// ============================================================
// PolicyFnState — dynamic policy callback state
// ============================================================

/// Dynamic policy callback state.
pub struct PolicyFnState {
    /// Event sender for dynamic policy callback (None if no policy_fn).
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::policy_fn::PolicyEvent>>,
    /// Shared live policy for dynamic updates (None if no policy_fn).
    pub live_policy: Option<std::sync::Arc<std::sync::RwLock<crate::policy_fn::LivePolicy>>>,
    /// Dynamically denied paths and inode identities from policy_fn / fs_deny.
    pub denied: std::sync::Arc<DeniedSet>,
}

impl PolicyFnState {
    pub fn new() -> Self {
        Self {
            event_tx: None,
            live_policy: None,
            denied: std::sync::Arc::new(DeniedSet::default()),
        }
    }

    /// Check if a path is at or beneath a denied path.
    pub fn is_path_denied(&self, path: &str) -> bool {
        self.denied.is_path_denied(path)
    }

    /// Check if an opened file's handle identity is denied.
    pub(crate) fn is_id_denied(&self, id: &FileId) -> bool {
        self.denied.is_id_denied(id)
    }

    /// Whether any deny rule is currently in effect. Cheap gate for the
    /// race-free on-behalf open path: with no denies there is no carve-out
    /// to protect and opens are left to the kernel and Landlock.
    pub fn has_denied_paths(&self) -> bool {
        !self.denied.is_empty()
    }
}

// ============================================================
// ChrootState — chroot-specific runtime state
// ============================================================

/// Chroot-specific sandbox-global runtime state.
///
/// Executable identity deliberately does not live here: one sandbox can host
/// many concurrent process images, so that state belongs to `ProcessIndex`.
pub struct ChrootState;

impl ChrootState {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn current_executable() -> std::fs::File {
        std::fs::File::open("/proc/self/exe").expect("open current executable")
    }

    #[test]
    fn process_index_register_lookup_unregister() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx
            .register(self_pid)
            .expect("register should succeed for live pid");
        assert_eq!(key.pid, self_pid);

        assert_eq!(idx.key_for(self_pid), Some(key));
        assert!(idx.contains(self_pid));
        assert!(idx.contains_current(self_pid));
        assert_eq!(idx.key_for(self_pid + 999_999), None);
        assert!(!idx.contains(self_pid + 999_999));
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.max_pid(), Some(self_pid));
        let executable = current_executable();
        assert!(idx.stage_virtual_executable(
            key,
            PathBuf::from("/usr/bin/current"),
            executable.as_raw_fd(),
        ));
        assert_eq!(
            idx.virtual_executable(self_pid),
            Some(PathBuf::from("/usr/bin/current"))
        );

        idx.unregister(key);
        assert_eq!(idx.key_for(self_pid), None);
        assert_eq!(idx.virtual_executable(self_pid), None);
        assert!(!idx.contains(self_pid));
        assert!(!idx.contains_current(self_pid));
        assert_eq!(idx.len(), 0);
        assert_eq!(idx.max_pid(), None);
    }

    #[test]
    fn threads_of_one_process_share_one_cwd() {
        // The kernel gives pthreads a shared fs_struct, so a chdir in one
        // thread moves its siblings. Registering a tid must join the leader's
        // cwd rather than start a private one.
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let leader_key = idx.register(leader).expect("leader registers");
        let executable = current_executable();
        assert!(idx.stage_virtual_executable(
            leader_key,
            PathBuf::from("/usr/bin/leader"),
            executable.as_raw_fd(),
        ));

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            // Stay alive: register() reads /proc/<tid>/stat.
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        let tid_key = idx.register(tid).expect("thread registers");

        idx.set_virtual_cwd(tid, PathBuf::from("/workspace"));
        assert_eq!(idx.virtual_cwd(leader), Some(PathBuf::from("/workspace")));
        assert_eq!(
            idx.virtual_executable(tid),
            Some(PathBuf::from("/usr/bin/leader"))
        );
        assert!(idx.stage_virtual_executable(
            tid_key,
            PathBuf::from("/usr/bin/replaced"),
            executable.as_raw_fd(),
        ));
        assert_eq!(
            idx.virtual_executable(leader),
            Some(PathBuf::from("/usr/bin/replaced"))
        );

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn an_unregistered_thread_uses_its_leader_cwd() {
        // pidfd_open on a non-leader tid needs PIDFD_THREAD (Linux 6.9), so
        // register_pid_if_new can leave a thread without an entry of its own.
        // It still shares the leader's fs_struct, so its chdir must land in
        // the leader's cell rather than vanish.
        let leader = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        idx.register(leader).expect("leader registers");

        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            tid_tx.send(tid).unwrap();
            let _ = stop_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        // Deliberately not registered.
        assert!(!idx.contains(tid));

        idx.set_virtual_cwd(tid, PathBuf::from("/workspace"));
        assert_eq!(idx.virtual_cwd(tid), Some(PathBuf::from("/workspace")));
        assert_eq!(idx.virtual_cwd(leader), Some(PathBuf::from("/workspace")));

        let _ = stop_tx.send(());
        thread.join().unwrap();
    }

    #[test]
    fn a_child_copies_the_parent_cwd_instead_of_sharing_it() {
        // fork(2) copies fs_struct: the child starts where the parent stood,
        // and its later chdir must not move the parent.
        let parent = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let parent_key = idx.register(parent).expect("parent registers");
        idx.set_virtual_cwd(parent, PathBuf::from("/workspace"));
        let executable = current_executable();
        assert!(idx.stage_virtual_executable(
            parent_key,
            PathBuf::from("/usr/bin/parent"),
            executable.as_raw_fd(),
        ));

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Async-signal-safe only: sleep, then leave without unwinding.
            let ts = libc::timespec { tv_sec: 30, tv_nsec: 0 };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            unsafe { libc::_exit(0) };
        }

        let child_key = idx.register(child).expect("child registers");
        assert_eq!(idx.virtual_cwd(child), Some(PathBuf::from("/workspace")));
        assert_eq!(
            idx.virtual_executable(child),
            Some(PathBuf::from("/usr/bin/parent"))
        );

        idx.set_virtual_cwd(child, PathBuf::from("/tmp"));
        assert_eq!(idx.virtual_cwd(parent), Some(PathBuf::from("/workspace")));
        assert!(idx.stage_virtual_executable(
            child_key,
            PathBuf::from("/usr/bin/child"),
            executable.as_raw_fd(),
        ));
        assert_eq!(
            idx.virtual_executable(parent),
            Some(PathBuf::from("/usr/bin/parent"))
        );

        unsafe { libc::kill(child, libc::SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
    }

    #[test]
    fn process_index_register_overwrites_stale_entry_for_recycled_pid() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        // Forge a stale entry by direct insertion under the lock.
        {
            let stale_key = PidKey { pid: self_pid, start_time: 0 };
            let stale = ProcessEntry {
                key: stale_key,
                tgid: self_pid,
                state: Arc::new(AsyncMutex::new(PerProcessState::default())),
                cwd: SharedCwd::default(),
                executable: SharedExecutable::default(),
                process_slot: None,
            };
            idx.inner.write().unwrap().insert(self_pid, stale);
        }
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        let executable = current_executable();
        assert!(!idx.stage_virtual_executable(
            stale_key,
            PathBuf::from("/stale"),
            executable.as_raw_fd(),
        ));
        assert!(!idx.contains_current(self_pid));
        assert_eq!(idx.virtual_executable(self_pid), None);

        let new_key = idx.register(self_pid).unwrap();
        assert_ne!(new_key.start_time, 0);
        assert_eq!(idx.key_for(self_pid), Some(new_key));
        assert!(idx.contains_current(self_pid));
        assert_eq!(idx.virtual_executable(self_pid), None);

        // Unregistering by the stale key must NOT clobber the fresh
        // registration; only an exact-match unregister wins.
        assert!(!idx.stage_virtual_executable(
            stale_key,
            PathBuf::from("/stale"),
            executable.as_raw_fd(),
        ));
        idx.unregister(stale_key);
        assert_eq!(idx.key_for(self_pid), Some(new_key));
        assert_eq!(idx.virtual_executable(self_pid), None);
    }

    #[tokio::test]
    async fn process_index_entry_for_returns_shared_handle() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();

        let (k1, s1) = idx.entry_for(self_pid).unwrap();
        let (k2, s2) = idx.entry_for(self_pid).unwrap();
        assert_eq!(k1, key);
        assert_eq!(k2, key);

        // Two clones of the same Arc — writes through one are visible
        // through the other.
        s1.lock().await.brk_base = Some(0xdead_beef);
        assert_eq!(s2.lock().await.brk_base, Some(0xdead_beef));

        // After unregister, entry_for returns None but existing Arc
        // clones stay valid (kept alive by callers).
        idx.unregister(key);
        assert!(idx.entry_for(self_pid).is_none());
        assert_eq!(s1.lock().await.brk_base, Some(0xdead_beef));
    }

    #[test]
    fn process_index_pids_snapshot_is_independent() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        let snap = idx.pids_snapshot();
        idx.unregister(key);
        assert!(snap.contains(&self_pid));
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn process_index_prune_dead_drops_recycled_entries() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        // Insert a stale entry for self with a wrong start_time.
        let stale_key = PidKey { pid: self_pid, start_time: 0 };
        let stale = ProcessEntry {
            key: stale_key,
            tgid: self_pid,
            state: Arc::new(AsyncMutex::new(PerProcessState::default())),
            cwd: SharedCwd::default(),
            executable: SharedExecutable::default(),
            process_slot: None,
        };
        idx.inner.write().unwrap().insert(self_pid, stale);

        for key in idx.dead_keys() {
            idx.unregister(key);
        }
        assert!(!idx.contains(self_pid));
    }

    #[test]
    fn process_index_prune_dead_keeps_live_entries() {
        let self_pid = unsafe { libc::getpid() };
        let idx = ProcessIndex::new();
        let key = idx.register(self_pid).unwrap();
        assert!(idx.dead_keys().is_empty());
        assert_eq!(idx.key_for(self_pid), Some(key));
    }
}
