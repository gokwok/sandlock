//! Session-scoped lifecycle for hosted runtimes. No numeric-PID-only signaling.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::sys::structs::SeccompNotif;
use serde::{Deserialize, Serialize};

#[path = "execution_domain_freeze.rs"]
mod freeze;

const MAX_TASKS: usize = 8192;
const MAX_PROC_ENTRIES: usize = 1_000_000;
const MAX_HELD_NOTIFICATIONS: usize = 8192;

/// Identity of a *live*, unreaped session anchor. Never use as durable policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDomainDescriptor {
    pub session_id: i32,
    pub anchor_start_time: u64,
}

/// Controls all process groups in an explicitly owned Linux session.
/// The direct parent must retain the unreaped anchor until domain retirement.
pub struct ExecutionDomain {
    descriptor: ExecutionDomainDescriptor,
    anchor: OwnedFd,
    retired: AtomicBool,
    terminating: AtomicBool,
    frozen: Mutex<FreezeState>,
    pub(crate) gate: Arc<NotificationGate>,
}

struct TaskStat {
    state: u8,
    session: i32,
    start: u64,
}

fn stat(pid: i32) -> io::Result<TaskStat> {
    read_stat(fs::File::open(format!("/proc/{pid}/stat"))?)
}

fn read_stat(reader: impl Read) -> io::Result<TaskStat> {
    let mut value = String::new();
    reader.take(4096).read_to_string(&mut value)?;
    let fields: Vec<_> = value
        .rsplit_once(')')
        .ok_or_else(invalid_stat)?
        .1
        .split_whitespace()
        .collect();
    Ok(TaskStat {
        state: *fields
            .first()
            .and_then(|s| s.as_bytes().first())
            .ok_or_else(invalid_stat)?,
        session: fields
            .get(3)
            .ok_or_else(invalid_stat)?
            .parse()
            .map_err(|_| invalid_stat())?,
        start: fields
            .get(19)
            .ok_or_else(invalid_stat)?
            .parse()
            .map_err(|_| invalid_stat())?,
    })
}

fn invalid_stat() -> io::Error {
    io::Error::other("invalid execution-domain task stat")
}

fn gone(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
}

fn send(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: pidfd is owned and live; a null siginfo requests a normal signal.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if !gone(&error) {
            return Err(error);
        }
    }
    Ok(())
}

fn exited(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll points to one initialized pollfd for an owned descriptor.
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(poll.revents & (libc::POLLIN | libc::POLLHUP) != 0)
}

struct FreezeAttempt<'a> {
    domain: &'a ExecutionDomain,
    active: bool,
    throttle: bool,
}
impl Drop for FreezeAttempt<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.domain.release_pause(self.throttle);
        }
    }
}

#[derive(Default)]
struct FreezeState {
    manual: bool,
    throttle: bool,
    trace: Option<freeze::SessionFreeze>,
}

pub(crate) struct ThrottleGuard<'a>(&'a ExecutionDomain);
impl Drop for ThrottleGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.release_pause(true);
    }
}

impl ExecutionDomain {
    pub(crate) fn capture(anchor: i32, killable_recv: bool) -> io::Result<Arc<Self>> {
        let info = stat(anchor)?;
        if info.session != anchor {
            return Err(io::Error::other(
                "execution did not establish its own session",
            ));
        }
        let domain = Self::open(ExecutionDomainDescriptor {
            session_id: anchor,
            anchor_start_time: info.start,
        })?;
        domain
            .gate
            .killable_recv
            .store(killable_recv, Ordering::Release);
        Ok(domain)
    }

    /// Open an observer while the original session anchor still exists.
    /// An observer may signal/terminate, but only the owning Sandbox can freeze.
    pub fn open(descriptor: ExecutionDomainDescriptor) -> io::Result<Arc<Self>> {
        if descriptor.session_id <= 0 {
            return Err(invalid_stat());
        }
        let anchor = crate::sys::syscall::pidfd_open(descriptor.session_id as u32, 0)?;
        let domain = Arc::new(Self {
            descriptor,
            anchor,
            retired: AtomicBool::new(false),
            terminating: AtomicBool::new(false),
            frozen: Mutex::new(FreezeState::default()),
            gate: Arc::new(NotificationGate::default()),
        });
        domain.validate_anchor()?;
        Ok(domain)
    }

    pub fn descriptor(&self) -> ExecutionDomainDescriptor {
        self.descriptor
    }

    pub(crate) fn is_terminating(&self) -> bool {
        self.terminating.load(Ordering::Acquire)
    }

    fn release_killed_tracees(&self) -> io::Result<()> {
        if let Some(trace) = self.frozen.lock().unwrap().trace.take() {
            trace.release()?;
        }
        Ok(())
    }

    pub(crate) fn terminate_blocking(&self, timeout: Duration) -> io::Result<()> {
        if self.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        self.gate.close();
        self.terminating.store(true, Ordering::Release);
        let deadline = Instant::now() + timeout;
        loop {
            let members = self.members()?;
            if members.is_empty() && self.gate.idle() {
                self.retired.store(true, Ordering::Release);
                return Ok(());
            }
            for member in members {
                send(&member, libc::SIGKILL)?;
            }
            self.release_killed_tracees()?;
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "abandoned execution domain requires retained cleanup",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn diagnostic(&self) -> String {
        let state = self.gate.state.lock().unwrap();
        let mut result = format!(
            "sid={} active={} held={}",
            self.descriptor.session_id,
            state.active,
            state.held.len()
        );
        drop(state);
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.take(MAX_PROC_ENTRIES).flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                if stat(pid).is_ok_and(|s| s.session == self.descriptor.session_id) {
                    if let Ok(tasks) = fs::read_dir(entry.path().join("task")) {
                        for task in tasks.take(64).flatten() {
                            if result.len() > 4096 {
                                return result;
                            }
                            if let Ok(status) = fs::read_to_string(task.path().join("status")) {
                                result.push_str(&format!(
                                    " [{} {}]",
                                    task.file_name().to_string_lossy(),
                                    status
                                        .lines()
                                        .filter(|l| l.starts_with("State:")
                                            || l.starts_with("TracerPid:"))
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                ));
                            }
                        }
                    }
                }
            }
        }
        result
    }

    fn validate_anchor(&self) -> io::Result<()> {
        let info = stat(self.descriptor.session_id)
            .map_err(|e| io::Error::other(format!("execution domain anchor unavailable: {e}")))?;
        if info.session != self.descriptor.session_id
            || info.start != self.descriptor.anchor_start_time
        {
            return Err(io::Error::other("execution domain anchor identity changed"));
        }
        // pidfd_send_signal(0) also prevents a reopened numeric PID from being
        // mistaken for the captured anchor. A zombie is intentionally retained.
        // SAFETY: anchor is an owned pidfd and no siginfo pointer is supplied.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.anchor.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(io::Error::other("execution domain anchor was reaped"));
        }
        Ok(())
    }

    fn members(&self) -> io::Result<Vec<OwnedFd>> {
        if self.retired.load(Ordering::Acquire) {
            return Ok(Vec::new());
        }
        self.validate_anchor()?;
        let mut members = Vec::new();
        for (count, entry) in fs::read_dir("/proc")?.enumerate() {
            if count >= MAX_PROC_ENTRIES {
                return Err(io::Error::other("process enumeration budget exceeded"));
            }
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let before = match stat(pid) {
                Ok(s) => s,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            if before.session != self.descriptor.session_id {
                continue;
            }
            let fd = match crate::sys::syscall::pidfd_open(pid as u32, 0) {
                Ok(fd) => fd,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            if exited(&fd)? {
                continue;
            }
            let after = match stat(pid) {
                Ok(s) => s,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            if after.start != before.start || after.session != before.session {
                continue;
            }
            if members.len() >= MAX_TASKS {
                return Err(io::Error::other("execution domain task budget exceeded"));
            }
            members.push(fd);
        }
        self.validate_anchor()?;
        Ok(members)
    }

    /// Signal every currently live process using stable kernel identities.
    /// For complete teardown use `terminate_and_wait`, not a single signal pass.
    pub fn signal(&self, signal: i32) -> io::Result<()> {
        if signal == libc::SIGKILL {
            self.terminating.store(true, Ordering::Release);
            self.gate.close();
        }
        for member in self.members()? {
            send(&member, signal)?;
        }
        if signal == libc::SIGKILL {
            self.release_killed_tracees()?;
        }
        Ok(())
    }

    /// Prove no live session member remains. Does not reap the anchor.
    pub async fn terminate_and_wait(&self, timeout: Duration) -> io::Result<()> {
        if self.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        self.gate.close();
        self.terminating.store(true, Ordering::Release);
        let deadline = Instant::now() + timeout;
        loop {
            let members = self.members()?;
            if members.is_empty() && self.gate.idle() {
                self.retired.store(true, Ordering::Release);
                return Ok(());
            }
            for member in members {
                send(&member, libc::SIGKILL)?;
            }
            self.release_killed_tracees()?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("execution domain teardown timed out: {}", self.diagnostic()),
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(crate) async fn pause_and_wait(&self, timeout: Duration) -> io::Result<()> {
        self.pause_inner(timeout, false).await
    }

    pub(crate) fn throttle_guard(&self) -> ThrottleGuard<'_> {
        ThrottleGuard(self)
    }

    pub(crate) async fn throttle_pause(&self, timeout: Duration) -> io::Result<()> {
        self.pause_inner(timeout, true).await
    }

    pub(crate) fn throttle_resume(&self) -> io::Result<()> {
        self.release_pause(true)
    }

    async fn pause_inner(&self, timeout: Duration, throttle: bool) -> io::Result<()> {
        {
            let mut frozen = self.frozen.lock().unwrap();
            if throttle {
                frozen.throttle = true;
            } else {
                frozen.manual = true;
            }
            self.gate.close();
        }
        let mut attempt = FreezeAttempt {
            domain: self,
            active: true,
            throttle,
        };
        let deadline = Instant::now() + timeout;
        loop {
            // Do not stop tasks still owned by fork/exec ptrace workers.
            if self.gate.idle() {
                if self.gate.killable_recv.load(Ordering::Acquire) {
                    self.stop_tasks()?;
                } else {
                    // Interruptible notification waits participate in group-stop.
                    // Process pidfds suffice on old kernels; no numeric-TID
                    // signals or unsupported PIDFD_THREAD handles are needed.
                    self.signal(libc::SIGSTOP)?;
                }
                if !self.tasks_stoppable()? {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("execution domain did not settle: {}", self.diagnostic()),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                let mut frozen = self.frozen.lock().unwrap();
                if frozen.trace.is_none() {
                    frozen.trace = Some(freeze::SessionFreeze::start(
                        self.descriptor,
                        Arc::clone(&self.gate),
                        deadline.saturating_duration_since(Instant::now()),
                    )?);
                }
                attempt.active = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("execution domain freeze timed out: {}", self.diagnostic()),
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub(crate) fn resume(&self) -> io::Result<()> {
        self.release_pause(false)
    }

    // A process-directed SIGSTOP may select a thread parked in a killable
    // seccomp wait. Until that thread returns, siblings may never start the
    // group-stop. Deliver to each thread identity so runnable siblings stop as
    // well, without replying to or withdrawing any parked syscall.
    fn stop_tasks(&self) -> io::Result<()> {
        self.validate_anchor()?;
        let mut total = 0;
        for (count, entry) in fs::read_dir("/proc")?.enumerate() {
            if count >= MAX_PROC_ENTRIES {
                return Err(io::Error::other("process enumeration budget exceeded"));
            }
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let info = match stat(pid) {
                Ok(info) => info,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            if info.session != self.descriptor.session_id {
                continue;
            }
            let tasks = match fs::read_dir(entry.path().join("task")) {
                Ok(tasks) => tasks,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            for task in tasks {
                total += 1;
                if total > MAX_TASKS {
                    return Err(io::Error::other("execution domain task budget exceeded"));
                }
                let task = task?;
                let tid = task
                    .file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .map_err(|_| invalid_stat())?;
                let before = match stat(tid) {
                    Ok(info) => info,
                    Err(e) if gone(&e) => continue,
                    Err(e) => return Err(e),
                };
                let fd = match crate::sys::syscall::pidfd_open(tid as u32, libc::O_EXCL as u32) {
                    Ok(fd) => fd,
                    Err(e) if gone(&e) => continue,
                    Err(e) => return Err(e),
                };
                match stat(tid) {
                    Ok(after)
                        if before.start == after.start
                            && after.session == self.descriptor.session_id =>
                    {
                        send(&fd, libc::SIGSTOP)?
                    }
                    Ok(_) => {}
                    Err(e) if gone(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        self.validate_anchor()
    }

    fn tasks_stoppable(&self) -> io::Result<bool> {
        self.validate_anchor()?;
        let mut total = 0;
        for (count, process) in fs::read_dir("/proc")?.enumerate() {
            if count >= MAX_PROC_ENTRIES {
                return Err(io::Error::other("process enumeration budget exceeded"));
            }
            let process = process?;
            let Ok(pid) = process.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let info = match stat(pid) {
                Ok(s) => s,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            if info.session != self.descriptor.session_id {
                continue;
            }
            let tasks = match fs::read_dir(process.path().join("task")) {
                Ok(t) => t,
                Err(e) if gone(&e) => continue,
                Err(e) => return Err(e),
            };
            for task in tasks {
                total += 1;
                if total > MAX_TASKS {
                    return Err(io::Error::other("execution domain task budget exceeded"));
                }
                let task = task?;
                let tid = task
                    .file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .map_err(|_| invalid_stat())?;
                match stat(tid) {
                    Ok(s) if matches!(s.state, b'T' | b'Z' | b'X') || self.gate.holds(tid) => {}
                    Ok(_) => return Ok(false),
                    Err(e) if gone(&e) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        self.validate_anchor()?;
        Ok(true)
    }

    fn release_pause(&self, throttle: bool) -> io::Result<()> {
        let mut frozen = self.frozen.lock().unwrap();
        if throttle {
            frozen.throttle = false;
        } else {
            frozen.manual = false;
        }
        if !frozen.manual && !frozen.throttle {
            if let Some(trace) = frozen.trace.take() {
                trace.release()?;
            }
            if !self.is_terminating() {
                self.signal(libc::SIGCONT)?;
                self.gate.open();
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct GateState {
    closed: bool,
    active: usize,
    held: VecDeque<SeccompNotif>,
}

pub(crate) struct NotificationGate {
    state: Mutex<GateState>,
    notif_fd: AtomicI32,
    killable_recv: AtomicBool,
    pub(crate) changed: tokio::sync::Notify,
}

impl Default for NotificationGate {
    fn default() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            notif_fd: AtomicI32::new(-1),
            killable_recv: AtomicBool::new(false),
            changed: tokio::sync::Notify::new(),
        }
    }
}

pub(crate) enum Admission {
    Run(NotificationPermit),
    Held,
    Full,
}
pub(crate) struct NotificationPermit(Arc<NotificationGate>);
impl Drop for NotificationPermit {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
    }
}

impl NotificationGate {
    pub(crate) fn attach(&self, fd: i32) {
        self.notif_fd.store(fd, Ordering::Release);
    }
    fn holds(&self, tid: i32) -> bool {
        if !self.killable_recv.load(Ordering::Acquire) {
            // ID_VALID only proves that a notification exists now. Without
            // killable receive, a signal may invalidate it immediately.
            return false;
        }
        let state = self.state.lock().unwrap();
        state.closed
            && state.held.iter().any(|n| {
                n.pid == tid as u32
                    && crate::seccomp::notif::id_valid(self.notif_fd.load(Ordering::Acquire), n.id)
                        .is_ok()
            })
    }
    pub(crate) fn enter(self: &Arc<Self>, notif: SeccompNotif) -> Admission {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            if state.held.len() == MAX_HELD_NOTIFICATIONS {
                let fd = self.notif_fd.load(Ordering::Acquire);
                state
                    .held
                    .retain(|notif| crate::seccomp::notif::id_valid(fd, notif.id).is_ok());
            }
            if state.held.len() == MAX_HELD_NOTIFICATIONS {
                return Admission::Full;
            }
            state.held.push_back(notif);
            Admission::Held
        } else {
            state.active += 1;
            Admission::Run(NotificationPermit(Arc::clone(self)))
        }
    }
    fn close(&self) {
        self.state.lock().unwrap().closed = true;
    }
    fn open(&self) {
        self.state.lock().unwrap().closed = false;
        self.changed.notify_one();
    }
    fn idle(&self) -> bool {
        self.state.lock().unwrap().active == 0
    }
    pub(crate) fn pop(&self) -> Option<SeccompNotif> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            None
        } else {
            state.held.pop_front()
        }
    }
}
