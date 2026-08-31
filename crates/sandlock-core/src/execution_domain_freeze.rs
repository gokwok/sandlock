//! Pinned ptrace owner for a filesystem freeze. SIGCONT cannot release it.

use super::*;
use std::sync::mpsc::{self, Receiver, SyncSender};

pub(super) struct SessionFreeze {
    release: SyncSender<()>,
    finished: Receiver<Result<(), String>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl SessionFreeze {
    pub(super) fn start(
        descriptor: ExecutionDomainDescriptor,
        gate: Arc<NotificationGate>,
        timeout: Duration,
    ) -> io::Result<Self> {
        let (release, commands) = mpsc::sync_channel(1);
        let (finished_tx, finished) = mpsc::sync_channel(1);
        let (prepared_tx, prepared) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("sandlock-domain-freeze".into())
            .spawn(move || {
                let mut tasks = Vec::new();
                let result = freeze(descriptor, &gate, Instant::now() + timeout, &mut tasks);
                let success = result.is_ok();
                if prepared_tx
                    .send(result.map_err(|error| error.to_string()))
                    .is_ok()
                    && success
                {
                    let _ = commands.recv();
                }
                let result = detach(&tasks).map_err(|error| error.to_string());
                let _ = finished_tx.send(result);
            })?;
        let trace = Self {
            release,
            finished,
            worker: Some(worker),
        };
        prepared
            .recv_timeout(timeout + Duration::from_secs(1))
            .map_err(|_| io::Error::other("domain freezer exited or timed out during setup"))?
            .map_err(io::Error::other)?;
        Ok(trace)
    }

    pub(super) fn release(mut self) -> io::Result<()> {
        self.finish()
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.worker.is_none() {
            return Ok(());
        }
        let _ = self.release.try_send(());
        let result = self
            .finished
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| io::Error::other("domain freezer cleanup did not complete"))?
            .map_err(io::Error::other);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| io::Error::other("domain freezer panicked"))?;
        }
        result
    }
}

impl Drop for SessionFreeze {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("sandlock: domain freezer cleanup failed: {error}");
        }
    }
}

struct Task {
    tid: i32,
    pidfd: OwnedFd,
}

fn freeze(
    descriptor: ExecutionDomainDescriptor,
    gate: &NotificationGate,
    deadline: Instant,
    seized: &mut Vec<Task>,
) -> io::Result<()> {
    let domain = ExecutionDomain::open(descriptor)?;
    // The owner closed the notification gate and drained fork/exec handlers.
    // No thread can be born or exec while this task list is being frozen.
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
        if info.session != descriptor.session_id {
            continue;
        }
        let tasks = match fs::read_dir(process.path().join("task")) {
            Ok(t) => t,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(e),
        };
        for entry in tasks {
            if seized.len() >= MAX_TASKS {
                return Err(io::Error::other("execution domain task budget exceeded"));
            }
            let entry = entry?;
            let tid = entry
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .map_err(|_| invalid_stat())?;
            if !gate.holds(tid) {
                seize(tid, descriptor.session_id, deadline, seized)?;
            }
        }
    }
    domain.validate_anchor()?;
    Ok(())
}

fn seize(tid: i32, session: i32, deadline: Instant, seized: &mut Vec<Task>) -> io::Result<()> {
    let before = match stat(tid) {
        Ok(s) => s,
        Err(e) if gone(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    if before.session != session || matches!(before.state, b'Z' | b'X') {
        return Ok(());
    }
    let pidfd = match crate::sys::syscall::pidfd_open(tid as u32, libc::O_EXCL as u32) {
        Ok(fd) => fd,
        Err(e) if gone(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    // SAFETY: this thread owns every ptrace operation. EXITKILL prevents a
    // failed freeze worker from releasing unconfirmed attachments to run.
    if unsafe { libc::ptrace(libc::PTRACE_SEIZE, tid, 0, libc::PTRACE_O_EXITKILL) } < 0 {
        let e = io::Error::last_os_error();
        return if gone(&e) { Ok(()) } else { Err(e) };
    }
    seized.push(Task { tid, pidfd });
    let current = stat(tid)?;
    if current.session != session || current.start != before.start {
        return Err(io::Error::other(
            "task identity changed while freezing execution domain",
        ));
    }
    // SAFETY: this worker just seized this task, and retains its identity fd.
    if unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0) } < 0 {
        let e = io::Error::last_os_error();
        return if gone(&e) { Ok(()) } else { Err(e) };
    }
    // SIGSTOP is uncatchable; under ptrace it becomes a held delivery stop.
    // Received notification waiters were separately proven kernel-parked and
    // skipped above; WAIT_KILLABLE_RECV is mandatory for that proof.
    send(&seized.last().unwrap().pidfd, libc::SIGSTOP)?;
    loop {
        // SAFETY: waitid fills initialized siginfo; only consume ptrace stops,
        // never terminal status (the session anchor must remain unreaped).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                tid as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WNOHANG | libc::__WALL,
            )
        };
        if rc == 0 && info.si_code == libc::CLD_TRAPPED && unsafe { info.si_pid() } == tid {
            return Ok(());
        }
        if exited(&seized.last().unwrap().pidfd)? {
            return Ok(());
        }
        if rc < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(io::Error::last_os_error());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "task {tid} did not enter a held ptrace stop: state={} wchan={}",
                    stat(tid).map(|s| s.state as char).unwrap_or('?'),
                    fs::read_to_string(format!("/proc/{tid}/wchan")).unwrap_or_default()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn detach(tasks: &[Task]) -> io::Result<()> {
    let mut failure = None;
    for task in tasks.iter().rev() {
        // SAFETY: attachments were made by this same worker and were never
        // transferred to another tracer. ESRCH denotes an exited tracee.
        if unsafe { libc::ptrace(libc::PTRACE_DETACH, task.tid, 0, 0) } < 0 {
            let error = io::Error::last_os_error();
            if !gone(&error) {
                failure = Some(error);
            }
        }
    }
    failure.map_or(Ok(()), Err)
}
