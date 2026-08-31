//! Bubblewrap launcher for the mount-namespace filesystem backend.

use std::ffi::{CString, OsStr, OsString};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::context::PipePair;
use crate::filesystem_backend::{EntryPurpose, FilesystemEntry, FilesystemPlan, MountAccess};
use crate::sandbox::Sandbox;
use crate::sys::structs::SockFilter;

const BOOTSTRAP_DESTINATION: &str = "/.sandlock-bootstrap";
use crate::bootstrap::LISTENER_MAGIC;

pub(crate) struct PreparedBubblewrap {
    executable: CString,
    argv: Vec<CString>,
    argv_pointers: Vec<usize>,
    environment: Vec<CString>,
    environment_pointers: Vec<usize>,
    inherited: Vec<OwnedFd>,
    control_parent: Option<OwnedFd>,
    control_child: Option<OwnedFd>,
    pass_fds: Vec<RawFd>,
    cleanup_paths: Vec<PathBuf>,
}

fn cstring(value: impl AsRef<OsStr>) -> io::Result<CString> {
    CString::new(value.as_ref().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn bubblewrap_path(sandbox: &Sandbox) -> io::Result<PathBuf> {
    sandbox
        .bubblewrap_path
        .clone()
        .or_else(|| {
            ["/usr/bin/bwrap", "/bin/bwrap"]
                .into_iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
        })
        .or_else(|| find_in_path("bwrap"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Bubblewrap executable not found"))
}

pub(crate) fn probe(sandbox: &Sandbox) -> io::Result<(PathBuf, String)> {
    let path = bubblewrap_path(sandbox)?;
    let output = std::process::Command::new(&path)
        .arg("--version")
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{} --version exited with {}",
            path.display(),
            output.status
        )));
    }
    let output = String::from_utf8_lossy(&output.stdout);
    let version = output
        .split_whitespace()
        .last()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty Bubblewrap version"))?;
    Ok((path, format!("bwrap-{version}")))
}

fn bootstrap_path(sandbox: &Sandbox) -> io::Result<PathBuf> {
    if let Some(path) = &sandbox.bubblewrap_bootstrap_path {
        return path.is_file().then(|| path.clone()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("bootstrap not found: {}", path.display()),
            )
        });
    }
    let executable = std::env::current_exe()?;
    let parent = executable.parent().unwrap_or_else(|| Path::new("/"));
    [
        parent.join("sandlock-bootstrap"),
        parent.parent().unwrap_or(parent).join("sandlock-bootstrap"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
    .or_else(|| find_in_path("sandlock-bootstrap"))
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "sandlock-bootstrap executable not found",
        )
    })
}

fn open_path(path: &Path) -> io::Result<OwnedFd> {
    let path_c = cstring(path.as_os_str())?;
    let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::new(
            io::Error::last_os_error().kind(),
            format!(
                "open Bubblewrap source {}: {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_entry(entry: &FilesystemEntry) -> io::Result<Option<OwnedFd>> {
    match open_path(&entry.host_source) {
        Ok(fd) => Ok(Some(fd)),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && entry.purpose == EntryPurpose::PolicyGrant
                && entry.access == MountAccess::ReadOnly =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn make_filter_memfd(
    filter: &[SockFilter],
    environment: &[CString],
    devices: &[OsString],
) -> io::Result<OwnedFd> {
    let name = CString::new("sandlock-seccomp").unwrap();
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut file = std::fs::File::from(owned);
    file.write_all(&crate::bootstrap::FILTER_MAGIC)?;
    file.write_all(&(filter.len() as u32).to_le_bytes())?;
    for instruction in filter {
        file.write_all(&instruction.code.to_le_bytes())?;
        file.write_all(&[instruction.jt, instruction.jf])?;
        file.write_all(&instruction.k.to_le_bytes())?;
    }
    write_strings(
        &mut file,
        environment.iter().map(|value| value.as_bytes()),
        16384,
        crate::bootstrap::MAX_ENVIRONMENT_BYTES,
    )?;
    write_strings(
        &mut file,
        devices.iter().map(|value| value.as_bytes()),
        crate::bootstrap::MAX_READ_DEVICES,
        crate::bootstrap::MAX_READ_DEVICES * 4096,
    )?;
    file.flush()?;
    let owned: OwnedFd = file.into();
    if unsafe {
        libc::fcntl(
            owned.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

fn write_strings<'a>(
    file: &mut std::fs::File,
    values: impl Iterator<Item = &'a [u8]>,
    max_count: usize,
    max_bytes: usize,
) -> io::Result<()> {
    let values = values.collect::<Vec<_>>();
    if values.len() > max_count || values.iter().map(|value| value.len()).sum::<usize>() > max_bytes
    {
        return Err(io::Error::other("bootstrap strings exceed limit"));
    }
    file.write_all(&(values.len() as u32).to_le_bytes())?;
    for value in values {
        file.write_all(&(value.len() as u32).to_le_bytes())?;
        file.write_all(value)?;
    }
    Ok(())
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn proc_fd(fd: RawFd) -> OsString {
    OsString::from(format!("/proc/self/fd/{fd}"))
}

fn child_environment(sandbox: &Sandbox) -> io::Result<Vec<CString>> {
    use std::collections::BTreeMap;

    let mut environment = if sandbox.clean_env {
        BTreeMap::<OsString, OsString>::new()
    } else {
        std::env::vars_os().collect()
    };
    for name in &sandbox.inject_env_strip {
        environment.remove(OsStr::new(name));
    }
    for (key, value) in &sandbox.env {
        if key.as_bytes().contains(&b'=') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "environment key contains '='",
            ));
        }
        environment.insert(OsString::from(key), OsString::from(value));
    }
    if let Some(devices) = &sandbox.gpu_devices {
        if !devices.is_empty() {
            let visible = devices
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            environment.insert(
                OsString::from("CUDA_VISIBLE_DEVICES"),
                OsString::from(&visible),
            );
            environment.insert(
                OsString::from("ROCR_VISIBLE_DEVICES"),
                OsString::from(visible),
            );
        }
    }

    environment
        .into_iter()
        .map(|(key, value)| {
            let mut encoded = key.as_bytes().to_vec();
            encoded.push(b'=');
            encoded.extend_from_slice(value.as_bytes());
            CString::new(encoded).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "environment contains a NUL byte",
                )
            })
        })
        .collect()
}

fn push_arg(argv: &mut Vec<CString>, value: impl AsRef<OsStr>) -> io::Result<()> {
    argv.push(cstring(value)?);
    Ok(())
}

fn deny_source(plan: &FilesystemPlan, denied: &Path) -> Option<PathBuf> {
    plan.entries
        .iter()
        .filter(|entry| denied.starts_with(&entry.guest_path))
        .max_by_key(|entry| entry.guest_path.components().count())
        .map(|entry| {
            let relative = denied
                .strip_prefix(&entry.guest_path)
                .unwrap_or(Path::new(""));
            entry.host_source.join(relative)
        })
}

fn make_empty_mask(directory: bool) -> io::Result<(OwnedFd, PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::temp_dir().join(format!("sandlock-mask-{}", uuid::Uuid::new_v4()));
    if directory {
        std::fs::create_dir(&path)?;
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
    }
    match open_path(&path) {
        Ok(fd) => Ok((fd, path)),
        Err(error) => {
            let _ = if directory {
                std::fs::remove_dir(&path)
            } else {
                std::fs::remove_file(&path)
            };
            Err(error)
        }
    }
}

impl PreparedBubblewrap {
    pub(crate) fn prepare(
        sandbox: &Sandbox,
        plan: &FilesystemPlan,
        filter: &[SockFilter],
        pipes: &PipePair,
        command: &[&str],
        extra_target_fds: &[RawFd],
        foreground: bool,
    ) -> io::Result<Self> {
        let executable_path = bubblewrap_path(sandbox)?;
        let bootstrap_path = bootstrap_path(sandbox)?;
        let executable = cstring(executable_path.as_os_str())?;
        let mut argv = vec![cstring("bwrap")?];
        let mut inherited = Vec::new();
        let mut cleanup_paths = Vec::new();
        let mut read_devices = Vec::new();

        for option in ["--unshare-user", "--die-with-parent", "--tmpfs", "/"] {
            push_arg(&mut argv, option)?;
        }
        if let Some(run_as) = sandbox.user {
            push_arg(&mut argv, "--uid")?;
            push_arg(&mut argv, run_as.uid.to_string())?;
            push_arg(&mut argv, "--gid")?;
            push_arg(&mut argv, run_as.gid.to_string())?;
        }

        for entry in &plan.entries {
            // Same absent read-grant semantics as Landlock. Explicit mounts
            // and writable grants remain mandatory; never mount an ancestor.
            let Some(source) = open_entry(entry)? else {
                continue;
            };
            let source_path = proc_fd(source.as_raw_fd());
            let bind_option = match entry.access {
                MountAccess::ReadOnly => "--ro-bind",
                MountAccess::ReadWrite => "--bind",
                MountAccess::DeviceReadOnly | MountAccess::DeviceReadWrite => "--dev-bind",
            };
            push_arg(&mut argv, bind_option)?;
            push_arg(&mut argv, &source_path)?;
            push_arg(&mut argv, entry.guest_path.as_os_str())?;
            if entry.access == MountAccess::DeviceReadOnly {
                if !crate::bootstrap_devices::supported(&std::fs::metadata(&entry.host_source)?) {
                    return Err(io::Error::other("unsupported read-only device kind"));
                }
                read_devices.push(entry.guest_path.as_os_str().to_owned());
            }
            inherited.push(source);
        }

        if plan.proc_mounted {
            push_arg(&mut argv, "--proc")?;
            push_arg(&mut argv, "/proc")?;
        }

        // A deny below a visible entry becomes a same-kind empty read-only
        // bind. Denies outside the guest plan need no synthetic parent path.
        // The seccomp path gate still returns EACCES; this mask prevents lower
        // content disclosure even for syscalls that do not need mediation.
        for denied in &plan.denied {
            let Some(source) = deny_source(plan, denied) else {
                continue;
            };
            let directory = std::fs::metadata(source)
                .map(|metadata| metadata.is_dir())
                .unwrap_or(true);
            let (mask, cleanup_path) = make_empty_mask(directory)?;
            push_arg(&mut argv, "--ro-bind")?;
            push_arg(&mut argv, proc_fd(mask.as_raw_fd()))?;
            push_arg(&mut argv, denied.as_os_str())?;
            inherited.push(mask);
            cleanup_paths.push(cleanup_path);
        }

        let bootstrap = open_path(&bootstrap_path)?;
        push_arg(&mut argv, "--ro-bind")?;
        push_arg(&mut argv, proc_fd(bootstrap.as_raw_fd()))?;
        push_arg(&mut argv, BOOTSTRAP_DESTINATION)?;
        inherited.push(bootstrap);

        push_arg(&mut argv, "--remount-ro")?;
        push_arg(&mut argv, "/")?;
        let cwd = sandbox
            .cwd
            .as_deref()
            .or(sandbox.workdir_virtual.as_deref())
            .or(sandbox.workdir.as_deref())
            .unwrap_or_else(|| Path::new("/"));
        push_arg(&mut argv, "--chdir")?;
        push_arg(&mut argv, cwd.as_os_str())?;

        if !read_devices.is_empty() {
            // Only the trusted bootstrap receives these user-namespace caps.
            // It preopens byte streams, remounts them readonly/nodev and drops
            // every capability before restoring the workload environment.
            for option in [
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CAP_SYS_ADMIN",
                "--cap-add",
                "CAP_SETPCAP",
            ] {
                push_arg(&mut argv, option)?;
            }
        }
        let workload_environment = child_environment(sandbox)?;
        let filter_fd = make_filter_memfd(filter, &workload_environment, &read_devices)?;
        let (control_parent, control_child) = socket_pair()?;
        push_arg(&mut argv, BOOTSTRAP_DESTINATION)?;
        for (flag, fd) in [
            ("--filter-fd", filter_fd.as_raw_fd()),
            ("--control-fd", control_child.as_raw_fd()),
            ("--ready-fd", pipes.ready_r.as_raw_fd()),
            ("--exec-status-fd", pipes.exec_status_w.as_raw_fd()),
        ] {
            push_arg(&mut argv, flag)?;
            push_arg(&mut argv, fd.to_string())?;
        }
        push_arg(&mut argv, "--foreground")?;
        push_arg(&mut argv, if foreground { "1" } else { "0" })?;
        if sandbox.session_domain_required {
            push_arg(&mut argv, "--session-domain")?;
            push_arg(&mut argv, "1")?;
        }
        for fd in extra_target_fds {
            push_arg(&mut argv, "--keep-fd")?;
            push_arg(&mut argv, fd.to_string())?;
        }
        push_arg(&mut argv, "--")?;
        for value in command {
            push_arg(&mut argv, value)?;
        }
        inherited.push(filter_fd);

        // Everything needed by the fork child is materialized here. The child
        // can be forked from a multithreaded Tokio process, so it must not call
        // the allocator or the process-global environment APIs before exec.
        let argv_pointers = argv
            .iter()
            .map(|argument| argument.as_ptr() as usize)
            .chain(std::iter::once(0))
            .collect();
        // Untrusted loader/environment settings must not run in the mount
        // setup or bootstrap. The sealed payload restores them after setup.
        let environment: Vec<CString> = Vec::new();
        let environment_pointers = environment
            .iter()
            .map(|entry| entry.as_ptr() as usize)
            .chain(std::iter::once(0))
            .collect();
        let mut pass_fds = inherited.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        pass_fds.push(control_child.as_raw_fd());
        pass_fds.push(pipes.ready_r.as_raw_fd());
        pass_fds.push(pipes.exec_status_w.as_raw_fd());
        pass_fds.extend_from_slice(extra_target_fds);

        Ok(Self {
            executable,
            argv,
            argv_pointers,
            environment,
            environment_pointers,
            inherited,
            control_parent: Some(control_parent),
            control_child: Some(control_child),
            pass_fds,
            cleanup_paths,
        })
    }

    pub(crate) fn parent_after_fork(&mut self) {
        self.control_child.take();
        self.inherited.clear();
    }

    pub(crate) fn receive_listener(
        &mut self,
    ) -> io::Result<(OwnedFd, libc::pid_t, bool, Vec<crate::seccomp::read_devices::ReadDevice>)> {
        let socket = self
            .control_parent
            .take()
            .ok_or_else(|| io::Error::other("Bubblewrap listener socket already consumed"))?;
        let mut payload = [0u8; 16];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let max_fd_bytes = (1 + crate::bootstrap::MAX_READ_DEVICES) * std::mem::size_of::<RawFd>();
        let control_len = unsafe { libc::CMSG_SPACE(max_fd_bytes as _) } as usize;
        let mut control = vec![0u8; control_len];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        // The bounded descriptor array fits GNU size_t and musl socklen_t fields.
        message.msg_controllen = control.len() as _;
        let received =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if cmsg.is_null()
            || unsafe {
                (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            }
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Bubblewrap listener frame has no fd",
            ));
        }
        let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
        let fd_bytes = (unsafe { (*cmsg).cmsg_len } as usize).saturating_sub(header_len);
        if fd_bytes == 0 || fd_bytes > max_fd_bytes || fd_bytes % std::mem::size_of::<RawFd>() != 0
        {
            return Err(io::Error::other("invalid bootstrap descriptor array"));
        }
        let mut received_fds = Vec::new();
        for index in 0..fd_bytes / std::mem::size_of::<RawFd>() {
            // SAFETY: the checked ancillary length contains this owned SCM_RIGHTS fd.
            received_fds.push(unsafe {
                OwnedFd::from_raw_fd(*libc::CMSG_DATA(cmsg).cast::<RawFd>().add(index))
            });
        }
        let device_count = u32::from_le_bytes(payload[12..].try_into().unwrap()) as usize;
        if received as usize != payload.len()
            || payload[..4] != LISTENER_MAGIC
            || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || device_count > crate::bootstrap::MAX_READ_DEVICES
            || received_fds.len() != 1 + device_count
        {
            return Err(io::Error::other("invalid Bubblewrap listener frame"));
        }
        let listener_fd = received_fds.remove(0);
        let read_devices = received_fds.into_iter()
            .map(crate::seccomp::read_devices::ReadDevice::new)
            .collect::<io::Result<Vec<_>>>()?;
        let payload_pid = i32::from_le_bytes(payload[4..8].try_into().unwrap());
        if payload_pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Bubblewrap payload pid",
            ));
        }
        let killable_recv = match u32::from_le_bytes(payload[8..12].try_into().unwrap()) {
            0 => false,
            1 => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid notification wait mode",
                ))
            }
        };
        Ok((listener_fd, payload_pid, killable_recv, read_devices))
    }

    pub(crate) fn exec_child(
        mut self,
        sandbox: &Sandbox,
        pipes: &PipePair,
        parent_pid: libc::pid_t,
        foreground: bool,
        session_created: bool,
    ) -> ! {
        self.control_parent.take();
        let fail = |stage: &str| -> ! {
            let error = io::Error::last_os_error();
            crate::context::report_exec_failure(
                pipes.exec_status_w.as_raw_fd(),
                stage,
                error.raw_os_error(),
            );
            eprintln!("sandlock Bubblewrap launcher: {stage}: {error}");
            unsafe { libc::_exit(127) }
        };

        if !session_created && unsafe { libc::setpgid(0, 0) } != 0 {
            fail("setpgid");
        }
        if foreground && unsafe { libc::isatty(0) } == 1 {
            unsafe {
                libc::signal(libc::SIGTTOU, libc::SIG_IGN);
                libc::tcsetpgrp(0, libc::getpgrp());
                libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            }
        }
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
            || unsafe { libc::getppid() } != parent_pid
        {
            fail("Bubblewrap parent death setup");
        }
        if sandbox.no_randomize_memory {
            const ADDR_NO_RANDOMIZE: libc::c_ulong = 0x0040000;
            let current = unsafe { libc::personality(0xffff_ffff) };
            if current == -1
                || unsafe { libc::personality(current as libc::c_ulong | ADDR_NO_RANDOMIZE) } == -1
            {
                fail("personality(ADDR_NO_RANDOMIZE)");
            }
        }
        if let Some(cores) = &sandbox.cpu_cores {
            if !cores.is_empty() {
                let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
                unsafe { libc::CPU_ZERO(&mut set) };
                for core in cores {
                    unsafe { libc::CPU_SET(*core as usize, &mut set) };
                }
                if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) } != 0 {
                    fail("sched_setaffinity");
                }
            }
        }
        if sandbox.no_huge_pages
            && unsafe { libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0) } != 0
        {
            fail("prctl(PR_SET_THP_DISABLE)");
        }
        if sandbox.no_coredump {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
                fail("setrlimit(RLIMIT_CORE)");
            }
        }
        if let Some(max) = sandbox.max_open_files {
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) } != 0 {
                fail("getrlimit(RLIMIT_NOFILE)");
            }
            let target = (max as libc::rlim_t)
                .min(inherited.rlim_cur)
                .min(inherited.rlim_max);
            let limit = libc::rlimit {
                rlim_cur: target,
                rlim_max: target,
            };
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                fail("setrlimit(RLIMIT_NOFILE)");
            }
        }

        for &fd in &self.pass_fds {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
            {
                fail("clear FD_CLOEXEC for Bubblewrap");
            }
        }

        // Keep the owning CString vectors live through execve. Pointer vectors
        // are stored as usize so PreparedBubblewrap remains Send without an
        // unsafe trait implementation; each value points into one of those
        // immutable CString allocations.
        let argv = self.argv_pointers.as_ptr().cast::<*const libc::c_char>();
        let environment = self
            .environment_pointers
            .as_ptr()
            .cast::<*const libc::c_char>();
        std::hint::black_box(&self.argv);
        std::hint::black_box(&self.environment);
        unsafe { libc::execve(self.executable.as_ptr(), argv, environment) };
        fail("exec Bubblewrap")
    }
}

#[cfg(test)]
mod optional_read_tests {
    use super::*;

    #[test]
    fn only_absent_read_policy_sources_are_optional() {
        let tmp = tempfile::tempdir().unwrap();
        let mut entry = FilesystemEntry {
            guest_path: PathBuf::from("/optional/config"),
            host_source: tmp.path().join("missing/config"),
            access: MountAccess::ReadOnly,
            purpose: EntryPurpose::PolicyGrant,
        };
        assert!(open_entry(&entry).unwrap().is_none());
        entry.purpose = EntryPurpose::ExplicitMount;
        assert!(open_entry(&entry).is_err());
        entry.purpose = EntryPurpose::CowLower;
        assert!(open_entry(&entry).is_err());
        entry.purpose = EntryPurpose::PolicyGrant;
        entry.access = MountAccess::ReadWrite;
        assert!(open_entry(&entry).is_err());
        entry.access = MountAccess::ReadOnly;
        std::fs::write(tmp.path().join("regular"), b"policy").unwrap();
        entry.host_source = tmp.path().join("regular/child");
        assert!(open_entry(&entry).is_err());
        entry.host_source = tmp.path().join("regular");
        assert!(open_entry(&entry).unwrap().is_some());
    }
}

impl Drop for PreparedBubblewrap {
    fn drop(&mut self) {
        for path in self.cleanup_paths.drain(..) {
            let _ = if path.is_dir() {
                std::fs::remove_dir(path)
            } else {
                std::fs::remove_file(path)
            };
        }
    }
}
