//! Trusted post-mount bootstrap used by the Bubblewrap filesystem backend.
//!
//! This module is public only so the companion `sandlock-bootstrap` binary can
//! stay tiny. It is not a stable application API.

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;

use crate::sys::structs::SockFilter;

pub(crate) const FILTER_MAGIC: [u8; 8] = *b"SLBP0003";
pub(crate) const LISTENER_MAGIC: [u8; 4] = *b"SLN3";
pub(crate) const MAX_READ_DEVICES: usize = 64;
pub(crate) const MAX_ENVIRONMENT_BYTES: usize = 1024 * 1024;
const MAX_FILTER_INSTRUCTIONS: usize = 4096;
const EXEC_FAILURE_MAGIC: [u8; 4] = *b"SLXF";

#[derive(Debug)]
struct BootstrapArgs {
    filter_fd: RawFd,
    control_fd: RawFd,
    ready_fd: RawFd,
    exec_status_fd: RawFd,
    foreground: bool,
    session_domain: bool,
    keep_fds: Vec<RawFd>,
    command: Vec<OsString>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_fd(value: OsString, flag: &str) -> io::Result<RawFd> {
    value
        .to_str()
        .ok_or_else(|| invalid(format!("{flag} is not UTF-8")))?
        .parse::<RawFd>()
        .map_err(|_| invalid(format!("invalid {flag} value")))
}

fn parse_args() -> io::Result<BootstrapArgs> {
    let mut args = std::env::args_os().skip(1);
    let mut filter_fd = None;
    let mut control_fd = None;
    let mut ready_fd = None;
    let mut exec_status_fd = None;
    let mut foreground = false;
    let mut session_domain = false;
    let mut keep_fds = Vec::new();
    let mut command = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--" {
            command.extend(args);
            break;
        }
        let value = args
            .next()
            .ok_or_else(|| invalid(format!("missing value after {}", arg.to_string_lossy())))?;
        match arg.to_str() {
            Some("--filter-fd") => filter_fd = Some(parse_fd(value, "--filter-fd")?),
            Some("--control-fd") => control_fd = Some(parse_fd(value, "--control-fd")?),
            Some("--ready-fd") => ready_fd = Some(parse_fd(value, "--ready-fd")?),
            Some("--exec-status-fd") => exec_status_fd = Some(parse_fd(value, "--exec-status-fd")?),
            Some("--foreground") => {
                foreground = value == "1";
            }
            Some("--session-domain") => {
                session_domain = match value.to_str() {
                    Some("1") => true,
                    Some("0") => false,
                    _ => return Err(invalid("invalid --session-domain value")),
                };
            }
            Some("--keep-fd") => keep_fds.push(parse_fd(value, "--keep-fd")?),
            _ => {
                return Err(invalid(format!(
                    "unknown bootstrap option {}",
                    arg.to_string_lossy()
                )))
            }
        }
    }
    if command.is_empty() {
        return Err(invalid("bootstrap command is empty"));
    }
    Ok(BootstrapArgs {
        filter_fd: filter_fd.ok_or_else(|| invalid("missing --filter-fd"))?,
        control_fd: control_fd.ok_or_else(|| invalid("missing --control-fd"))?,
        ready_fd: ready_fd.ok_or_else(|| invalid("missing --ready-fd"))?,
        exec_status_fd: exec_status_fd.ok_or_else(|| invalid("missing --exec-status-fd"))?,
        foreground,
        session_domain,
        keep_fds,
        command,
    })
}

fn read_exact_fd(fd: RawFd, mut bytes: &mut [u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let read = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short bootstrap payload",
            ));
        }
        bytes = &mut bytes[read as usize..];
    }
    Ok(())
}

fn write_exact_fd(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_filter(fd: RawFd) -> io::Result<(Vec<SockFilter>, Vec<OsString>, Vec<OsString>)> {
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut header = [0u8; 12];
    read_exact_fd(fd, &mut header)?;
    if header[..8] != FILTER_MAGIC {
        return Err(invalid("invalid bootstrap filter magic"));
    }
    let count = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
    if count == 0 || count > MAX_FILTER_INSTRUCTIONS {
        return Err(invalid("invalid bootstrap filter instruction count"));
    }
    let mut raw = vec![0u8; count * 8];
    read_exact_fd(fd, &mut raw)?;
    let mut filter = Vec::with_capacity(count);
    for instruction in raw.chunks_exact(8) {
        filter.push(SockFilter {
            code: u16::from_le_bytes(instruction[0..2].try_into().unwrap()),
            jt: instruction[2],
            jf: instruction[3],
            k: u32::from_le_bytes(instruction[4..8].try_into().unwrap()),
        });
    }
    let environment = read_strings(fd, 16384, MAX_ENVIRONMENT_BYTES)?;
    let devices = read_strings(fd, MAX_READ_DEVICES, MAX_READ_DEVICES * 4096)?;
    Ok((filter, environment, devices))
}

fn read_strings(fd: RawFd, max_count: usize, max_bytes: usize) -> io::Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStringExt;
    let mut word = [0; 4];
    read_exact_fd(fd, &mut word)?;
    let count = u32::from_le_bytes(word) as usize;
    if count > max_count {
        return Err(invalid("bootstrap string count exceeds limit"));
    }
    let mut total = 0usize;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        read_exact_fd(fd, &mut word)?;
        let length = u32::from_le_bytes(word) as usize;
        total = total
            .checked_add(length)
            .ok_or_else(|| invalid("bootstrap size overflow"))?;
        if total > max_bytes {
            return Err(invalid("bootstrap strings exceed limit"));
        }
        let mut bytes = vec![0; length];
        read_exact_fd(fd, &mut bytes)?;
        if bytes.contains(&0) {
            return Err(invalid("bootstrap string contains NUL"));
        }
        values.push(OsString::from_vec(bytes));
    }
    Ok(values)
}

struct RelayArgs {
    pipe_r: RawFd,
    control_fd: RawFd,
    payload_pid: libc::pid_t,
    read_devices: Vec<RawFd>,
}

extern "C" fn relay_main(raw: *mut libc::c_void) -> libc::c_int {
    let args = unsafe { Box::from_raw(raw.cast::<RelayArgs>()) };
    let mut listener_bytes = [0u8; 8];
    if read_exact_fd(args.pipe_r, &mut listener_bytes).is_err() {
        return 126;
    }
    let listener_fd = i32::from_le_bytes(listener_bytes[..4].try_into().unwrap());
    let mut payload = [0u8; 16];
    payload[..4].copy_from_slice(&LISTENER_MAGIC);
    payload[4..8].copy_from_slice(&(args.payload_pid as i32).to_le_bytes());
    payload[8..12].copy_from_slice(&listener_bytes[4..]);
    payload[12..].copy_from_slice(&(args.read_devices.len() as u32).to_le_bytes());
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut fds = vec![listener_fd];
    fds.extend_from_slice(&args.read_devices);
    let fd_bytes = fds.len() * std::mem::size_of::<RawFd>();
    let control_len = unsafe { libc::CMSG_SPACE(fd_bytes as _) } as usize;
    let mut control = vec![0u8; control_len];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // One fd's ancillary data fits both the GNU size_t and musl socklen_t fields.
    message.msg_controllen = control.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        if cmsg.is_null() {
            return 126;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as _) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(cmsg).cast::<RawFd>(),
            fds.len(),
        );
        message.msg_controllen = (*cmsg).cmsg_len;
        if libc::sendmsg(args.control_fd, &message, 0) < 0 {
            return 126;
        }
    }
    0
}

fn relay_listener(
    control_fd: RawFd,
    filter: &[SockFilter],
    session_domain: bool,
    devices: &[OwnedFd],
) -> io::Result<()> {
    let mut pipe = [0i32; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let pipe_r = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let pipe_w = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let mut stack = vec![0u8; 128 * 1024];
    let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) } as usize & !15usize;
    let relay_args = Box::new(RelayArgs {
        pipe_r: pipe_r.as_raw_fd(),
        control_fd,
        payload_pid: unsafe { libc::getpid() },
        read_devices: devices.iter().map(AsRawFd::as_raw_fd).collect(),
    });
    let relay_args_raw = Box::into_raw(relay_args);
    let relay_pid = unsafe {
        libc::clone(
            relay_main,
            stack_top as *mut libc::c_void,
            libc::CLONE_FILES | libc::SIGCHLD,
            relay_args_raw.cast(),
        )
    };
    if relay_pid < 0 {
        unsafe { drop(Box::from_raw(relay_args_raw)) };
        return Err(io::Error::last_os_error());
    }
    // The relay has a private address space, so the bootstrap owns and frees
    // its copy of this allocation independently.
    unsafe { drop(Box::from_raw(relay_args_raw)) };

    let listener = crate::seccomp::bpf::install_filter_for_domain(filter, session_domain)?;
    let mut listener_bytes = [0u8; 8];
    listener_bytes[..4].copy_from_slice(&listener.fd.as_raw_fd().to_le_bytes());
    listener_bytes[4..].copy_from_slice(&u32::from(listener.killable_recv).to_le_bytes());
    write_exact_fd(pipe_w.as_raw_fd(), &listener_bytes)?;
    let mut status = 0;
    if unsafe { libc::waitpid(relay_pid, &mut status, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::other("listener relay failed"));
    }
    Ok(())
}

fn close_fds_above(min_fd: RawFd, keep: &[RawFd]) {
    let mut kept = keep
        .iter()
        .copied()
        .filter(|fd| *fd > min_fd)
        .collect::<Vec<_>>();
    kept.sort_unstable();
    kept.dedup();
    let mut next = min_fd + 1;
    for fd in kept {
        if fd > next {
            unsafe {
                libc::syscall(
                    libc::SYS_close_range,
                    next as libc::c_uint,
                    (fd - 1) as libc::c_uint,
                    0,
                );
            }
        }
        next = fd + 1;
    }
    unsafe {
        libc::syscall(
            libc::SYS_close_range,
            next as libc::c_uint,
            libc::c_uint::MAX,
            0,
        );
    }
}

fn report_exec_failure(fd: RawFd, stage: &str, error: &io::Error) {
    let stage = stage.as_bytes();
    let stage = &stage[..stage.len().min(512)];
    let mut frame = Vec::with_capacity(10 + stage.len());
    frame.extend_from_slice(&EXEC_FAILURE_MAGIC);
    frame.extend_from_slice(&error.raw_os_error().unwrap_or(0).to_le_bytes());
    frame.extend_from_slice(&(stage.len() as u16).to_le_bytes());
    frame.extend_from_slice(stage);
    let _ = write_exact_fd(fd, &frame);
}

fn run_inner() -> io::Result<()> {
    let args = parse_args()?;
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if args.foreground && unsafe { libc::isatty(0) } == 1 {
        unsafe {
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            if libc::tcsetpgrp(0, libc::getpgrp()) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
        }
    }
    let (filter, environment, device_paths) = read_filter(args.filter_fd)?;
    let devices = crate::bootstrap_devices::prepare(&device_paths)?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    relay_listener(args.control_fd, &filter, args.session_domain, &devices)?;

    let mut ready = [0u8; 4];
    read_exact_fd(args.ready_fd, &mut ready)?;
    drop(devices);

    let flags = unsafe { libc::fcntl(args.exec_status_fd, libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(args.exec_status_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut keep = args.keep_fds.clone();
    keep.push(args.exec_status_fd);
    close_fds_above(2, &keep);

    // This bootstrap is single-threaded again after the listener relay exited.
    // Workload environment (including loader settings) is restored only after
    // device mounts, capability removal, confinement and inherited-fd closure.
    for entry in environment {
        let bytes = entry.as_bytes();
        let equal = bytes
            .iter()
            .position(|b| *b == b'=')
            .ok_or_else(|| invalid("invalid bootstrap environment entry"))?;
        if equal == 0 {
            return Err(invalid("empty bootstrap environment key"));
        }
        let key = std::ffi::OsStr::from_bytes(&bytes[..equal]);
        let value = std::ffi::OsStr::from_bytes(&bytes[equal + 1..]);
        std::env::set_var(key, value);
    }

    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let command = args
        .command
        .iter()
        .map(|value| {
            CString::new(value.as_os_str().as_bytes())
                .map_err(|_| invalid("command contains a NUL byte"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let argv = command
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    unsafe { libc::execvp(command[0].as_ptr(), argv.as_ptr()) };
    Err(io::Error::last_os_error())
}

/// Entry point for the companion bootstrap executable.
#[doc(hidden)]
pub fn main() -> ! {
    let exec_status_fd = std::env::args_os()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|window| window[0] == "--exec-status-fd")
        .and_then(|window| window[1].to_str()?.parse::<RawFd>().ok());
    if let Err(error) = run_inner() {
        if let Some(fd) = exec_status_fd {
            report_exec_failure(fd, "bubblewrap bootstrap", &error);
        }
        eprintln!("sandlock bootstrap: {error}");
        unsafe { libc::_exit(127) }
    }
    unreachable!()
}
