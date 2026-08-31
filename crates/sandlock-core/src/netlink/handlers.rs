//! Netlink virtualization handlers — interpose AF_NETLINK sockets as
//! unix socketpairs driven by a synthesized NETLINK_ROUTE responder.
//!
//! Continue safety (issue #27): every Continue here is dispatch routing
//! based on register args (socket domain, fd number) or a fall-through
//! after harmless cosmetic adjustments (recvmsg pre-zeroing). Decisions
//! that require security enforcement (non-NETLINK_ROUTE protocol) return
//! Errno; substitution returns InjectFdSend. The fd-cookie check
//! pins the open file description and checks its kernel SO_COOKIE. Descriptor
//! reuse cannot authorize a network operation: these matches only synthesize
//! metadata, skip a virtual bind, or pre-zero the caller's receive address.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::netlink::{proxy, state::NetlinkState};
use crate::seccomp::notif::{read_child_mem, write_child_mem, NotifAction};
use crate::sys::structs::SeccompNotif;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const NETLINK_ROUTE: u64 = 0;

/// Socket families allowed to reach the kernel. Everything else returns
/// EAFNOSUPPORT — the same errno the kernel itself uses for unknown
/// families, so callers see a normal "not supported" error rather than a
/// sandbox-flavored one.
///
/// The set is intentionally tiny: an XOA agent has no legitimate need for
/// AF_ALG, AF_PACKET, AF_VSOCK, AF_XDP, AF_TIPC, AF_RDS, AF_BLUETOOTH, and
/// the rest of the niche families that have historically yielded LPEs
/// (Copy Fail / CVE-2026-31431 via AF_ALG, Dirty Pipe-adjacent splice
/// primitives, AF_PACKET PACKET_MMAP UAFs, etc.). Closing the surface
/// once is cheaper than chasing one CVE per family.
fn family_allowed(domain: u64) -> bool {
    matches!(domain, AF_UNIX | AF_INET | AF_INET6 | AF_NETLINK)
}

/// Resolve `notif.pid` (which is a TID per the kernel's `task_pid_vnr`) to
/// the enclosing thread group id, used as the socket creator's virtual port id.
/// Socket identity itself is independent of process and descriptor numbers.
fn tgid_of(tid: i32) -> i32 {
    let path = format!("/proc/{}/status", tid);
    if let Ok(s) = std::fs::read_to_string(&path) {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Tgid:") {
                if let Ok(v) = rest.trim().parse::<i32>() {
                    return v;
                }
            }
        }
    }
    // Fallback: if we can't read status, treat the tid as the tgid.
    tid
}

/// Read a POD struct `T` from child memory via `process_vm_readv`, with the
/// shared `notif::read_child_mem` helper that ID-validates the notification
/// before and after the read.
fn read_struct<T: Copy>(
    notif_fd: RawFd,
    id: u64,
    pid: u32,
    addr: usize,
) -> Option<T> {
    let bytes = read_child_mem(notif_fd, id, pid, addr as u64, std::mem::size_of::<T>()).ok()?;
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

/// Intercept `socket(AF_NETLINK, *, NETLINK_ROUTE)` and substitute one end
/// of a `socketpair(AF_UNIX, SOCK_SEQPACKET)`. A tokio task takes the
/// supervisor-side end and speaks synthesized NETLINK_ROUTE replies.
/// Allowed domains pass through; AF_NETLINK is virtualized; everything
/// else (and non-NETLINK_ROUTE netlink protocols) returns EAFNOSUPPORT.
pub async fn handle_socket(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let domain   = notif.data.args[0];
    let protocol = notif.data.args[2];

    if !family_allowed(domain) {
        return NotifAction::Errno(libc::EAFNOSUPPORT);
    }
    if domain != AF_NETLINK {
        return NotifAction::Continue;
    }
    if protocol != NETLINK_ROUTE {
        return NotifAction::Errno(libc::EAFNOSUPPORT);
    }

    let mut fds = [0i32; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return NotifAction::Errno(libc::ENOMEM);
    }
    // fds[0] → supervisor side (responder owns)
    // fds[1] → child side (injected)
    //
    // The supervisor end is driven by a tokio task via AsyncFd, so it
    // must be non-blocking. The child end stays blocking (glibc's
    // netlink code expects blocking semantics).
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return NotifAction::Errno(libc::ENOMEM);
    }
    let responder_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // Preserve the creator's virtual port id across dup/fork, matching the
    // responder's nlmsg_pid and the value returned by getsockname.
    let tgid = tgid_of(notif.pid as i32);
    let registration = match state.register(child_fd.as_raw_fd(), tgid as u32) {
        Ok(registration) => registration,
        Err(error) => return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EIO)),
    };
    proxy::spawn_responder(responder_fd, tgid as u32, registration);

    // Registration precedes injection; failed injection closes child_fd and
    // responder EOF releases it. No close syscall interception is necessary.
    NotifAction::InjectFdSend {
        srcfd: child_fd,
        newfd_flags: libc::O_CLOEXEC as u32,
    }
}

/// Zero out the `msg_name` region of a recvmsg/recvfrom before the kernel
/// runs the syscall, so that the source address glibc sees has
/// `nl_pid == 0` (the kernel only writes `sun_family` = AF_UNIX = 2 bytes
/// into a unix-socketpair recvmsg's source address; bytes 2..end remain as
/// whatever we pre-filled).
///
/// glibc's netlink receive loop rejects messages where
/// `source_addr.nl_pid != 0` with a silent `continue`, interpreting them as
/// coming from a non-kernel peer.  Without this zeroing the `nl_pid` bits
/// are uninitialized stack and the check is flaky.
pub async fn handle_netlink_recvmsg(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    if state.cookie_pid(notif.pid, fd).is_none() {
        return NotifAction::Continue;
    }

    let nr = notif.data.nr as i64;
    let sockaddr_nl_len: usize = 12;
    let zeros = [0u8; 12];
    let pid = notif.pid;
    let id = notif.id;

    if nr == libc::SYS_recvmsg {
        // args: (fd, msghdr*, flags)
        let msghdr_ptr = notif.data.args[1] as usize;
        if let Some(hdr) = read_struct::<libc::msghdr>(notif_fd, id, pid, msghdr_ptr) {
            if !hdr.msg_name.is_null() && (hdr.msg_namelen as usize) >= sockaddr_nl_len {
                let _ = write_child_mem(notif_fd, id, pid, hdr.msg_name as u64, &zeros);
            }
        }
    } else if nr == libc::SYS_recvfrom {
        // args: (fd, buf, len, flags, src_addr*, addrlen_ptr)
        let src_addr = notif.data.args[4] as u64;
        let addrlen_ptr = notif.data.args[5] as u64;
        if src_addr != 0 && addrlen_ptr != 0 {
            if let Ok(b) = read_child_mem(notif_fd, id, pid, addrlen_ptr, 4) {
                let cap = u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize;
                if cap >= sockaddr_nl_len {
                    let _ = write_child_mem(notif_fd, id, pid, src_addr, &zeros);
                }
            }
        }
    }

    NotifAction::Continue
}

pub async fn handle_bind(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    if state.cookie_pid(notif.pid, fd).is_some() {
        return NotifAction::ReturnValue(0);
    }
    NotifAction::Continue
}

pub async fn handle_getsockname(
    notif: &SeccompNotif,
    state: &Arc<NetlinkState>,
    notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let Some(reply_pid) = state.cookie_pid(notif.pid, fd) else {
        return NotifAction::Continue;
    };

    // struct sockaddr_nl { u16 nl_family; u16 _pad; u32 nl_pid; u32 nl_groups; }
    //
    // The creator's virtual port id is stable across threads and inherited or
    // duplicated descriptors, and matches nlmsg_pid in the responder's replies.
    let mut addr = [0u8; 12];
    let nl_family = libc::AF_NETLINK as u16;
    addr[0..2].copy_from_slice(&nl_family.to_ne_bytes());
    addr[4..8].copy_from_slice(&reply_pid.to_ne_bytes());

    let addr_ptr = notif.data.args[1] as u64;
    let addrlen_ptr = notif.data.args[2] as u64;
    let pid = notif.pid;
    let id = notif.id;

    let cur = match read_child_mem(notif_fd, id, pid, addrlen_ptr, 4) {
        Ok(b) => u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize,
        Err(_) => return NotifAction::Errno(libc::EFAULT),
    };
    let to_write = cur.min(addr.len());
    if write_child_mem(notif_fd, id, pid, addr_ptr, &addr[..to_write]).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }
    let actual = (addr.len() as u32).to_ne_bytes();
    let _ = write_child_mem(notif_fd, id, pid, addrlen_ptr, &actual);
    NotifAction::ReturnValue(0)
}
