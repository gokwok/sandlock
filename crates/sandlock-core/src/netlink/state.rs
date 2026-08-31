use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

const MAX_SOCKETS: usize = 1024;

/// Live virtual netlink sockets, identified by the kernel's stable SO_COOKIE.
///
/// Descriptor numbers can be reused by close, dup2, close_range and exec. Never
/// intercept close to maintain this registry: a signal can interrupt seccomp
/// notification before Linux closes the descriptor, violating close's normal
/// EINTR semantics and leaking a shell pipeline's write end.
#[derive(Default)]
pub struct NetlinkState {
    cookies: Mutex<HashMap<u64, u32>>,
}

pub struct Registration {
    state: Arc<NetlinkState>,
    cookie: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.state.cookies.lock().unwrap().remove(&self.cookie);
    }
}

impl NetlinkState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register before injection; responder EOF/cancellation releases the entry.
    /// No extra child-side descriptor is retained, so this cannot delay EOF.
    pub fn register(self: &Arc<Self>, fd: RawFd, reply_pid: u32) -> io::Result<Registration> {
        let cookie = socket_cookie(fd)?;
        let mut cookies = self.cookies.lock().unwrap();
        if cookies.len() >= MAX_SOCKETS {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        cookies.insert(cookie, reply_pid);
        Ok(Registration {
            state: Arc::clone(self),
            cookie,
        })
    }

    /// Pin the actual open file description before identifying it. This handles
    /// aliases and inherited descriptors without mistaking a reused slot for a
    /// virtual socket. The result affects only synthesized netlink metadata.
    pub fn cookie_pid(&self, tid: u32, fd: RawFd) -> Option<u32> {
        if self.cookies.lock().unwrap().is_empty() {
            return None;
        }
        let pinned = crate::seccomp::notif::dup_fd_from_pid(tid, fd).ok()?;
        let cookie = socket_cookie(pinned.as_raw_fd()).ok()?;
        self.cookies.lock().unwrap().get(&cookie).copied()
    }
}

fn socket_cookie(fd: RawFd) -> io::Result<u64> {
    let mut cookie = 0u64;
    let mut length = std::mem::size_of_val(&cookie) as libc::socklen_t;
    // SAFETY: both output pointers are aligned, writable, and sized as supplied;
    // fd is held open by the caller for the duration of this kernel query.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            std::ptr::addr_of_mut!(cookie).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&cookie) {
        return Err(io::Error::other("invalid kernel socket cookie size"));
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn socket_registration_is_bounded_and_capacity_is_released() {
        let state = Arc::new(NetlinkState::new());
        let mut sockets = Vec::new();
        let mut registrations = Vec::new();
        for _ in 0..MAX_SOCKETS {
            let (socket, _peer) = UnixStream::pair().unwrap();
            registrations.push(state.register(socket.as_raw_fd(), 123).unwrap());
            sockets.push(socket);
        }
        let (extra, _peer) = UnixStream::pair().unwrap();
        assert_eq!(
            state
                .register(extra.as_raw_fd(), 123)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EMFILE)
        );
        registrations.pop();
        let _registration = state.register(extra.as_raw_fd(), 123).unwrap();
        assert_eq!(
            state.cookie_pid(std::process::id(), extra.as_raw_fd()),
            Some(123)
        );
    }

    #[test]
    fn socket_identity_survives_dup_but_not_fd_reuse_or_responder_exit() {
        let state = Arc::new(NetlinkState::new());
        let (socket, _peer) = UnixStream::pair().unwrap();
        let fd = socket.as_raw_fd();
        let registration = state.register(fd, 123).unwrap();
        let alias = socket.try_clone().unwrap();
        let pid = std::process::id();
        assert_eq!(state.cookie_pid(pid, fd), Some(123));
        assert_eq!(state.cookie_pid(pid, alias.as_raw_fd()), Some(123));
        let (other, _other_peer) = UnixStream::pair().unwrap();
        // SAFETY: both streams stay live; dup2 replaces only socket's owned fd.
        assert_eq!(unsafe { libc::dup2(other.as_raw_fd(), fd) }, fd);
        assert_eq!(state.cookie_pid(pid, fd), None);
        assert_eq!(state.cookie_pid(pid, alias.as_raw_fd()), Some(123));
        drop(registration);
        assert_eq!(state.cookie_pid(pid, alias.as_raw_fd()), None);
    }
}
