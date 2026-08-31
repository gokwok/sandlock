//! Read access to preopened, kernel-readonly/nodev byte-stream mounts.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::notif::{decode_open_args, read_child_cstr, NotifAction};
use super::state::{file_id_of_fd, PolicyFnState};
use crate::sys::structs::SeccompNotif;

pub(crate) struct ReadDevice {
    file: std::fs::File,
    device: u64,
    inode: u64,
}

impl ReadDevice {
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        crate::bootstrap_devices::validate(&fd)?;
        let file = std::fs::File::from(fd);
        let metadata = file.metadata()?;
        Ok(Self {
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

pub(crate) fn open(
    notif: &SeccompNotif,
    listener: i32,
    devices: &[ReadDevice],
    pfs: &PolicyFnState,
) -> Option<NotifAction> {
    let nr = notif.data.nr as i64;
    if devices.is_empty()
        || (nr != libc::SYS_openat
            && nr != crate::arch::SYS_OPENAT2
            && Some(nr) != crate::arch::sys_open())
    {
        return None;
    }
    let args = decode_open_args(notif, listener).ok()?;
    // O_PATH remains a real kernel path handle. Unusual openat2 resolution
    // modes fall through to the restrictive namespace, never to a host open.
    if args.flags & libc::O_PATH as u64 != 0 || args.resolve != 0 {
        return None;
    }
    let path = read_child_cstr(listener, notif.id, notif.pid, args.path_ptr, 4096)?;
    let path = if Path::new(&path).is_absolute() {
        PathBuf::from(path)
    } else {
        let base = if args.dirfd as i32 == libc::AT_FDCWD {
            format!("/proc/{}/cwd", notif.pid)
        } else {
            format!("/proc/{}/fd/{}", notif.pid, args.dirfd as i32)
        };
        std::fs::read_link(base).ok()?.join(path)
    };
    // This side-effect-free probe follows the guest root and pins the actual
    // inode, including aliases. A concurrent path change cannot redirect the
    // injected result. A non-match may Continue because nodev prevents a race
    // from turning the kernel's later lookup into a device open.
    let root = PathBuf::from(format!("/proc/{}/root", notif.pid));
    let flags = libc::O_PATH | libc::O_CLOEXEC | (args.flags as i32 & libc::O_NOFOLLOW);
    let raw = crate::sys::fs::openat2_in_root(&root, path.to_str()?, flags, 0).ok()?;
    use std::os::fd::FromRawFd;
    // SAFETY: successful openat2 transferred this descriptor to us.
    let probe = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    let metadata = probe.metadata().ok()?;
    let source = devices
        .iter()
        .find(|device| device.device == metadata.dev() && device.inode == metadata.ino())?;
    let resolved = std::fs::read_link(format!("/proc/self/fd/{}", probe.as_raw_fd())).ok()?;
    if pfs.is_path_denied(&path.to_string_lossy())
        || pfs.is_path_denied(&resolved.to_string_lossy())
        || file_id_of_fd(probe.as_raw_fd()).is_some_and(|id| pfs.is_id_denied(&id))
    {
        return Some(NotifAction::Errno(libc::EACCES));
    }
    if args.flags & (libc::O_CREAT | libc::O_EXCL) as u64 == (libc::O_CREAT | libc::O_EXCL) as u64 {
        return Some(NotifAction::Errno(libc::EEXIST));
    }
    if args.flags & libc::O_DIRECTORY as u64 != 0 {
        return Some(NotifAction::Errno(libc::ENOTDIR));
    }
    if args.flags & libc::O_ACCMODE as u64 != libc::O_RDONLY as u64
        || args.flags & libc::O_TRUNC as u64 != 0
    {
        return Some(NotifAction::Errno(libc::EACCES));
    }
    Some(match source.file.try_clone() {
        Ok(file) => NotifAction::InjectFdSend {
            srcfd: file.into(),
            newfd_flags: (args.flags & libc::O_CLOEXEC as u64) as u32,
        },
        Err(error) => NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EIO)),
    })
}
