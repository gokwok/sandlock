//! Trusted setup of read-only byte-stream devices inside the new mount namespace.

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

/// Only these stateless Linux byte streams support duplicated open descriptions.
/// Other read-only device kinds remain unavailable rather than acquiring writes.
pub(crate) fn supported(metadata: &std::fs::Metadata) -> bool {
    metadata.mode() & libc::S_IFMT == libc::S_IFCHR
        && libc::major(metadata.rdev()) == 1
        && matches!(libc::minor(metadata.rdev()), 3 | 5 | 8 | 9)
}

pub(crate) fn prepare(paths: &[OsString]) -> io::Result<Vec<OwnedFd>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut devices = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = std::fs::metadata(path)?;
        if !supported(&metadata) {
            return Err(io::Error::other("unsupported read-only device kind"));
        }
        let path = CString::new(path.as_bytes())?;
        // SAFETY: trusted, pinned device binds exist before any workload code.
        // The fd is opened on the guest mount before that very mount becomes
        // readonly/nodev. Existing reads still work; fd metadata writes and
        // reopening the device (including through /proc/fd) remain kernel-denied.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let device = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe {
            libc::mount(
                std::ptr::null(),
                path.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        validate(&device)?;
        devices.push(device);
    }
    drop_capabilities()?;
    Ok(devices)
}

pub(crate) fn validate(device: &OwnedFd) -> io::Result<()> {
    let copy = device.try_clone()?;
    if !supported(&std::fs::File::from(copy).metadata()?) {
        return Err(io::Error::other("invalid read-only device descriptor"));
    }
    // SAFETY: the owned fd and initialized output remain live for these calls.
    let mut info: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(device.as_raw_fd(), &mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = unsafe { libc::fcntl(device.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || info.f_flag & (libc::ST_RDONLY | libc::ST_NODEV) != (libc::ST_RDONLY | libc::ST_NODEV)
    {
        return Err(io::Error::other("device descriptor is not read-only"));
    }
    Ok(())
}

fn drop_capabilities() -> io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // SAFETY: this single-threaded trusted bootstrap alone holds temporary
    // capabilities in the newly created user namespace. Drop the entire
    // bounding set before clearing effective/permitted/inheritable sets.
    unsafe {
        for capability in 0..64 {
            if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL)
            {
                return Err(io::Error::last_os_error());
            }
        }
        let header = Header {
            version: 0x20080522,
            pid: 0,
        };
        let data = [Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
