//! Seccomp notification handlers for COW filesystem interception.
//!
//! Reads paths from child memory, delegates to SeccompCowBranch,
//! and injects results (fds, stat structs, readlink strings, dirents) back.
//!
//! # Continue safety (issue #27)
//!
//! Every `Continue` in this module is a *fall-through* — the COW layer
//! decided the syscall is outside its scope, so it lets the kernel handle
//! the original syscall normally. No COW path was modified or rewritten
//! when we return Continue, so the kernel's re-read sees exactly what the
//! child originally passed. The fall-through happens when:
//!
//!   * No COW branch is active (`cow_state.branch == None`).
//!   * The path doesn't match the COW prefix (`!cow.matches(path)`).
//!   * `read_path` / `read_child_mem` / `CString::new` failed.
//!   * The supervisor's own open/copy attempt failed and we want the
//!     kernel to surface its own error.
//!
//! Because Continue means "we didn't intervene," the seccomp_unotify
//! TOCTOU concern doesn't apply: we're not making a security decision
//! whose validity depends on the kernel re-reading the same memory we
//! read. Path-based security enforcement for these fall-throughs is
//! provided by Landlock (or by the chroot dispatcher, when chroot mode
//! is active and runs before COW).

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;

use crate::arch;
use crate::cow::result::link_result;
use crate::cow::seccomp::SeccompCowBranch;
use crate::procfs::{build_dirent64, DT_DIR, DT_LNK, DT_REG};
use crate::seccomp::notif::{read_child_mem, write_child_mem, write_child_mem_force, NotifAction};
use crate::seccomp::state::{CowState, PerProcessState, ProcessIndex};
use crate::sys::structs::SeccompNotif;

/// Acquire the per-process state handle for `notif.pid`. Returns
/// None if the pid isn't tracked (pidfd_open failed at fork on an
/// old kernel, or the process is gone) — callers should fall back
/// to `NotifAction::Continue`.
fn pp_handle(
    processes: &Arc<ProcessIndex>,
    pid: u32,
) -> Option<Arc<AsyncMutex<PerProcessState>>> {
    processes
        .entry_for(i32::try_from(pid).ok()?)
        .map(|(_, s)| s)
}

/// Read the current virtual cwd for `pid` (None if the process
/// hasn't chdir'd into a COW-only directory, or isn't tracked).
async fn current_virtual_cwd(
    processes: &Arc<ProcessIndex>,
    pid: u32,
) -> Option<String> {
    let handle = pp_handle(processes, pid)?;
    let cwd = handle.lock().await.virtual_cwd.clone();
    cwd
}

/// Read a NUL-terminated path from child memory (up to 4096 bytes for filesystem paths).
///
/// Reads page-by-page to avoid crossing into unmapped memory (e.g. when the path
/// pointer is near a page boundary on the stack).
fn read_path(notif: &SeccompNotif, addr: u64, notif_fd: RawFd) -> Option<String> {
    if addr == 0 {
        return None;
    }
    const PAGE_SIZE: u64 = 4096;
    let mut result = Vec::with_capacity(256);
    let mut cur = addr;
    while result.len() < 4096 {
        let page_remaining = PAGE_SIZE - (cur % PAGE_SIZE);
        let to_read = page_remaining.min((4096 - result.len()) as u64) as usize;
        let bytes = read_child_mem(notif_fd, notif.id, notif.pid, cur, to_read).ok()?;
        if let Some(nul) = bytes.iter().position(|&b| b == 0) {
            result.extend_from_slice(&bytes[..nul]);
            return String::from_utf8(result).ok();
        }
        result.extend_from_slice(&bytes);
        cur += to_read as u64;
    }
    String::from_utf8(result).ok()
}

/// Resolve a path that may be relative to a dirfd.
/// For AT_FDCWD (-100), returns the path as-is (assumed absolute or cwd-relative).
/// For other dirfds, reads /proc/{pid}/fd/{dirfd} to get the base path.
fn normalize_path(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

fn resolve_at_path_with_virtual(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    virtual_cwd: Option<&str>,
) -> String {
    if Path::new(path).is_absolute() {
        if let Some(resolved) = resolve_tracee_magic_fd_path(notif, path) {
            return resolved;
        }
        return normalize_path(PathBuf::from(path)).to_string_lossy().into_owned();
    }
    // dirfd is stored as u64 in seccomp_data.args but AT_FDCWD is a negative i32.
    // Truncate to i32 for correct sign comparison.
    let dirfd32 = dirfd as i32;
    if dirfd32 == libc::AT_FDCWD {
        if let Some(cwd) = virtual_cwd {
            return normalize_path(Path::new(cwd).join(path))
                .to_string_lossy()
                .into_owned();
        }
        // Relative to cwd — read /proc/{pid}/cwd
        if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            return normalize_path(cwd.join(path)).to_string_lossy().into_owned();
        }
        return path.to_string();
    }
    // Relative to dirfd
    if let Ok(base) = std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd)) {
        normalize_path(base.join(path)).to_string_lossy().into_owned()
    } else {
        path.to_string()
    }
}

/// Resolve procfs/devfs aliases for a tracee file descriptor in the tracee's
/// namespace. Reading `/proc/self` from the supervisor would otherwise resolve
/// its own descriptors and let aliases such as `/dev/fd/N` bypass COW policy.
fn resolve_tracee_magic_fd_path(notif: &SeccompNotif, path: &str) -> Option<String> {
    let (fd, tail) = if let Some(rest) = path.strip_prefix("/dev/fd/") {
        let (fd, tail) = rest.split_once('/').unwrap_or((rest, ""));
        (fd.parse::<i32>().ok()?, tail)
    } else if path == "/dev/stdin" || path == "/dev/stdout" || path == "/dev/stderr" {
        let fd = match path {
            "/dev/stdin" => 0,
            "/dev/stdout" => 1,
            _ => 2,
        };
        (fd, "")
    } else if let Some(rest) = path
        .strip_prefix("/proc/self/fd/")
        .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))
    {
        let (fd, tail) = rest.split_once('/').unwrap_or((rest, ""));
        (fd.parse::<i32>().ok()?, tail)
    } else {
        let components: Vec<_> = path.trim_start_matches('/').split('/').collect();
        let fd_index = components.iter().position(|component| *component == "fd")?;
        if components.first().copied() != Some("proc") || fd_index + 1 >= components.len() {
            return None;
        }
        let _fd = components[fd_index + 1].parse::<i32>().ok()?;
        let link_path = format!("/{}", components[..=fd_index + 1].join("/"));
        let base = std::fs::read_link(link_path).ok()?;
        let tail = components[fd_index + 2..].join("/");
        return Some(normalize_path(base.join(tail)).to_string_lossy().into_owned());
    };
    let base = std::fs::read_link(format!("/proc/{}/fd/{fd}", notif.pid)).ok()?;
    Some(normalize_path(base.join(tail)).to_string_lossy().into_owned())
}

fn is_magic_fd_path(path: &str) -> bool {
    path.starts_with("/dev/fd/")
        || matches!(path, "/dev/stdin" | "/dev/stdout" | "/dev/stderr")
        || (path.starts_with("/proc/")
            && path
                .trim_start_matches('/')
                .split('/')
                .any(|component| component == "fd"))
}

fn dirfd_base_path(
    notif: &SeccompNotif,
    dirfd: i64,
    virtual_cwd: Option<&str>,
) -> Option<PathBuf> {
    if dirfd as i32 == libc::AT_FDCWD {
        virtual_cwd
            .map(PathBuf::from)
            .or_else(|| std::fs::read_link(format!("/proc/{}/cwd", notif.pid)).ok())
    } else {
        std::fs::read_link(format!("/proc/{}/fd/{}", notif.pid, dirfd as i32)).ok()
    }
}

fn pin_resolution_base(pid: u32, dirfd: i64) -> Result<OwnedFd, i32> {
    if dirfd as i32 != libc::AT_FDCWD {
        return crate::seccomp::notif::dup_fd_from_pid(pid, dirfd as i32)
            .map_err(|error| error.raw_os_error().unwrap_or(libc::EBADF));
    }
    let path = std::ffi::CString::new(format!("/proc/{pid}/cwd")).map_err(|_| libc::EINVAL)?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF),
        );
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Enforce execute/search permission on the exact directory inode selected by
/// a relative *at syscall. Looking up `/proc/<pid>/fd/N` as a pathname alone
/// is insufficient after that logical name has been copied up or chmod'd.
async fn check_relative_resolution_base(
    notif: &SeccompNotif,
    dirfd: i64,
    raw_path: &str,
    cow_state: &Arc<Mutex<CowState>>,
) -> Result<(), i32> {
    if Path::new(raw_path).is_absolute() {
        return Ok(());
    }
    if cow_state.lock().await.branch.is_none() {
        return Ok(());
    }
    let pinned = pin_resolution_base(notif.pid, dirfd)?;
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(pinned.as_raw_fd(), &mut metadata) } < 0 {
        return Err(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF),
        );
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(libc::ENOTDIR);
    }
    let real_path = std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| libc::EBADF)?;
    let state = cow_state.lock().await;
    let Some(cow) = state.branch.as_ref() else {
        return Ok(());
    };
    if !cow.contains_layer_path(&real_path) {
        return Ok(());
    }
    let mode = cow
        .logical_directory_mode_for_handle(&real_path)
        .unwrap_or(metadata.st_mode & 0o7777);
    if mode & 0o100 == 0 {
        Err(libc::EACCES)
    } else {
        Ok(())
    }
}

/// Resolve the lexical part of an openat2 pathname relative to the caller's
/// selected dirfd root. BENEATH rejects an attempted `..` escape; IN_ROOT
/// clamps it and also treats an absolute pathname as relative to that dirfd.
fn resolve_openat2_lexical_path(
    notif: &SeccompNotif,
    dirfd: i64,
    path: &str,
    virtual_cwd: Option<&str>,
    resolve: u64,
) -> Result<(String, Option<PathBuf>), i32> {
    const RESOLVE_BENEATH: u64 = 0x08;
    const RESOLVE_IN_ROOT: u64 = 0x10;
    let beneath = resolve & RESOLVE_BENEATH != 0;
    let in_root = resolve & RESOLVE_IN_ROOT != 0;
    if beneath && in_root {
        return Err(libc::EINVAL);
    }
    if !beneath && !in_root {
        return Ok((
            resolve_at_path_with_virtual(notif, dirfd, path, virtual_cwd),
            None,
        ));
    }
    if beneath && Path::new(path).is_absolute() {
        return Err(libc::EXDEV);
    }
    let base = dirfd_base_path(notif, dirfd, virtual_cwd).ok_or(libc::EBADF)?;
    let mut joined = base.clone();
    let mut relative_depth = 0usize;
    for component in Path::new(path).components() {
        match component {
            Component::Prefix(_) => return Err(libc::EINVAL),
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                joined.push(part);
                relative_depth += 1;
            }
            Component::ParentDir if relative_depth > 0 => {
                joined.pop();
                relative_depth -= 1;
            }
            Component::ParentDir if beneath => return Err(libc::EXDEV),
            Component::ParentDir => {
                // RESOLVE_IN_ROOT gives `..` at the selected root the same
                // semantics as `..` at `/`: it remains at the root.
            }
        }
    }
    Ok((normalize_path(joined).to_string_lossy().into_owned(), Some(base)))
}

pub(crate) fn map_cow_upper_path(cow: &SeccompCowBranch, path: &str) -> String {
    let path = PathBuf::from(path);
    if let Ok(rel) = path.strip_prefix(cow.upper_dir()) {
        return normalize_path(cow.workdir().join(rel)).to_string_lossy().into_owned();
    }
    normalize_path(path).to_string_lossy().into_owned()
}

// ============================================================
// openat handler
// ============================================================

/// Open `real_path` confined to its layer root, so a symlink or `..` in the
/// child-controlled path cannot escape the upper/lower tree (issue #112).
/// Picks the anchor root by prefix, then defers all resolution to the kernel
/// via `openat2(RESOLVE_IN_ROOT)`.
/// Select the layer root (`upper` first, then `workdir`) that `real_path` lives
/// under and return it with the relative remainder. `Err(EACCES)` if the path
/// is under neither root. This only selects the anchor; the kernel re-resolves
/// the relative path under it with `RESOLVE_IN_ROOT`, so the lexical
/// `strip_prefix` grants no trust.
fn pick_root_rel<'a>(
    upper_root: &'a Path,
    workdir_root: &'a Path,
    real_path: &Path,
) -> Result<(&'a Path, String), i32> {
    let (root, rel) = if let Ok(rel) = real_path.strip_prefix(upper_root) {
        (upper_root, rel)
    } else if let Ok(rel) = real_path.strip_prefix(workdir_root) {
        (workdir_root, rel)
    } else {
        return Err(libc::EACCES);
    };
    Ok((root, rel.to_str().ok_or(libc::EINVAL)?.to_string()))
}

fn open_confined(
    upper_root: &Path,
    workdir_root: &Path,
    real_path: &Path,
    flags: i32,
    mode: u32,
    resolve: u64,
) -> Result<RawFd, i32> {
    let (root, rel) = pick_root_rel(upper_root, workdir_root, real_path)?;
    crate::sys::fs::openat2_in_root_with_resolve(root, &rel, flags, mode, resolve)
}

/// Handle openat under workdir: redirect to COW upper/lower.
/// openat(dirfd, pathname, flags, mode): args[0]=dirfd, args[1]=path, args[2]=flags
pub(crate) async fn handle_cow_open(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    use crate::cow::seccomp::CowOpenPlan;

    let nr = notif.data.nr as i64;

    // open(path, flags, mode):         args[0]=path, args[1]=flags, args[2]=mode
    // openat(dirfd, path, flags, mode): args[0]=dirfd, args[1]=path, args[2]=flags, args[3]=mode
    let (path_ptr, dirfd, flags, mode, resolve) = if Some(nr) == arch::sys_open() {
        (
            notif.data.args[0],
            libc::AT_FDCWD as i64,
            notif.data.args[1],
            notif.data.args[2],
            0,
        )
    } else if nr == arch::SYS_OPENAT2 {
        let size = usize::try_from(notif.data.args[3]).unwrap_or(0);
        if size < 24 {
            return NotifAction::Errno(libc::EINVAL);
        }
        if size > 4096 {
            return NotifAction::Errno(libc::E2BIG);
        }
        let how = match read_child_mem(
            notif_fd,
            notif.id,
            notif.pid,
            notif.data.args[2],
            size,
        ) {
            Ok(how) => how,
            Err(_) => return NotifAction::Continue,
        };
        let mut flags = [0u8; 8];
        let mut mode = [0u8; 8];
        let mut resolve = [0u8; 8];
        flags.copy_from_slice(&how[..8]);
        mode.copy_from_slice(&how[8..16]);
        resolve.copy_from_slice(&how[16..24]);
        if how[24..].iter().any(|byte| *byte != 0) {
            return NotifAction::Errno(libc::E2BIG);
        }
        (
            notif.data.args[1],
            notif.data.args[0] as i64,
            u64::from_ne_bytes(flags),
            u64::from_ne_bytes(mode),
            u64::from_ne_bytes(resolve),
        )
    } else {
        (
            notif.data.args[1],
            notif.data.args[0] as i64,
            notif.data.args[2],
            notif.data.args[3],
            0,
        )
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    if let Err(errno) = check_relative_resolution_base(notif, dirfd, &rel_path, cow_state).await {
        return NotifAction::Errno(errno);
    }
    let virtual_cwd = if (dirfd as i32) == libc::AT_FDCWD && !Path::new(&rel_path).is_absolute() {
        current_virtual_cwd(processes, notif.pid).await
    } else {
        None
    };
    let (mut path, resolve_base) = match resolve_openat2_lexical_path(
        notif,
        dirfd,
        &rel_path,
        virtual_cwd.as_deref(),
        resolve,
    ) {
        Ok(value) => value,
        Err(errno) => return NotifAction::Errno(errno),
    };

    // Phase 1: determine plan under lock (no heavy I/O)
    let (plan, upper_root, workdir_root, bounded_revalidation) = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();

        path = map_cow_upper_path(cow, &path);
        let resolve_base = resolve_base
            .as_ref()
            .map(|base| map_cow_upper_path(cow, base.to_string_lossy().as_ref()));
        let bounded_input_path = path.clone();
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const KNOWN_RESOLVE_FLAGS: u64 = 0x3f;
        if resolve & !KNOWN_RESOLVE_FLAGS != 0 {
            return NotifAction::Errno(libc::EINVAL);
        }
        if resolve & RESOLVE_NO_SYMLINKS != 0
            && cow.merged_path_uses_symlink(&path, flags & libc::O_NOFOLLOW as u64 == 0)
        {
            return NotifAction::Errno(libc::ELOOP);
        }
        const RESOLVE_BENEATH: u64 = 0x08;
        if resolve & RESOLVE_BENEATH != 0
            && cow.merged_path_uses_absolute_symlink(
                &path,
                flags & libc::O_NOFOLLOW as u64 == 0,
            )
        {
            return NotifAction::Errno(libc::EXDEV);
        }
        if let Some(base) = resolve_base.as_ref() {
            let resolved = match cow.resolve_merged_path_bounded(
                &path,
                base,
                flags & libc::O_NOFOLLOW as u64 == 0,
                resolve & 0x10 != 0,
                resolve & 0x08 != 0,
            ) {
                Ok(path) => path,
                Err(errno) if flags & libc::O_CREAT as u64 != 0 && errno == libc::ENOENT => {
                    path.clone()
                }
                Err(errno) => return NotifAction::Errno(errno),
            };
            path = resolved;
        }
        let bounded_revalidation = resolve_base
            .map(|base| (bounded_input_path, base, path.clone()));
        let logical_directory = if flags & libc::O_NOFOLLOW as u64 == 0 {
            cow.logical_directory_mode_follow(&path)
        } else {
            cow.logical_directory_mode(&path)
        };
        let leaf_bits = if logical_directory.is_some() {
            if flags & libc::O_PATH as u64 != 0 {
                0
            } else {
                let mut bits = 0o100;
                if flags & libc::O_ACCMODE as u64 != libc::O_WRONLY as u64 {
                    bits |= 0o400;
                }
                bits
            }
        } else {
            0
        };
        if let Err(errno) = cow.check_logical_path_access(&path, leaf_bits) {
            return NotifAction::Errno(errno);
        }
        if flags & libc::O_CREAT as u64 != 0 {
            if let Err(errno) = cow.check_merged_parent_path(&path) {
                return NotifAction::Errno(errno);
            }
        }

        // Read-only opens don't need interception unless the file was
        // modified or deleted in the COW layer.
        const WRITE_FLAGS: u64 = (libc::O_WRONLY
            | libc::O_RDWR
            | libc::O_CREAT
            | libc::O_TRUNC
            | libc::O_APPEND) as u64;
        let is_write = flags & WRITE_FLAGS != 0;
        if !is_write && !cow.needs_read_intercept(&path) {
            return NotifAction::Continue;
        }

        let plan = match cow.prepare_open(&path, flags) {
            Ok(plan) => plan,
            Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
            Err(crate::error::BranchError::Exists) => return NotifAction::Errno(libc::EEXIST),
            Err(crate::error::BranchError::Deleted) => return NotifAction::Errno(libc::ENOENT),
            Err(_) => return NotifAction::Errno(libc::EIO),
        };
        (plan, upper_root, workdir_root, bounded_revalidation)
    };
    // Lock is released here

    // Phase 2: execute I/O plan without holding the lock
    let (real_path, create_candidate) = match plan {
        CowOpenPlan::Skip => return NotifAction::Continue,
        // Deleted in this branch (whiteout): the lower file still exists, so
        // Continue would read its pre-delete content. Return ENOENT, matching
        // the stat/access handlers.
        CowOpenPlan::Deleted => return NotifAction::Errno(libc::ENOENT),
        CowOpenPlan::Resolved(path) => (path, false),
        CowOpenPlan::UpperReady {
            upper,
            create_candidate,
        } => (upper, create_candidate),
        CowOpenPlan::NeedsCopy { upper, lower: _lower, file_size, rel_path } => {
            // Do the potentially-expensive copy on a blocking thread
            let root = workdir_root.clone();
            let uroot = upper_root.clone();
            let rel = rel_path.clone();
            let copy_result = tokio::task::spawn_blocking(move || {
                crate::cow::seccomp::SeccompCowBranch::execute_copy(&root, &uroot, &rel)
            }).await;

            match copy_result {
                Ok(Ok(())) => (upper, false),
                Ok(Err(_)) | Err(_) => {
                    // Copy failed after this path was classified as COW.
                    // Falling through would operate on the lower file.
                    let mut st = cow_state.lock().await;
                    if let Some(cow) = st.branch.as_mut() {
                        cow.rollback_copy(file_size);
                    }
                    return NotifAction::Errno(libc::EIO);
                }
            }
        }
    };

    // Phase 3: open the resolved path and inject fd.
    // Honor the child's requested creation mode (masked to permission bits).
    // Hardcoding 0o666 dropped the execute bits, so a binary copied into the
    // workdir (e.g. `cp /bin/echo m`) landed in upper non-executable and
    // `./m` failed with EACCES. The kernel ignores mode unless O_CREAT is set.
    let create_mode = if flags & libc::O_CREAT as u64 != 0 {
        let umask = tracee_umask(notif.pid).unwrap_or(0o777);
        ((mode as u32 & 0o7777) & !(umask & 0o777)) as libc::c_uint
    } else {
        (mode & 0o7777) as libc::c_uint
    };
    // Keep the namespace plan and the kernel open in one COW mutation epoch.
    // Every tracee rename/symlink replacement is mediated through this same
    // mutex, so BENEATH/IN_ROOT cannot be invalidated between validation and
    // the actual confined open.
    let open_guard = cow_state.lock().await;
    if let Some((input_path, base, expected_path)) = bounded_revalidation.as_ref() {
        let Some(cow) = open_guard.branch.as_ref() else {
            return NotifAction::Errno(libc::EIO);
        };
        let revalidated = match cow.resolve_merged_path_bounded(
            input_path,
            base,
            flags & libc::O_NOFOLLOW as u64 == 0,
            resolve & 0x10 != 0,
            resolve & 0x08 != 0,
        ) {
            Ok(path) => path,
            Err(errno) if flags & libc::O_CREAT as u64 != 0 && errno == libc::ENOENT => {
                input_path.clone()
            }
            Err(errno) => return NotifAction::Errno(errno),
        };
        if &revalidated != expected_path {
            return NotifAction::Errno(libc::EAGAIN);
        }
    }
    let ordinary_flags = (flags & !(libc::O_EXCL as u64)) as i32;
    let (fd, created_by_open) = if create_candidate && flags & libc::O_CREAT as u64 != 0 {
        // The metadata plan cannot decide creation: another stopped tracee
        // can race after the branch lock is released. O_EXCL is the actual
        // linearization point, including for a caller that did not request it.
        let exclusive_flags = ordinary_flags | libc::O_CREAT | libc::O_EXCL;
        match open_confined(
            &upper_root,
            &workdir_root,
            &real_path,
            exclusive_flags,
            create_mode,
            resolve,
        ) {
            Ok(fd) => (fd, true),
            Err(libc::EEXIST) if flags & libc::O_EXCL as u64 == 0 => {
                match open_confined(
                    &upper_root,
                    &workdir_root,
                    &real_path,
                    ordinary_flags,
                    create_mode,
                    resolve,
                ) {
                    Ok(fd) => (fd, false),
                    Err(errno) => return NotifAction::Errno(errno),
                }
            }
            Err(errno) => return NotifAction::Errno(errno),
        }
    } else {
        match open_confined(
            &upper_root,
            &workdir_root,
            &real_path,
            ordinary_flags,
            create_mode,
            resolve,
        ) {
            Ok(fd) => (fd, false),
            // This is a resolved COW path. Continue would retry the original
            // pathname against the lower layer and can expose old content.
            Err(errno) => return NotifAction::Errno(errno),
        }
    };
    if created_by_open && unsafe { libc::fchmod(fd, create_mode as libc::mode_t) } < 0 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        unsafe { libc::close(fd) };
        if let Ok((root, rel)) = pick_root_rel(&upper_root, &workdir_root, &real_path) {
            let _ = crate::sys::fs::unlinkat_in_root(root, &rel, false);
        }
        return NotifAction::Errno(errno);
    }

    // Preserve O_CLOEXEC from the original openat flags.
    let newfd_flags = if flags & libc::O_CLOEXEC as u64 != 0 {
        libc::O_CLOEXEC as u32
    } else {
        0
    };
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    NotifAction::InjectFdSend { srcfd: owned, newfd_flags }
}

// ============================================================
// Write operation handlers
// ============================================================

/// Parsed COW write operation with resolved paths and extracted arguments.
enum CowWriteOp {
    Unlink { path: String, is_dir: bool },
    Mkdir { path: String, mode: u32 },
    Mknod { path: String, mode: u32, dev: u64 },
    Rename { old_path: String, new_path: String, flags: u32 },
    Symlink { target: String, linkpath: String },
    Link { old_path: String, new_path: String, follow_old: bool },
    Chmod { path: String, mode: u32, follow_final: bool },
    Chown { path: String, uid: u32, gid: u32, follow_final: bool },
    Truncate { path: String, length: i64 },
}

pub(crate) fn tracee_umask(tid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))?
        .trim();
    u32::from_str_radix(value, 8).ok().filter(|mask| *mask <= 0o777)
}

impl CowWriteOp {
    fn remap_upper_paths(&mut self, cow: &SeccompCowBranch) {
        match self {
            CowWriteOp::Unlink { path, .. }
            | CowWriteOp::Mkdir { path, .. }
            | CowWriteOp::Mknod { path, .. }
            | CowWriteOp::Chmod { path, .. }
            | CowWriteOp::Chown { path, .. }
            | CowWriteOp::Truncate { path, .. } => {
                *path = map_cow_upper_path(cow, path);
            }
            CowWriteOp::Rename { old_path, new_path, .. }
            | CowWriteOp::Link { old_path, new_path, .. } => {
                *old_path = map_cow_upper_path(cow, old_path);
                *new_path = map_cow_upper_path(cow, new_path);
            }
            CowWriteOp::Symlink { linkpath, .. } => {
                *linkpath = map_cow_upper_path(cow, linkpath);
            }
        }
    }

    fn paths(&self) -> Vec<&str> {
        match self {
            CowWriteOp::Unlink { path, .. }
            | CowWriteOp::Mkdir { path, .. }
            | CowWriteOp::Mknod { path, .. }
            | CowWriteOp::Chmod { path, .. }
            | CowWriteOp::Chown { path, .. }
            | CowWriteOp::Truncate { path, .. } => vec![path],
            CowWriteOp::Rename { old_path, new_path, .. }
            | CowWriteOp::Link { old_path, new_path, .. } => vec![old_path, new_path],
            CowWriteOp::Symlink { linkpath, .. } => vec![linkpath],
        }
    }

    /// Apply each syscall's final-component following rules while always
    /// following symlinked parents. This must happen before copy-up/whiteout
    /// bookkeeping so the live merged view and a later checkpoint name the
    /// same logical entries.
    fn resolve_merged_paths(&mut self, cow: &SeccompCowBranch) -> Result<(), i32> {
        let resolve = |path: &str, follow_final: bool| {
            cow.resolve_merged_path(path, follow_final)
        };
        match self {
            CowWriteOp::Unlink { path, .. }
            | CowWriteOp::Mkdir { path, .. }
            | CowWriteOp::Mknod { path, .. } => {
                *path = resolve(path, false)?;
            }
            CowWriteOp::Rename { old_path, new_path, .. } => {
                *old_path = resolve(old_path, false)?;
                *new_path = resolve(new_path, false)?;
            }
            CowWriteOp::Symlink { linkpath, .. } => {
                *linkpath = resolve(linkpath, false)?;
            }
            CowWriteOp::Link { old_path, new_path, follow_old } => {
                *old_path = resolve(old_path, *follow_old)?;
                *new_path = resolve(new_path, false)?;
            }
            CowWriteOp::Truncate { path, .. } => {
                *path = resolve(path, true)?;
            }
            CowWriteOp::Chmod { path, follow_final, .. } => {
                *path = resolve(path, *follow_final)?;
            }
            CowWriteOp::Chown { path, follow_final, .. } => {
                *path = resolve(path, *follow_final)?;
            }
        }
        Ok(())
    }
}

/// Read and resolve a path argument. For *at syscalls, pass the dirfd arg index;
/// for legacy syscalls, pass None to use the raw path.
fn read_resolved(
    notif: &SeccompNotif,
    path_arg: usize,
    dirfd_arg: Option<usize>,
    notif_fd: RawFd,
    virtual_cwd: Option<&str>,
) -> Option<String> {
    let raw = read_path(notif, notif.data.args[path_arg], notif_fd)?;
    match dirfd_arg {
        Some(i) => Some(resolve_at_path_with_virtual(
            notif,
            notif.data.args[i] as i64,
            &raw,
            virtual_cwd,
        )),
        None => Some(resolve_at_path_with_virtual(
            notif,
            libc::AT_FDCWD as i64,
            &raw,
            virtual_cwd,
        )),
    }
}

/// Parse the syscall into a CowWriteOp, reading and resolving paths from child memory.
fn parse_cow_write(
    notif: &SeccompNotif,
    notif_fd: RawFd,
    virtual_cwd: Option<&str>,
) -> Option<CowWriteOp> {
    let nr = notif.data.nr as i64;

    // *at variants (dirfd in args[0], path in args[1])
    if nr == libc::SYS_unlinkat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let is_dir = (notif.data.args[2] & libc::AT_REMOVEDIR as u64) != 0;
        return Some(CowWriteOp::Unlink { path, is_dir });
    }
    if nr == libc::SYS_mkdirat {
        return Some(CowWriteOp::Mkdir {
            path: read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?,
            mode: notif.data.args[2] as u32,
        });
    }
    if nr == libc::SYS_mknodat {
        // mknodat(dirfd, pathname, mode, dev)
        return Some(CowWriteOp::Mknod {
            path: read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?,
            mode: notif.data.args[2] as u32,
            dev:  notif.data.args[3],
        });
    }
    if nr == libc::SYS_renameat2 {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path, flags: notif.data.args[4] as u32 });
    }
    if arch::sys_renameat() == Some(nr) {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path, flags: 0 });
    }
    if nr == libc::SYS_symlinkat {
        // symlinkat(target, newdirfd, linkpath): target is raw, linkpath is resolved
        let target = read_path(notif, notif.data.args[0], notif_fd)?;
        let linkpath = read_resolved(notif, 2, Some(1), notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Symlink { target, linkpath });
    }
    if nr == libc::SYS_linkat {
        let old_path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 3, Some(2), notif_fd, virtual_cwd)?;
        let follow_old = notif.data.args[4] & libc::AT_SYMLINK_FOLLOW as u64 != 0;
        return Some(CowWriteOp::Link { old_path, new_path, follow_old });
    }
    if nr == libc::SYS_fchmodat || nr == arch::SYS_FCHMODAT2 {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let follow_final = nr != arch::SYS_FCHMODAT2
            || notif.data.args[3] & libc::AT_SYMLINK_NOFOLLOW as u64 == 0;
        return Some(CowWriteOp::Chmod {
            path,
            mode: (notif.data.args[2] & 0o7777) as u32,
            follow_final,
        });
    }
    if nr == libc::SYS_fchownat {
        let path = read_resolved(notif, 1, Some(0), notif_fd, virtual_cwd)?;
        let follow_final = notif.data.args[4] & libc::AT_SYMLINK_NOFOLLOW as u64 == 0;
        return Some(CowWriteOp::Chown { path, uid: notif.data.args[2] as u32, gid: notif.data.args[3] as u32, follow_final });
    }

    // Legacy variants (path in args[0], no dirfd)
    if Some(nr) == arch::sys_unlink() {
        return Some(CowWriteOp::Unlink {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            is_dir: false,
        });
    }
    if Some(nr) == arch::sys_rmdir() {
        return Some(CowWriteOp::Unlink {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            is_dir: true,
        });
    }
    if Some(nr) == arch::sys_mkdir() {
        return Some(CowWriteOp::Mkdir {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            mode: notif.data.args[1] as u32,
        });
    }
    if Some(nr) == arch::sys_mknod() {
        // mknod(pathname, mode, dev)
        return Some(CowWriteOp::Mknod {
            path: read_resolved(notif, 0, None, notif_fd, virtual_cwd)?,
            mode: notif.data.args[1] as u32,
            dev:  notif.data.args[2],
        });
    }
    if Some(nr) == arch::sys_rename() {
        let old_path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Rename { old_path, new_path, flags: 0 });
    }
    if Some(nr) == arch::sys_symlink() {
        let target = read_path(notif, notif.data.args[0], notif_fd)?;
        let linkpath = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Symlink { target, linkpath });
    }
    if Some(nr) == arch::sys_link() {
        let old_path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        let new_path = read_resolved(notif, 1, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Link { old_path, new_path, follow_old: false });
    }
    if Some(nr) == arch::sys_chmod() {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chmod {
            path,
            mode: (notif.data.args[1] & 0o7777) as u32,
            follow_final: true,
        });
    }
    if Some(nr) == arch::sys_chown() || Some(nr) == arch::sys_lchown() {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Chown { path, uid: notif.data.args[1] as u32, gid: notif.data.args[2] as u32, follow_final: Some(nr) == arch::sys_chown() });
    }

    // truncate (legacy only, path in args[0])
    if nr == libc::SYS_truncate {
        let path = read_resolved(notif, 0, None, notif_fd, virtual_cwd)?;
        return Some(CowWriteOp::Truncate { path, length: notif.data.args[1] as i64 });
    }

    None
}

/// Map a BranchError result to a NotifAction.
fn cow_result(r: Result<bool, crate::error::BranchError>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        Err(crate::error::BranchError::QuotaExceeded) => NotifAction::Errno(libc::ENOSPC),
        Err(crate::error::BranchError::Denied) => NotifAction::Errno(libc::EPERM),
        // Whiteouted source: Continue would let the kernel act on the lower
        // entry, which still exists with its pre-delete content.
        Err(crate::error::BranchError::Deleted) => NotifAction::Errno(libc::ENOENT),
        Err(crate::error::BranchError::Exists) | Ok(false) => NotifAction::Errno(libc::EEXIST),
        // This path is already known to be inside a COW lower. Never continue
        // a failed virtualized mutation into the immutable lower.
        Err(_) => NotifAction::Errno(libc::EIO),
    }
}

/// Map an errno-style handler result (unlink, rename) to a NotifAction.
fn unlink_result(r: Result<bool, i32>) -> NotifAction {
    match r {
        Ok(true) => NotifAction::ReturnValue(0),
        Err(errno) => NotifAction::Errno(errno),
        // Callers only invoke this after the path matched the COW root. A
        // staging failure must never fall through to the immutable lower.
        Ok(false) => NotifAction::Errno(libc::EIO),
    }
}

/// Determine which relative path (if any) needs a COW copy for this operation.
/// Returns `(match_path, copy_rel)` where match_path is checked against
/// `cow.matches()` and copy_rel is the relative path to pre-copy.
fn cow_copy_rel<'a>(
    op: &'a CowWriteOp,
    cow: &crate::cow::seccomp::SeccompCowBranch,
) -> Option<(&'a str, String)> {
    let (match_path, copy_path) = match op {
        // These ops call ensure_cow_copy internally — pre-copy the target
        CowWriteOp::Chmod { ref path, .. }
        | CowWriteOp::Chown { ref path, .. }
        | CowWriteOp::Truncate { ref path, .. } => (path.as_str(), path.as_str()),
        CowWriteOp::Rename { ref old_path, .. } => (old_path.as_str(), old_path.as_str()),
        CowWriteOp::Link { ref old_path, ref new_path, .. } => (new_path.as_str(), old_path.as_str()),
        // These ops don't need a pre-copy
        _ => return None,
    };
    if !cow.matches(match_path) {
        return None;
    }
    cow.safe_rel(copy_path)
        .map(|rel| (match_path, rel))
}

/// Execute a deferred `CowCopyPlan::NeedsCopy` on a blocking thread.
/// Returns the upper path on success, or rolls back quota on failure.
async fn execute_deferred_copy(
    cow_state: &Arc<Mutex<CowState>>,
    workdir_root: std::path::PathBuf,
    upper_root: std::path::PathBuf,
    rel: String,
    upper: std::path::PathBuf,
    file_size: u64,
) -> Option<std::path::PathBuf> {
    let copy_result = tokio::task::spawn_blocking(move || {
        crate::cow::seccomp::SeccompCowBranch::execute_copy(&workdir_root, &upper_root, &rel)
    }).await;
    match copy_result {
        Ok(Ok(())) => Some(upper),
        _ => {
            let mut st = cow_state.lock().await;
            if let Some(cow) = st.branch.as_mut() {
                cow.rollback_copy(file_size);
            }
            None
        }
    }
}

fn cow_write_resolution_bases(
    notif: &SeccompNotif,
    notif_fd: RawFd,
) -> Option<Vec<(i64, String)>> {
    let nr = notif.data.nr as i64;
    let at = |dirfd_arg: usize, path_arg: usize| {
        Some((
            notif.data.args[dirfd_arg] as i64,
            read_path(notif, notif.data.args[path_arg], notif_fd)?,
        ))
    };
    let cwd = |path_arg: usize| {
        Some((
            libc::AT_FDCWD as i64,
            read_path(notif, notif.data.args[path_arg], notif_fd)?,
        ))
    };
    if matches!(
        nr,
        libc::SYS_unlinkat
            | libc::SYS_mkdirat
            | libc::SYS_mknodat
            | libc::SYS_fchmodat
            | arch::SYS_FCHMODAT2
            | libc::SYS_fchownat
    ) {
        return Some(vec![at(0, 1)?]);
    }
    if nr == libc::SYS_renameat2 || arch::sys_renameat() == Some(nr) || nr == libc::SYS_linkat {
        return Some(vec![at(0, 1)?, at(2, 3)?]);
    }
    if nr == libc::SYS_symlinkat {
        return Some(vec![at(1, 2)?]);
    }
    if Some(nr) == arch::sys_rename() || Some(nr) == arch::sys_link() {
        return Some(vec![cwd(0)?, cwd(1)?]);
    }
    if Some(nr) == arch::sys_symlink() {
        return Some(vec![cwd(1)?]);
    }
    if Some(nr) == arch::sys_unlink()
        || Some(nr) == arch::sys_rmdir()
        || Some(nr) == arch::sys_mkdir()
        || Some(nr) == arch::sys_mknod()
        || Some(nr) == arch::sys_chmod()
        || Some(nr) == arch::sys_chown()
        || Some(nr) == arch::sys_lchown()
        || nr == libc::SYS_truncate
    {
        return Some(vec![cwd(0)?]);
    }
    Some(Vec::new())
}

/// Handle all write-type syscalls: both *at variants (unlinkat, mkdirat, etc.)
/// and legacy variants (unlink, rmdir, mkdir, etc.).
///
/// For operations that modify existing files (chmod, chown, rename, link,
/// truncate), the handler uses a two-phase pattern: prepare the copy plan
/// under the lock, execute the potentially expensive file copy outside the
/// lock, then re-acquire the lock and run the actual operation (which finds
/// the file already in upper).
pub(crate) async fn handle_cow_write(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    if notif.data.nr as i64 == arch::SYS_FCHMODAT2 {
        let flags = notif.data.args[3] as i32;
        let supported = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH;
        if flags & !supported != 0 {
            return NotifAction::Errno(libc::EINVAL);
        }
        let path = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(path) => path,
            None => return NotifAction::Errno(libc::EFAULT),
        };
        if path.is_empty() {
            if flags & libc::AT_EMPTY_PATH == 0 {
                return NotifAction::Errno(libc::ENOENT);
            }
            // An fd-only metadata operation cannot be redirected to the upper
            // inode without changing the syscall's descriptor semantics.
            // Deny it for snapshot branches rather than permit an immutable
            // lower mutation (or a concurrent fd-slot substitution).
            let pinned = match crate::seccomp::notif::dup_fd_from_pid(
                notif.pid,
                notif.data.args[0] as i32,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF))
                }
            };
            let real_path = match std::fs::read_link(format!(
                "/proc/self/fd/{}",
                pinned.as_raw_fd()
            )) {
                Ok(path) => path,
                Err(_) => return NotifAction::Errno(libc::EBADF),
            };
            let state = cow_state.lock().await;
            return if state.branch.as_ref().is_some_and(|cow| {
                cow.is_snapshot_backed() && real_path.starts_with(cow.workdir())
            }) {
                NotifAction::Errno(libc::EPERM)
            } else {
                NotifAction::Continue
            };
        }
    }
    let resolution_bases = match cow_write_resolution_bases(notif, notif_fd) {
        Some(bases) => bases,
        None => return NotifAction::Continue,
    };
    for (dirfd, path) in resolution_bases {
        if is_magic_fd_path(&path) {
            let state = cow_state.lock().await;
            if state.branch.as_ref().is_some_and(|cow| cow.is_snapshot_backed()) {
                return NotifAction::Errno(libc::EPERM);
            }
        }
        if let Err(errno) = check_relative_resolution_base(notif, dirfd, &path, cow_state).await {
            return NotifAction::Errno(errno);
        }
    }
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let mut op = match parse_cow_write(notif, notif_fd, virtual_cwd.as_deref()) {
        Some(op) => op,
        None => return NotifAction::Continue,
    };
    if let CowWriteOp::Mkdir { mode, .. } = &mut op {
        // The supervisor creates the upper entry, so the kernel cannot apply
        // the tracee's umask for us. `/proc/<tid>/status` exposes the umask of
        // the stopped task's shared fs context. If procfs is unavailable,
        // fail closed on permission bits instead of accidentally widening a
        // private directory.
        let umask = tracee_umask(notif.pid).unwrap_or(0o777);
        *mode = (*mode & 0o7777) & !(umask & 0o777);
    }

    // Phase 1: check if we need to pre-copy a file (under lock, no heavy I/O).
    // Capture both layer roots here so Phase 2 needs no second lock.
    let (copy_plan, copy_workdir, copy_upper, copy_rel) = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };

        op.remap_upper_paths(cow);
        if let Err(errno) = op.resolve_merged_paths(cow) {
            return NotifAction::Errno(errno);
        }
        let creation_target = match &op {
            CowWriteOp::Mkdir { path, .. }
            | CowWriteOp::Mknod { path, .. }
            | CowWriteOp::Symlink { linkpath: path, .. }
            | CowWriteOp::Link { new_path: path, .. } => Some(path.as_str()),
            _ => None,
        };
        if creation_target.is_some_and(|path| cow.merged_entry_exists_path(path)) {
            return NotifAction::Errno(libc::EEXIST);
        }
        if let Some(path) = creation_target {
            if let Err(errno) = cow.check_merged_parent_path(path) {
                return NotifAction::Errno(errno);
            }
        }
        if let CowWriteOp::Chmod { path, follow_final: false, .. } = &op {
            if cow.merged_entry_is_symlink_path(path) {
                return NotifAction::Errno(libc::EOPNOTSUPP);
            }
        }
        for path in op.paths() {
            if cow.matches(path) {
                if let Err(errno) = cow.check_logical_path_access(path, 0) {
                    return NotifAction::Errno(errno);
                }
            }
        }
        match cow_copy_rel(&op, cow) {
            Some((_match_path, ref rel)) => {
                let workdir = cow.workdir().to_path_buf();
                let upper = cow.upper_dir().to_path_buf();
                match cow.prepare_copy(rel) {
                    Ok(plan) => (Some(plan), workdir, upper, rel.clone()),
                    Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
                    Err(_) => return NotifAction::Errno(libc::EIO),
                }
            }
            None => (None, std::path::PathBuf::new(), std::path::PathBuf::new(), String::new()),
        }
    };
    // Lock is released here

    // Phase 2: execute the file copy outside the lock (if needed)
    if let Some(crate::cow::seccomp::CowCopyPlan::NeedsCopy { upper, lower: _lower, file_size }) = copy_plan {
        if execute_deferred_copy(cow_state, copy_workdir, copy_upper, copy_rel, upper, file_size).await.is_none() {
            return NotifAction::Errno(libc::EIO);
        }
    }

    // Phase 3: execute the operation under lock (ensure_cow_copy is now a no-op
    // for the pre-copied file since it's already in upper)
    let mut st = cow_state.lock().await;
    let cow = match st.branch.as_mut() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };
    let creation_target = match &op {
        CowWriteOp::Mkdir { path, .. }
        | CowWriteOp::Mknod { path, .. }
        | CowWriteOp::Symlink { linkpath: path, .. }
        | CowWriteOp::Link { new_path: path, .. } => Some(path.as_str()),
        _ => None,
    };
    if let Some(path) = creation_target {
        if let Err(errno) = cow.check_merged_parent_path(path) {
            return NotifAction::Errno(errno);
        }
    }

    match op {
        CowWriteOp::Unlink { ref path, is_dir } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            unlink_result(cow.handle_unlink(path, is_dir))
        }
        CowWriteOp::Mkdir { ref path, mode } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_mkdir(path, mode))
        }
        CowWriteOp::Mknod { ref path, mode, dev } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_mknod(path, mode, dev))
        }
        CowWriteOp::Rename { ref old_path, ref new_path, flags } => {
            if !cow.matches(old_path) { return NotifAction::Continue; }
            unlink_result(cow.handle_rename_with_flags(old_path, new_path, flags))
        }
        CowWriteOp::Symlink { ref target, ref linkpath } => {
            if !cow.matches(linkpath) { return NotifAction::Continue; }
            cow_result(cow.handle_symlink(target, linkpath))
        }
        CowWriteOp::Link { ref old_path, ref new_path, .. } => {
            // A hard link cannot be half staged. With one name inside the
            // branch and the other below it there is nothing to stage: linking
            // in would create the name in the workdir the branch promised to
            // leave untouched, and linking out would hand the child an alias
            // for the lower inode that survives an abort. EXDEV is what the
            // kernel says about a link that cannot span the two sides.
            if cow.matches(old_path) != cow.matches(new_path) {
                return NotifAction::Errno(libc::EXDEV);
            }
            if !cow.matches(new_path) { return NotifAction::Continue; }
            link_result(cow.handle_link(old_path, new_path))
        }
        CowWriteOp::Chmod { ref path, mode, .. } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_chmod(path, mode))
        }
        CowWriteOp::Chown { ref path, uid, gid, .. } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_chown(path, uid, gid))
        }
        CowWriteOp::Truncate { ref path, length } => {
            if !cow.matches(path) { return NotifAction::Continue; }
            cow_result(cow.handle_truncate(path, length))
        }
    }
}

// ============================================================
// access() handler — fake W_OK for COW-managed paths
// ============================================================

/// Handle faccessat/faccessat2/access — return success for W_OK checks on
/// COW-managed paths so programs that pre-check write permissions (like dpkg)
/// don't fail before the COW layer can redirect their writes.
pub(crate) async fn handle_cow_access(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;

    // access(pathname, mode): args[0]=path, args[1]=mode
    // faccessat(dirfd, pathname, mode, flags): args[0]=dirfd, args[1]=path, args[2]=mode
    let (path, mode) = if Some(nr) == arch::sys_access() {
        let dirfd = libc::AT_FDCWD as i64;
        let p = match read_path(notif, notif.data.args[0], notif_fd) {
            Some(p) => {
                if let Err(errno) = check_relative_resolution_base(notif, dirfd, &p, cow_state).await {
                    return NotifAction::Errno(errno);
                }
                resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref())
            }
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[1] as i32)
    } else {
        let dirfd = notif.data.args[0] as i64;
        let p = match read_path(notif, notif.data.args[1], notif_fd) {
            Some(p) => {
                if let Err(errno) = check_relative_resolution_base(notif, dirfd, &p, cow_state).await {
                    return NotifAction::Errno(errno);
                }
                resolve_at_path_with_virtual(notif, dirfd, &p, virtual_cwd.as_deref())
            }
            None => return NotifAction::Continue,
        };
        (p, notif.data.args[2] as i32)
    };

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }
    let mut leaf_bits = 0;
    let follows_final_symlink = nr != crate::arch::SYS_FACCESSAT2
        || notif.data.args[3] as i32 & libc::AT_SYMLINK_NOFOLLOW == 0;
    let logical_directory = if follows_final_symlink {
        cow.logical_directory_mode_follow(&path)
    } else {
        cow.logical_directory_mode(&path)
    };
    if logical_directory.is_some() {
        if mode & libc::R_OK != 0 {
            leaf_bits |= 0o400;
        }
        if mode & libc::X_OK != 0 {
            leaf_bits |= 0o100;
        }
    }
    if let Err(errno) = cow.check_logical_path_access(&path, leaf_bits) {
        return NotifAction::Errno(errno);
    }

    if mode & libc::W_OK == 0 {
        return NotifAction::Continue;
    }

    // Path is under workdir and W_OK was requested — writes will be
    // redirected to the COW upper layer, so report success.
    // Check the path actually exists on the real filesystem.
    if std::path::Path::new(&path).exists() || cow.handle_stat(&path).is_some() {
        return NotifAction::ReturnValue(0);
    }

    NotifAction::Continue
}

// ============================================================
// utimensat handler
// ============================================================

/// fd-only metadata operations cannot be redirected to a copied-up inode:
/// the child's fd would still name the immutable lower object. Permit upper
/// handles, but fail closed for snapshot lower handles.
pub(crate) async fn handle_cow_fd_metadata(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    _processes: &Arc<ProcessIndex>,
    _notif_fd: RawFd,
) -> NotifAction {
    let pinned = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, notif.data.args[0] as i32) {
        Ok(fd) => fd,
        Err(error) => return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let real_path = match std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd())) {
        Ok(path) => path,
        Err(_) => return NotifAction::Errno(libc::EBADF),
    };
    let state = cow_state.lock().await;
    let Some(cow) = state.branch.as_ref() else {
        return NotifAction::Continue;
    };
    if real_path.starts_with(cow.workdir()) && cow.is_snapshot_backed() {
        NotifAction::Errno(libc::EPERM)
    } else {
        NotifAction::Continue
    }
}

/// Handle utimensat — resolve path to COW upper then set timestamps.
/// utimensat(dirfd, pathname, times, flags)
pub(crate) async fn handle_cow_utimensat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let dirfd = notif.data.args[0] as i64;
    let path_ptr = notif.data.args[1];
    let times_ptr = notif.data.args[2];
    let flags = notif.data.args[3] as i32;

    if path_ptr == 0 {
        let pinned = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, dirfd as i32) {
            Ok(fd) => fd,
            Err(error) => return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF)),
        };
        let real_path = match std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd())) {
            Ok(path) => path,
            Err(_) => return NotifAction::Errno(libc::EBADF),
        };
        let state = cow_state.lock().await;
        let Some(cow) = state.branch.as_ref() else {
            return NotifAction::Continue;
        };
        return if real_path.starts_with(cow.workdir()) && cow.is_snapshot_backed() {
            NotifAction::Errno(libc::EPERM)
        } else {
            NotifAction::Continue
        };
    }

    let raw_path = match read_path(notif, path_ptr, notif_fd) {
        Some(path) => path,
        None => return NotifAction::Continue,
    };
    if let Err(errno) = check_relative_resolution_base(notif, dirfd, &raw_path, cow_state).await {
        return NotifAction::Errno(errno);
    }
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = resolve_at_path_with_virtual(notif, dirfd, &raw_path, virtual_cwd.as_deref());

    let (upper_path, upper_root, workdir_root) = {
        let mut st = cow_state.lock().await;
        let cow = match st.branch.as_mut() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &path);
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }
        let path = match cow.resolve_merged_path(
            &path,
            (flags & libc::AT_SYMLINK_NOFOLLOW) == 0,
        ) {
            Ok(path) => path,
            Err(errno) => return NotifAction::Errno(errno),
        };
        if let Err(errno) = cow.check_logical_path_access(&path, 0) {
            return NotifAction::Errno(errno);
        }
        let p = match cow.handle_utimensat(&path) {
            Ok(Some(p)) => p,
            Ok(None) => return NotifAction::Errno(libc::EIO),
            Err(crate::error::BranchError::QuotaExceeded) => return NotifAction::Errno(libc::ENOSPC),
            Err(_) => return NotifAction::Errno(libc::EIO),
        };
        (p, upper_root, workdir_root)
    };

    // Read times from child memory (2 x struct timespec = 32 bytes on x86_64)
    let times = if times_ptr != 0 {
        match read_child_mem(notif_fd, notif.id, notif.pid, times_ptr, 32) {
            Ok(data) => {
                let mut ts: [libc::timespec; 2] = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), &mut ts as *mut _ as *mut u8, 32);
                }
                Some(ts)
            }
            Err(_) => return NotifAction::Errno(libc::EFAULT),
        }
    } else {
        None
    };

    let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &upper_path) {
        Ok(v) => v,
        Err(e) => return NotifAction::Errno(e),
    };
    let times_raw = times.as_ref().map(|t| t.as_ptr()).unwrap_or(std::ptr::null());
    let follow = (flags & libc::AT_SYMLINK_NOFOLLOW) == 0;
    if let Err(e) = crate::sys::fs::utimensat_in_root(root, &rel, times_raw, follow) {
        return NotifAction::Errno(e);
    }
    NotifAction::ReturnValue(0)
}

// ============================================================
// Read operation handlers (stat, readlink, getdents)
// ============================================================

async fn handle_cow_fd_stat_into(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    fd: i32,
    statbuf_addr: u64,
    notif_fd: RawFd,
) -> NotifAction {
    let pinned = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, fd) {
        Ok(fd) => fd,
        Err(error) => return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF)),
    };
    handle_cow_pinned_stat_into(notif, cow_state, pinned, statbuf_addr, notif_fd).await
}

async fn handle_cow_pinned_stat_into(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    pinned: OwnedFd,
    statbuf_addr: u64,
    notif_fd: RawFd,
) -> NotifAction {
    let real_path = match std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd())) {
        Ok(path) => path,
        Err(_) => return NotifAction::Errno(libc::EBADF),
    };
    let logical_mode = {
        let state = cow_state.lock().await;
        let cow = match state.branch.as_ref() {
            Some(cow) => cow,
            None => return NotifAction::Continue,
        };
        if !cow.contains_layer_path(&real_path) {
            return NotifAction::Continue;
        }
        cow.logical_directory_mode_for_handle(&real_path)
    };
    let mut statbuf = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(pinned.as_raw_fd(), &mut statbuf) } < 0 {
        return NotifAction::Errno(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        );
    }
    if let Some(mode) = logical_mode {
        statbuf.st_mode =
            (statbuf.st_mode & !(0o7777 as libc::mode_t)) | mode as libc::mode_t;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &statbuf as *const libc::stat as *const u8,
            std::mem::size_of::<libc::stat>(),
        )
    };
    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, bytes).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

/// Handle newfstatat / faccessat — resolve path then Continue to let kernel stat.
/// The trick: we rewrite the path pointer in child memory to point to the resolved path.
/// Actually, simpler: for stat, we do the stat ourselves and write the result.
pub(crate) async fn handle_cow_stat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;

    // newfstatat(dirfd, pathname, statbuf, flags)
    // faccessat(dirfd, pathname, mode, flags)
    // stat/lstat(pathname, statbuf), access(pathname, mode)
    //
    // The legacy x86_64 variants carry the path in args[0] and have no
    // dirfd or flags. Parsing them with the at-variant layout reads the
    // statbuf pointer as the path, never matches the workdir, and falls
    // through to the kernel, which leaks whiteouted lower entries to any
    // static-libc child that emits legacy stat (same register-layout bug
    // handle_cow_open fixed for legacy open).
    let legacy = [arch::sys_stat(), arch::sys_lstat(), arch::sys_access()]
        .into_iter()
        .flatten()
        .any(|l| l == nr);
    let (dirfd, path_ptr) = if legacy {
        (libc::AT_FDCWD as i64, notif.data.args[0])
    } else {
        (notif.data.args[0] as i64, notif.data.args[1])
    };
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let at_flags = if legacy {
        0
    } else {
        (notif.data.args[3] & 0xFFFF_FFFF) as i32
    };
    let raw_path = read_path(notif, path_ptr, notif_fd);
    let empty_fd_path = nr == libc::SYS_newfstatat
        && at_flags & libc::AT_EMPTY_PATH != 0
        && (path_ptr == 0 || raw_path.as_deref() == Some(""));
    if empty_fd_path {
        if dirfd as i32 != libc::AT_FDCWD {
            return handle_cow_fd_stat_into(
                notif,
                cow_state,
                dirfd as i32,
                notif.data.args[2],
                notif_fd,
            )
            .await;
        }
        let pinned = match pin_resolution_base(notif.pid, dirfd) {
            Ok(fd) => fd,
            Err(errno) => return NotifAction::Errno(errno),
        };
        return handle_cow_pinned_stat_into(
            notif,
            cow_state,
            pinned,
            notif.data.args[2],
            notif_fd,
        )
        .await;
    }
    let path = match (empty_fd_path, raw_path) {
        (true, _) => unreachable!("AT_EMPTY_PATH handled above"),
        (false, Some(path)) => {
            if let Err(errno) = check_relative_resolution_base(notif, dirfd, &path, cow_state).await {
                return NotifAction::Errno(errno);
            }
            resolve_at_path_with_virtual(notif, dirfd, &path, virtual_cwd.as_deref())
        }
        (false, None) => return NotifAction::Continue,
    };

    let follow = if legacy {
        arch::sys_lstat() != Some(nr)
    } else {
        at_flags & libc::AT_SYMLINK_NOFOLLOW == 0
    };

    let (real_path, upper_root, workdir_root, logical_mode) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &path);
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }
        if let Err(errno) = cow.check_logical_path_access(&path, 0) {
            return NotifAction::Errno(errno);
        }
        let real = match cow.handle_stat_with_follow(&path, follow) {
            Some(p) => p,
            None => return NotifAction::Errno(libc::ENOENT),
        };
        let logical_mode = if follow {
            cow.logical_directory_mode_follow(&path)
        } else {
            cow.logical_directory_mode(&path)
        };
        (real, upper_root, workdir_root, logical_mode)
    };

    if nr == libc::SYS_faccessat
        || nr == crate::arch::SYS_FACCESSAT2
        || arch::sys_access() == Some(nr)
    {
        // Existence check, confined: lstat succeeds for any present entry
        // (including a dangling symlink), matching the prior semantics.
        let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &real_path) {
            Ok(v) => v,
            Err(_) => return NotifAction::Errno(libc::ENOENT),
        };
        if crate::sys::fs::statat_in_root(root, &rel, false).is_ok() {
            return NotifAction::ReturnValue(0);
        }
        return NotifAction::Errno(libc::ENOENT);
    }

    // newfstatat/stat/lstat — stat the resolved path (confined to its layer
    // root) and write the native libc layout back to the child. Do not
    // hand-pack struct stat; its layout is architecture-specific.
    let statbuf_addr = if legacy { notif.data.args[1] } else { notif.data.args[2] };
    let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &real_path) {
        Ok(v) => v,
        Err(e) => return NotifAction::Errno(e),
    };
    let mut statbuf = match crate::sys::fs::statat_in_root(root, &rel, follow) {
        Ok(s) => s,
        Err(e) => return NotifAction::Errno(e),
    };
    if let Some(mode) = logical_mode {
        statbuf.st_mode = (statbuf.st_mode & !(0o7777 as libc::mode_t))
            | mode as libc::mode_t;
    }
    let buf = unsafe {
        std::slice::from_raw_parts(
            &statbuf as *const libc::stat as *const u8,
            std::mem::size_of::<libc::stat>(),
        )
    };

    if write_child_mem(notif_fd, notif.id, notif.pid, statbuf_addr, buf).is_err() {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(0)
}

/// Handle statx — resolve the path to upper/lower and run statx ourselves.
///
/// We cannot return Continue when the file exists: on Continue the kernel
/// re-runs statx against the original (un-redirected) path, which for a
/// COW-only file lives only in the upper layer and is invisible to the
/// kernel under the lower workdir → ENOENT. So mirror `handle_cow_stat`:
/// statx the resolved path in the supervisor and write the buffer back.
pub(crate) async fn handle_cow_statx(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    // statx(dirfd, pathname, flags, mask, statxbuf)
    let dirfd = notif.data.args[0] as i64;
    let flags = notif.data.args[2] as i32;
    let mask = notif.data.args[3] as u32;
    let statxbuf_addr = notif.data.args[4];

    // AT_EMPTY_PATH with an actually empty pathname operates on the fd's
    // pinned inode.  Never turn it back into a pathname: rename, unlink, and
    // fd reuse can make that name refer to a different merged entry.
    let empty_path = if (flags & libc::AT_EMPTY_PATH) != 0 {
        if notif.data.args[1] == 0 {
            true
        } else {
            match read_path(notif, notif.data.args[1], notif_fd) {
            Some(path) => path.is_empty(),
            None => return NotifAction::Continue,
            }
        }
    } else {
        false
    };
    if empty_path {
        let pinned = if dirfd as i32 == libc::AT_FDCWD {
            match pin_resolution_base(notif.pid, dirfd) {
                Ok(fd) => fd,
                Err(errno) => return NotifAction::Errno(errno),
            }
        } else {
            match crate::seccomp::notif::dup_fd_from_pid(notif.pid, dirfd as i32) {
                Ok(fd) => fd,
                Err(error) => {
                    return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF))
                }
            }
        };
        let real_path = match std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd())) {
            Ok(path) => path,
            Err(_) => return NotifAction::Errno(libc::EBADF),
        };
        let logical_mode = {
            let st = cow_state.lock().await;
            let cow = match st.branch.as_ref() {
                Some(cow) => cow,
                None => return NotifAction::Continue,
            };
            if !cow.contains_layer_path(&real_path) {
                return NotifAction::Continue;
            }
            cow.logical_directory_mode_for_handle(&real_path)
        };
        let mut stx_buf = vec![0u8; 256];
        let empty = b"\0";
        let rc = unsafe {
            libc::syscall(
                libc::SYS_statx,
                pinned.as_raw_fd(),
                empty.as_ptr() as *const libc::c_char,
                flags,
                mask,
                stx_buf.as_mut_ptr(),
            )
        };
        if rc < 0 {
            return NotifAction::Errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            );
        }
        patch_statx_mode(&mut stx_buf, logical_mode);
        if write_child_mem(notif_fd, notif.id, notif.pid, statxbuf_addr, &stx_buf).is_err() {
            return NotifAction::Continue;
        }
        return NotifAction::ReturnValue(0);
    }

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(path) if !path.is_empty() => {
            if let Err(errno) = check_relative_resolution_base(notif, dirfd, &path, cow_state).await {
                return NotifAction::Errno(errno);
            }
            resolve_at_path_with_virtual(notif, dirfd, &path, virtual_cwd.as_deref())
        }
        _ => return NotifAction::Continue,
    };

    let (real_path, upper_root, workdir_root, logical_mode) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &path);
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }
        if let Err(errno) = cow.check_logical_path_access(&path, 0) {
            return NotifAction::Errno(errno);
        }
        let real = match cow.handle_stat_with_follow(
            &path,
            flags & libc::AT_SYMLINK_NOFOLLOW == 0,
        ) {
            Some(p) => p,
            None => return NotifAction::Errno(libc::ENOENT), // deleted or absent
        };
        let logical_mode = if flags & libc::AT_SYMLINK_NOFOLLOW == 0 {
            cow.logical_directory_mode_follow(&path)
        } else {
            cow.logical_directory_mode(&path)
        };
        (real, upper_root, workdir_root, logical_mode)
    };

    let (root, rel) = match pick_root_rel(&upper_root, &workdir_root, &real_path) {
        Ok(v) => v,
        Err(e) => return NotifAction::Errno(e),
    };
    let mut stx_buf = vec![0u8; 256]; // sizeof(struct statx)
    if let Err(e) = crate::sys::fs::statx_in_root(root, &rel, flags, mask, &mut stx_buf) {
        return NotifAction::Errno(e);
    }
    patch_statx_mode(&mut stx_buf, logical_mode);

    if write_child_mem(notif_fd, notif.id, notif.pid, statxbuf_addr, &stx_buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(0)
}

pub(crate) async fn handle_cow_fstat(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    _processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    handle_cow_fd_stat_into(
        notif,
        cow_state,
        notif.data.args[0] as i32,
        notif.data.args[1],
        notif_fd,
    )
    .await
}

fn patch_statx_mode(buffer: &mut [u8], logical_mode: Option<u32>) {
    let Some(mode) = logical_mode else {
        return;
    };
    // Linux `struct statx::stx_mode` is the u16 at byte offset 28 on every
    // architecture using this syscall ABI.
    if buffer.len() >= 30 {
        let current = u16::from_ne_bytes([buffer[28], buffer[29]]);
        let patched = (current & !0o7777) | mode as u16;
        buffer[28..30].copy_from_slice(&patched.to_ne_bytes());
    }
}

// ============================================================
// execve / execveat handler
// ============================================================

/// Handle execve/execveat under COW: when the binary resolves into the
/// upper layer (created or modified inside the workdir), open the upper
/// file and inject it as an fd, rewriting the path to /proc/self/fd/N so
/// the kernel execs the COW version.
///
/// Without this, execve resolves the original (un-redirected) path, which
/// for a COW-only binary lives only in upper and is invisible under the
/// lower workdir → ENOENT. Files resolving to the lower layer are
/// unmodified, so the kernel finds them at the original path and we leave
/// them alone.
pub(crate) async fn handle_cow_exec(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let nr = notif.data.nr as i64;
    // execve(path, argv, envp):              args[0]=path,  args[1]=argv, args[2]=envp
    // execveat(dirfd, path, argv, envp, ..): args[1]=path, args[2]=argv, args[3]=envp
    let (dirfd, path_ptr, argv_ptr, envp_ptr) = if nr == libc::SYS_execveat {
        (notif.data.args[0] as i64, notif.data.args[1], notif.data.args[2], notif.data.args[3])
    } else {
        (libc::AT_FDCWD as i64, notif.data.args[0], notif.data.args[1], notif.data.args[2])
    };

    let rel_path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    if let Err(errno) = check_relative_resolution_base(notif, dirfd, &rel_path, cow_state).await {
        return NotifAction::Errno(errno);
    }

    let virtual_cwd = if (dirfd as i32) == libc::AT_FDCWD && !Path::new(&rel_path).is_absolute() {
        current_virtual_cwd(processes, notif.pid).await
    } else {
        None
    };
    let resolved = resolve_at_path_with_virtual(notif, dirfd, &rel_path, virtual_cwd.as_deref());

    let (upper_path, upper_root, workdir_root) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let path = map_cow_upper_path(cow, &resolved);
        if !cow.matches(&path) {
            return NotifAction::Continue;
        }
        if let Err(errno) = cow.check_logical_path_access(&path, 0) {
            return NotifAction::Errno(errno);
        }
        let real = match cow.handle_stat(&path) {
            // Only redirect when the binary lives in the upper layer.
            Some(real) if real.starts_with(cow.upper_dir()) => real,
            // Lower-layer (unmodified) binary — kernel resolves it fine.
            Some(_) => return NotifAction::Continue,
            // Deleted in the COW layer (or absent) — must not exec the lower file.
            None => return NotifAction::Errno(libc::ENOENT),
        };
        (real, upper_root, workdir_root)
    };

    // Open the upper binary and inject the fd into the child.
    let src_fd = match open_confined(
        &upper_root,
        &workdir_root,
        &upper_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    let addfd = crate::sys::structs::SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: 0, // no O_CLOEXEC — the kernel must read it at exec time
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            crate::sys::structs::SECCOMP_IOCTL_NOTIF_ADDFD as _,
            &addfd as *const _,
        )
    };
    unsafe { libc::close(src_fd) };

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    // Rewrite the path argument to /proc/self/fd/N so the kernel execs the
    // injected fd, relocating argv[0] when it aliases the path buffer (see
    // rewrite_exec_path_to_fd). Force-writes past read-only protections (a
    // .rodata exec path literal). No length guard: execve replaces the
    // address space on success, so a write past the original buffer is
    // harmless.
    if crate::seccomp::notif::rewrite_exec_path_to_fd(
        notif_fd, notif.id, notif.pid, path_ptr, argv_ptr, envp_ptr, child_fd,
    )
    .is_err()
    {
        return NotifAction::Errno(libc::EFAULT);
    }

    NotifAction::Continue
}

/// Handle readlinkat — read symlink from upper/lower, write to child buffer.
pub(crate) async fn handle_cow_readlink(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    // readlinkat(dirfd, pathname, buf, bufsiz)
    let dirfd = notif.data.args[0] as i64;
    let raw_path = match read_path(notif, notif.data.args[1], notif_fd) {
        Some(path) => path,
        None => return NotifAction::Continue,
    };
    if let Err(errno) = check_relative_resolution_base(notif, dirfd, &raw_path, cow_state).await {
        return NotifAction::Errno(errno);
    }
    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let path = resolve_at_path_with_virtual(notif, dirfd, &raw_path, virtual_cwd.as_deref());
    let buf_addr = notif.data.args[2];
    let bufsiz = (notif.data.args[3] & 0xFFFFFFFF) as usize;

    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(c) => c,
        None => return NotifAction::Continue,
    };

    let path = map_cow_upper_path(cow, &path);
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }
    if let Err(errno) = cow.check_logical_path_access(&path, 0) {
        return NotifAction::Errno(errno);
    }

    let target = match cow.handle_readlink(&path) {
        Some(t) => t,
        None => return NotifAction::Errno(libc::ENOENT),
    };
    drop(st);

    let target_bytes = target.as_bytes();
    let write_len = target_bytes.len().min(bufsiz);

    if write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &target_bytes[..write_len]).is_err()
    {
        return NotifAction::Continue;
    }

    NotifAction::ReturnValue(write_len as i64)
}

/// Handle getdents64 for COW directories — merge upper + lower entries.
pub(crate) async fn handle_cow_getdents(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let pid = notif.pid;
    let child_fd = (notif.data.args[0] & 0xFFFFFFFF) as u32;
    let buf_addr = notif.data.args[1];
    let buf_size = (notif.data.args[2] & 0xFFFFFFFF) as usize;

    // Pin the directory inode. The child may close/reuse its numeric fd while
    // this notification is stopped, but this merged read must stay bound to
    // the object that triggered it.
    let pinned = match crate::seccomp::notif::dup_fd_from_pid(pid, child_fd as i32) {
        Ok(fd) => fd,
        Err(error) => return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let target = match std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd())) {
        Ok(t) => t.to_string_lossy().into_owned(),
        Err(_) => return NotifAction::Errno(libc::EBADF),
    };

    // Compute rel_path under the global COW lock, but do not hold it
    // across the per-process lock acquired below.
    let rel_path = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let handle_mode = cow.logical_directory_mode_for_handle(Path::new(&target));
        if handle_mode.is_some_and(|mode| mode & 0o100 == 0) {
            return NotifAction::Errno(libc::EACCES);
        }
        if !cow.has_changes() {
            return NotifAction::Continue;
        }
        let target_path = Path::new(&target);
        if cow.matches(&target) {
            cow.safe_rel(&target).unwrap_or_else(|| ".".to_string())
        } else if let Ok(rel) = target_path.strip_prefix(cow.upper_dir()) {
            let rel = rel.to_string_lossy();
            if rel.is_empty() {
                ".".to_string()
            } else {
                rel.into_owned()
            }
        } else {
            return NotifAction::Continue;
        }
    };

    // Per-process dir cache lookup.
    let pp = match pp_handle(processes, pid) {
        Some(h) => h,
        None => return NotifAction::Continue,
    };
    let mut perproc = pp.lock().await;

    // Invalidate stale cache (fd reused for a different directory),
    // and short-circuit EOF on a previously fully-drained entry.
    if let Some((cached_target, entries)) = perproc.cow_dir_cache.get(&child_fd) {
        if *cached_target != target {
            perproc.cow_dir_cache.remove(&child_fd);
        } else if entries.is_empty() {
            perproc.cow_dir_cache.remove(&child_fd);
            return NotifAction::ReturnValue(0);
        }
    }

    // Build cache on first call.
    if !perproc.cow_dir_cache.contains_key(&child_fd) {
        let entries = {
            let st = cow_state.lock().await;
            let cow = match st.branch.as_ref() {
                Some(c) => c,
                None => return NotifAction::Continue,
            };
            let merged = cow.list_merged_dir(&rel_path);
            let upper_dir = cow.upper_dir().join(&rel_path);
            let lower_dir = cow.workdir().join(&rel_path);

            let mut out = Vec::new();
            let mut d_off: i64 = 0;
            for name in &merged {
                d_off += 1;
                let upper_p = upper_dir.join(name);
                let lower_p = lower_dir.join(name);
                let check = if upper_p.exists() || upper_p.is_symlink() {
                    &upper_p
                } else {
                    &lower_p
                };
                let d_type = if check.is_dir() {
                    DT_DIR
                } else if check.is_symlink() {
                    DT_LNK
                } else {
                    DT_REG
                };
                use std::os::unix::fs::MetadataExt;
                let d_ino = std::fs::symlink_metadata(check)
                    .map(|m| m.ino())
                    .unwrap_or(0);
                if let Some(rec) = build_dirent64(d_ino, d_off, d_type, name) {
                    out.push(rec);
                }
            }
            out
        };
        perproc.cow_dir_cache.insert(child_fd, (target.clone(), entries));
    }

    let entries = match perproc.cow_dir_cache.get_mut(&child_fd) {
        Some((_, e)) => e,
        None => return NotifAction::Continue,
    };

    let mut result = Vec::new();
    let mut consumed = 0;
    for entry in entries.iter() {
        if result.len() + entry.len() > buf_size {
            break;
        }
        result.extend_from_slice(entry);
        consumed += 1;
    }

    if consumed > 0 {
        entries.drain(..consumed);
    }
    drop(perproc);

    if !result.is_empty() {
        if write_child_mem(notif_fd, notif.id, pid, buf_addr, &result).is_err() {
            return NotifAction::Continue;
        }
    }

    NotifAction::ReturnValue(result.len() as i64)
}

/// Handle chdir — redirect to COW upper directory if the target was created
/// by COW and doesn't exist on the real filesystem.
///
/// Opens the upper directory, injects the fd into the child, and rewrites
/// the path arg to /proc/self/fd/N so the kernel chdir succeeds.
pub(crate) async fn handle_cow_chdir(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let path_ptr = notif.data.args[0];
    let path = match read_path(notif, path_ptr, notif_fd) {
        Some(p) => p,
        None => return NotifAction::Continue,
    };
    if let Err(errno) = check_relative_resolution_base(
        notif,
        libc::AT_FDCWD as i64,
        &path,
        cow_state,
    )
    .await
    {
        return NotifAction::Errno(errno);
    }
    let orig_path_buf_len = path.len() + 1; // NUL-terminated size in child memory

    let virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let resolved = resolve_at_path_with_virtual(
        notif,
        libc::AT_FDCWD as i64,
        &path,
        virtual_cwd.as_deref(),
    );

    let (abs_path, upper_path, upper_root, workdir_root) = {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let upper_root = cow.upper_dir().to_path_buf();
        let workdir_root = cow.workdir().to_path_buf();
        let abs_path = map_cow_upper_path(cow, &resolved);
        if !cow.matches(&abs_path) {
            return NotifAction::Continue;
        }
        if let Err(errno) = cow.check_logical_path_access(&abs_path, 0o100) {
            return NotifAction::Errno(errno);
        }
        let rel = match cow.safe_rel(&abs_path) {
            Some(r) => r,
            None => return NotifAction::Continue,
        };
        let upper_path = cow.upper_dir().join(&rel);
        (abs_path, upper_path, upper_root, workdir_root)
    };

    // If the directory exists on the real filesystem, let the kernel handle it.
    if std::path::Path::new(&abs_path).is_dir() {
        return NotifAction::Continue;
    }

    // Only intervene if the directory exists in the COW upper layer.
    if !upper_path.is_dir() {
        return NotifAction::Continue;
    }

    // Open the upper directory and inject fd into the child.
    let src_fd = match open_confined(
        &upper_root,
        &workdir_root,
        &upper_path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
        0,
    ) {
        Ok(fd) => fd,
        Err(_) => return NotifAction::Errno(libc::ENOENT),
    };

    let addfd = crate::sys::structs::SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    let child_fd = unsafe {
        libc::ioctl(
            notif_fd,
            crate::sys::structs::SECCOMP_IOCTL_NOTIF_ADDFD as _,
            &addfd as *const _,
        )
    };
    unsafe { libc::close(src_fd) };

    if child_fd < 0 {
        return NotifAction::Errno(libc::EIO);
    }

    // Rewrite the path argument to /proc/self/fd/N so the kernel chdir
    // follows the injected fd.  The original buffer at path_ptr must be
    // large enough — otherwise we'd corrupt adjacent child memory.
    let fd_path = format!("/proc/self/fd/{}\0", child_fd);
    if orig_path_buf_len < fd_path.len() {
        // Original path buffer too small for the rewrite.  The injected
        // fd has O_CLOEXEC so it will be cleaned up on exit/exec.
        return NotifAction::Errno(libc::ENOENT);
    }
    // Force-write past read-only protections (a .rodata chdir path literal).
    // The fit guard above keeps the redirect from overflowing the buffer.
    if write_child_mem_force(notif_fd, notif.id, notif.pid, path_ptr, fd_path.as_bytes()).is_err() {
        return NotifAction::Errno(libc::EFAULT);
    }

    // We insert the virtual cwd here, before returning Continue and
    // letting the kernel run the rewritten chdir. We can't observe
    // the kernel's verdict without polling, but at this point we've
    // verified upper_path is a directory, the addfd ioctl succeeded,
    // and write_child_mem rewrote the path argument — so a kernel
    // chdir to /proc/self/fd/N is essentially guaranteed. If it does
    // somehow fail, the per-child pidfd watcher will drop this entry
    // when the process exits, so the inconsistency is bounded by
    // process lifetime.
    if let Some(pp) = pp_handle(processes, notif.pid) {
        pp.lock().await.virtual_cwd = Some(abs_path);
    }

    NotifAction::Continue
}

pub(crate) async fn handle_cow_fchdir(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    _notif_fd: RawFd,
) -> NotifAction {
    let fd = notif.data.args[0] as i32;
    let pinned = match crate::seccomp::notif::dup_fd_from_pid(notif.pid, fd) {
        Ok(fd) => fd,
        Err(error) => return NotifAction::Errno(error.raw_os_error().unwrap_or(libc::EBADF)),
    };
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(pinned.as_raw_fd(), &mut metadata) } < 0 {
        return NotifAction::Errno(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF),
        );
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return NotifAction::Errno(libc::ENOTDIR);
    }
    let real_path = match std::fs::read_link(format!("/proc/self/fd/{}", pinned.as_raw_fd())) {
        Ok(path) => path,
        Err(_) => return NotifAction::Errno(libc::EBADF),
    };
    let st = cow_state.lock().await;
    let cow = match st.branch.as_ref() {
        Some(cow) => cow,
        None => return NotifAction::Continue,
    };
    let path = map_cow_upper_path(cow, real_path.to_string_lossy().as_ref());
    if !cow.matches(&path) {
        return NotifAction::Continue;
    }
    let handle_mode = cow
        .logical_directory_mode_for_handle(&real_path)
        .unwrap_or(metadata.st_mode & 0o7777);
    if handle_mode & 0o100 == 0 {
        return NotifAction::Errno(libc::EACCES);
    }
    // Do not predict which inode the kernel will install from the child's fd
    // slot: another thread can close/dup2 that number while this notification
    // is stopped. Forget any prior synthetic cwd so later relative operations
    // derive the actual successful result (or unchanged cwd on failure) from
    // /proc instead of poisoning routing with the preflight handle.
    if let Some(process) = pp_handle(processes, notif.pid) {
        process.lock().await.virtual_cwd = None;
    }
    if let Ok(pid) = i32::try_from(notif.pid) {
        processes.clear_virtual_cwd(pid);
    }
    NotifAction::Continue
}

/// Handle getcwd after chdir into a COW-only directory.
pub(crate) async fn handle_cow_getcwd(
    notif: &SeccompNotif,
    cow_state: &Arc<Mutex<CowState>>,
    processes: &Arc<ProcessIndex>,
    notif_fd: RawFd,
) -> NotifAction {
    let buf_addr = notif.data.args[0];
    let buf_size = (notif.data.args[1] & 0xFFFF_FFFF) as usize;

    let cached_virtual_cwd = current_virtual_cwd(processes, notif.pid).await;
    let virtual_cwd = if let Some(cwd) = cached_virtual_cwd {
        cwd
    } else {
        let st = cow_state.lock().await;
        let cow = match st.branch.as_ref() {
            Some(c) => c,
            None => return NotifAction::Continue,
        };
        let cwd = match std::fs::read_link(format!("/proc/{}/cwd", notif.pid)) {
            Ok(c) => c,
            Err(_) => return NotifAction::Continue,
        };
        match cwd.strip_prefix(cow.upper_dir()) {
            Ok(rel) => cow.workdir().join(rel).to_string_lossy().into_owned(),
            Err(_) => return NotifAction::Continue,
        }
    };

    let cwd_bytes = virtual_cwd.as_bytes();
    if cwd_bytes.len() + 1 > buf_size {
        return NotifAction::Errno(libc::ERANGE);
    }

    let mut write_buf = cwd_bytes.to_vec();
    write_buf.push(0);

    if write_child_mem(notif_fd, notif.id, notif.pid, buf_addr, &write_buf).is_err() {
        return NotifAction::Continue;
    }
    NotifAction::ReturnValue(write_buf.len() as i64)
}

#[cfg(test)]
mod confine_tests {
    use super::open_confined;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use tempfile::TempDir;

    fn read_fd_path(fd: i32) -> std::path::PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{}", fd)).unwrap()
    }

    #[test]
    fn serves_in_tree_file() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        std::fs::write(lower.path().join("ok.txt"), "data").unwrap();
        let real = lower.path().join("ok.txt");
        match open_confined(upper.path(), lower.path(), &real, libc::O_RDONLY, 0, 0) {
            Ok(fd) => {
                assert_eq!(std::fs::read_to_string(format!("/proc/self/fd/{}", fd)).unwrap(), "data");
                unsafe { libc::close(fd) };
            }
            Err(libc::ENOSYS) => {}
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn blocks_final_component_symlink_escape() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        // workdir/link -> /etc/passwd
        symlink("/etc/passwd", lower.path().join("link")).unwrap();
        let real = lower.path().join("link");
        match open_confined(upper.path(), lower.path(), &real, libc::O_RDONLY, 0, 0) {
            // Confined: /etc/passwd resolves under <lower>/etc/passwd, absent.
            Err(libc::ENOENT) | Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved = read_fd_path(fd);
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(lower.path()), "escaped: {:?}", resolved);
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn blocks_intermediate_component_symlink_escape() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        // workdir/evil -> /etc, child opens evil/passwd
        symlink("/etc", lower.path().join("evil")).unwrap();
        let real = lower.path().join("evil/passwd");
        match open_confined(upper.path(), lower.path(), &real, libc::O_RDONLY, 0, 0) {
            Err(libc::ENOENT) | Err(libc::ENOSYS) => {}
            Ok(fd) => {
                let resolved = read_fd_path(fd);
                unsafe { libc::close(fd) };
                assert!(resolved.starts_with(lower.path()), "escaped: {:?}", resolved);
            }
            Err(e) => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn refuses_path_under_neither_root() {
        let upper = TempDir::new().unwrap();
        let lower = TempDir::new().unwrap();
        let real = Path::new("/etc/passwd");
        assert_eq!(
            open_confined(upper.path(), lower.path(), real, libc::O_RDONLY, 0, 0),
            Err(libc::EACCES)
        );
    }
}
