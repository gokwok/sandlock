//! Durable immutable filesystem snapshots used as stable COW branch lowers.
//!
//! A snapshot is a complete materialized tree published through a staging
//! directory and an atomic rename. Regular files use reflink cloning when the
//! backing filesystem supports it and fall back to buffered copies otherwise.
//! A persistent file hash and directory Merkle index accelerates immutable
//! comparisons without adding a content-addressed store or live COW layer.

use crate::error::SnapshotError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[path = "snapshot/compare.rs"]
mod compare;
#[path = "snapshot/delta.rs"]
mod delta;
#[path = "snapshot/index.rs"]
mod index;
#[path = "snapshot/mutation.rs"]
mod mutation;

use index::{SnapshotIndex, SnapshotIndexEntry};

pub use compare::{
    SnapshotCompareLimits, SnapshotCompareScope, SnapshotComparison, SnapshotRequirement,
};
pub use delta::{
    SnapshotDelta, SnapshotDeltaApplyMode, SnapshotDeltaLimits, SnapshotDeltaPolicy,
    SnapshotDeltaSummary,
};
pub use mutation::{SnapshotMutation, SnapshotMutationLimits};

const SNAPSHOT_METADATA: &str = "SNAPSHOT.json";
const SNAPSHOT_DIRECTORY_MODES: &str = "DIRECTORY_MODES.json";
const SNAPSHOT_INDEX: &str = "INDEX.bin";
const SNAPSHOT_TREE: &str = "tree";
const SNAPSHOT_LEASES: &str = "leases";
const SNAPSHOT_LEASE_LOCK: &str = "leases.lock";
const HANDLE_LEASE_PREFIX: &str = "handle-";
const BRANCH_LEASE_PREFIX: &str = "branch-";
const BRANCH_PRESERVED_MARKER: &str = "PRESERVED";
const DEFAULT_SCAN_ENTRY_BUDGET: usize = 100_000;
const DEFAULT_SCAN_PATH_BYTE_BUDGET: usize = 16 * 1024 * 1024;
const DEFAULT_DIFF_CONTENT_BYTE_BUDGET: u64 = 1024 * 1024 * 1024;

#[cfg(test)]
static FAIL_AFTER_SNAPSHOT_PUBLISH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static FAIL_AFTER_MATERIALIZE_PUBLISH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static FAIL_AFTER_DESTROY_TOMBSTONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Durable opaque reference to one immutable snapshot.
///
/// The descriptor is intended for a trusted controller to serialize. Its path
/// is backend state and must not be exposed to a sandboxed process.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FsSnapshotDescriptor {
    snapshot_dir: PathBuf,
    id: String,
}

impl FsSnapshotDescriptor {
    /// Stable backend-generated snapshot identifier.
    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotMetadata {
    id: String,
    root_hash: [u8; 32],
}

/// Type of one entry in a snapshot tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotEntryKind {
    File,
    Directory,
    Symlink,
}

/// Metadata for one snapshot-relative path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    pub path: PathBuf,
    pub kind: SnapshotEntryKind,
    pub mode: u32,
    pub len: u64,
    pub symlink_target: Option<PathBuf>,
}

/// Bounded immediate-child directory listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotList {
    pub entries: Vec<SnapshotEntry>,
    pub total_entries: usize,
    pub next_offset: Option<usize>,
}

/// Structural difference between two immutable snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotChangeKind {
    Added,
    Modified,
    Deleted,
    TypeChanged,
    ModeChanged,
    SymlinkTargetChanged,
}

/// One changed snapshot-relative path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotChange {
    pub path: PathBuf,
    pub kind: SnapshotChangeKind,
}

/// Bounded snapshot diff plus the complete change count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDiff {
    pub changes: Vec<SnapshotChange>,
    pub changed_paths: usize,
    pub truncated: bool,
    pub next_path: Option<PathBuf>,
}

/// Immutable, durable, materialized filesystem tree.
#[must_use = "snapshots persist until explicitly destroyed"]
pub struct FsSnapshot {
    descriptor: FsSnapshotDescriptor,
    tree_dir: PathBuf,
    root_hash: [u8; 32],
    handle_lease: Option<SnapshotHandleLease>,
    destroyed: bool,
}

enum SnapshotIndexUpdate {
    None,
    RefreshPaths(Vec<PathBuf>),
    Branch {
        upper: PathBuf,
        deleted: Vec<PathBuf>,
        changed_directories: BTreeSet<PathBuf>,
    },
}

impl std::fmt::Debug for FsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsSnapshot")
            .field("id", &self.descriptor.id)
            .field("snapshot_dir", &self.descriptor.snapshot_dir)
            .field("destroyed", &self.destroyed)
            .finish()
    }
}

impl FsSnapshot {
    /// Enumerate complete snapshots in one caller-owned storage base.
    ///
    /// This is the recovery path for a controller that crashed after Sandlock
    /// atomically published a snapshot but before it persisted the returned
    /// descriptor. Incomplete dot-prefixed staging directories are ignored.
    pub fn discover(storage: impl AsRef<Path>) -> Result<Vec<FsSnapshotDescriptor>, SnapshotError> {
        let storage = storage.as_ref().canonicalize().map_err(|error| {
            SnapshotError::InvalidDescriptor(format!(
                "canonicalize snapshot storage for discovery: {error}"
            ))
        })?;
        validate_plain_directory(&storage, "snapshot storage")?;
        let mut descriptors = Vec::new();
        for entry in
            fs::read_dir(&storage).map_err(|error| operation("list snapshot storage", error))?
        {
            let entry = entry.map_err(|error| operation("read snapshot storage entry", error))?;
            let name = entry.file_name();
            if name.as_os_str().as_bytes().starts_with(b".") {
                reap_destroy_tombstone(&entry.path(), &name)?;
                continue;
            }
            if !entry
                .file_type()
                .map_err(|error| operation("inspect snapshot storage entry", error))?
                .is_dir()
            {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "unexpected non-directory in snapshot storage: {}",
                    entry.path().display()
                )));
            }
            let id = name.to_str().ok_or_else(|| {
                SnapshotError::InvalidDescriptor(
                    "snapshot directory id is not valid UTF-8".to_string(),
                )
            })?;
            let parsed = uuid::Uuid::parse_str(id).map_err(|error| {
                SnapshotError::InvalidDescriptor(format!(
                    "snapshot directory id is invalid: {error}"
                ))
            })?;
            if parsed.to_string() != id {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot directory id is not canonical".to_string(),
                ));
            }
            let metadata = read_metadata(&entry.path())?;
            if metadata.id != id {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot storage entry does not match its metadata".to_string(),
                ));
            }
            let _ = read_index(&entry.path(), metadata.root_hash)?;
            descriptors.push(FsSnapshotDescriptor {
                snapshot_dir: entry.path(),
                id: id.to_string(),
            });
        }
        descriptors.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(descriptors)
    }

    /// Capture a stable copy of `source` under the caller-owned storage base.
    ///
    /// A metadata inventory before and after the copy detects concurrent
    /// mutation. The caller must still quiesce every writer it controls; no
    /// userspace directory copy can globally lock arbitrary external writers.
    pub fn capture(
        source: impl AsRef<Path>,
        storage: impl AsRef<Path>,
    ) -> Result<Self, SnapshotError> {
        capture_with_overlay(source.as_ref(), storage.as_ref(), None, None, |_, _| {
            Ok(SnapshotIndexUpdate::None)
        })
    }

    /// Reopen a snapshot that was previously published successfully.
    pub fn reopen(descriptor: FsSnapshotDescriptor) -> Result<Self, SnapshotError> {
        let canonical = descriptor.snapshot_dir.canonicalize().map_err(|error| {
            SnapshotError::InvalidDescriptor(format!("canonicalize snapshot directory: {error}"))
        })?;
        if canonical != descriptor.snapshot_dir {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot directory is not canonical".to_string(),
            ));
        }
        let expected_name = std::ffi::OsStr::new(&descriptor.id);
        if canonical.file_name() != Some(expected_name)
            || expected_name.as_bytes().starts_with(b".")
        {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot directory name does not match its id".to_string(),
            ));
        }
        validate_plain_directory(&canonical, "snapshot directory")?;
        let tree_dir = canonical.join(SNAPSHOT_TREE);
        validate_plain_directory(&tree_dir, "snapshot tree")?;
        validate_plain_directory(&canonical.join(SNAPSHOT_LEASES), "snapshot leases")?;
        validate_plain_file(&canonical.join(SNAPSHOT_LEASE_LOCK), "snapshot lease lock")?;
        validate_plain_file(
            &canonical.join(SNAPSHOT_DIRECTORY_MODES),
            "snapshot directory modes",
        )?;

        let metadata = read_metadata(&canonical)?;
        if metadata.id != descriptor.id {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot id does not match its descriptor".to_string(),
            ));
        }
        let _ = read_index(&canonical, metadata.root_hash)?;
        let handle_lease = acquire_handle_lease(&descriptor)?;
        Ok(Self {
            descriptor,
            tree_dir,
            root_hash: metadata.root_hash,
            handle_lease: Some(handle_lease),
            destroyed: false,
        })
    }

    /// Opaque durable descriptor for controller persistence.
    pub fn descriptor(&self) -> &FsSnapshotDescriptor {
        &self.descriptor
    }

    /// Stable backend-generated snapshot identifier.
    pub fn id(&self) -> &str {
        self.descriptor.id()
    }

    /// Physical immutable lower directory for trusted Sandlock composition.
    ///
    /// Do not grant this path directly to an untrusted process. Use it as a
    /// read-only workdir/lower through Sandlock's policy and COW APIs.
    pub fn root_dir(&self) -> &Path {
        &self.tree_dir
    }

    fn index(&self) -> Result<SnapshotIndex, SnapshotError> {
        read_index(&self.descriptor.snapshot_dir, self.root_hash)
    }

    pub(crate) fn directory_modes(&self) -> Result<BTreeMap<PathBuf, u32>, SnapshotError> {
        Ok(read_backend_directory_modes(&self.tree_dir)?.unwrap_or_default())
    }

    /// Inspect one path without following its final symlink.
    pub fn stat(&self, path: impl AsRef<Path>) -> Result<SnapshotEntry, SnapshotError> {
        self.ensure_live()?;
        snapshot_entry(&self.tree_dir, path.as_ref())
    }

    /// Read at most `max_bytes` from a regular file starting at `offset`.
    pub fn read_range(
        &self,
        path: impl AsRef<Path>,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Vec<u8>, SnapshotError> {
        self.ensure_live()?;
        let rel = normalize_relative(path.as_ref())?;
        let full = contained_final_path(&self.tree_dir, &rel)?;
        let metadata = fs::symlink_metadata(&full)
            .map_err(|error| operation("inspect snapshot file", error))?;
        if !metadata.file_type().is_file() {
            return Err(SnapshotError::Operation(format!(
                "{} is not a regular file",
                rel.display()
            )));
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&full)
            .map_err(|error| operation("open snapshot file", error))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| operation("seek snapshot file", error))?;
        let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
        file.take(u64::try_from(max_bytes).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|error| operation("read snapshot file", error))?;
        Ok(bytes)
    }

    /// List immediate children in deterministic bytewise path order.
    pub fn list(
        &self,
        path: impl AsRef<Path>,
        offset: usize,
        max_entries: usize,
    ) -> Result<SnapshotList, SnapshotError> {
        self.ensure_live()?;
        let rel = normalize_relative(path.as_ref())?;
        let directory = contained_directory(&self.tree_dir, &rel)?;
        let requested = offset.checked_add(max_entries).ok_or_else(|| {
            SnapshotError::LimitExceeded("directory page offset overflow".to_string())
        })?;
        if requested > DEFAULT_SCAN_ENTRY_BUDGET {
            return Err(SnapshotError::LimitExceeded(format!(
                "directory page requires scanning {requested} entries; limit is {DEFAULT_SCAN_ENTRY_BUDGET}"
            )));
        }
        let mut paths = Vec::with_capacity(requested.min(4096));
        let mut total_entries = 0_usize;
        let mut path_bytes = 0_usize;
        for entry in
            fs::read_dir(&directory).map_err(|error| operation("list snapshot directory", error))?
        {
            let entry = entry.map_err(|error| operation("read snapshot directory entry", error))?;
            total_entries = total_entries.checked_add(1).ok_or_else(|| {
                SnapshotError::LimitExceeded("directory entry count overflow".to_string())
            })?;
            if total_entries > DEFAULT_SCAN_ENTRY_BUDGET {
                return Err(SnapshotError::LimitExceeded(format!(
                    "directory contains more than {DEFAULT_SCAN_ENTRY_BUDGET} entries"
                )));
            }
            let path = rel.join(entry.file_name());
            path_bytes = path_bytes
                .checked_add(path.as_os_str().as_bytes().len())
                .ok_or_else(|| {
                    SnapshotError::LimitExceeded("directory path budget overflow".to_string())
                })?;
            if path_bytes > DEFAULT_SCAN_PATH_BYTE_BUDGET {
                return Err(SnapshotError::LimitExceeded(format!(
                    "directory path data exceeds {DEFAULT_SCAN_PATH_BYTE_BUDGET} bytes"
                )));
            }
            paths.push(path);
        }
        paths.sort();
        let entries = paths
            .into_iter()
            .skip(offset)
            .take(max_entries)
            .map(|path| snapshot_entry(&self.tree_dir, &path))
            .collect::<Result<Vec<_>, _>>()?;
        let consumed = offset.saturating_add(entries.len());
        let next_offset = (consumed < total_entries).then_some(consumed);
        Ok(SnapshotList {
            entries,
            total_entries,
            next_offset,
        })
    }

    /// Compare two complete immutable trees, retaining at most `max_changes`.
    pub fn diff(
        &self,
        target: &FsSnapshot,
        max_changes: usize,
    ) -> Result<SnapshotDiff, SnapshotError> {
        self.diff_after(target, None::<&Path>, max_changes)
    }

    /// Compare two snapshots after an optional exclusive path cursor.
    ///
    /// `next_path` can be passed back as `after` to continue a truncated diff.
    pub fn diff_after(
        &self,
        target: &FsSnapshot,
        after: Option<impl AsRef<Path>>,
        max_changes: usize,
    ) -> Result<SnapshotDiff, SnapshotError> {
        self.ensure_live()?;
        target.ensure_live()?;
        let cursor = after
            .map(|path| normalize_relative(path.as_ref()))
            .transpose()?;
        if self.root_hash == target.root_hash {
            return Ok(SnapshotDiff {
                changes: Vec::new(),
                changed_paths: 0,
                truncated: false,
                next_path: None,
            });
        }
        let before = self.index()?;
        let after = target.index()?;
        let remaining = DEFAULT_SCAN_ENTRY_BUDGET
            .checked_sub(before.entries.len())
            .ok_or_else(|| {
                SnapshotError::LimitExceeded("snapshot diff entry budget was exceeded".to_string())
            })?;
        if after.entries.len() > remaining {
            return Err(SnapshotError::LimitExceeded(
                "snapshot diff entry budget was exceeded".to_string(),
            ));
        }
        let paths = before
            .entries
            .keys()
            .chain(after.entries.keys())
            .filter(|path| !path.as_os_str().is_empty())
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut changes = Vec::new();
        let mut changed_paths = 0;
        let mut remaining_changed_paths = 0;
        for path in paths {
            let kind = match (before.entries.get(&path), after.entries.get(&path)) {
                (None, Some(_)) => Some(SnapshotChangeKind::Added),
                (Some(_), None) => Some(SnapshotChangeKind::Deleted),
                (Some(left), Some(right)) => indexed_change_kind(left, right),
                (None, None) => None,
            };
            if let Some(kind) = kind {
                changed_paths += 1;
                if cursor
                    .as_ref()
                    .is_none_or(|cursor| path.as_path() > cursor.as_path())
                {
                    remaining_changed_paths += 1;
                }
                if cursor
                    .as_ref()
                    .is_none_or(|cursor| path.as_path() > cursor.as_path())
                    && changes.len() < max_changes
                {
                    changes.push(SnapshotChange { path, kind });
                }
            }
        }
        let truncated = changes.len() < remaining_changed_paths;
        let next_path = truncated
            .then(|| changes.last().map(|change| change.path.clone()))
            .flatten();
        Ok(SnapshotDiff {
            truncated,
            changes,
            changed_paths,
            next_path,
        })
    }

    /// Atomically materialize this snapshot at a new destination path.
    pub fn materialize(&self, destination: impl AsRef<Path>) -> Result<(), SnapshotError> {
        self.ensure_live()?;
        let destination = destination.as_ref();
        let parent = destination.parent().ok_or_else(|| {
            SnapshotError::InvalidPath("materialize destination has no parent".to_string())
        })?;
        let destination_name = destination.file_name().ok_or_else(|| {
            SnapshotError::InvalidPath("materialize destination has no file name".to_string())
        })?;
        let parent_dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
            .map_err(|error| operation("open materialize parent", error))?;
        let staging_name = format!(".sandlock-materialize-{}.tmp", uuid::Uuid::new_v4());
        mkdirat_private(parent_dir.as_raw_fd(), std::ffi::OsStr::new(&staging_name))?;
        let staging = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            parent_dir.as_raw_fd(),
            staging_name
        ));
        let mut cleanup = StagingCleanup::new(staging.clone());
        let payload = staging.join("payload");
        create_private_directory(&payload)?;
        let source_modes = self.directory_modes()?;
        let modes = copy_tree_with_modes(&self.tree_dir, &payload, Some(&source_modes))?;
        finalize_directories(&payload, &modes)?;
        sync_directory(&payload)?;
        let source_name = Path::new(&staging_name).join("payload");
        rename_noreplace_at(parent_dir.as_raw_fd(), &source_name, destination_name)
            .map_err(|error| operation("publish materialized snapshot", error))?;
        #[cfg(test)]
        if FAIL_AFTER_MATERIALIZE_PUBLISH.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(SnapshotError::Materialized {
                destination: destination.to_path_buf(),
                message: "injected failure after destination publication".to_string(),
            });
        }
        fs::remove_dir(&staging).map_err(|error| SnapshotError::Materialized {
            destination: destination.to_path_buf(),
            message: format!("remove materialize staging wrapper: {error}"),
        })?;
        cleanup.published = true;
        if let Err(error) = parent_dir.sync_all() {
            return Err(SnapshotError::Materialized {
                destination: destination.to_path_buf(),
                message: format!("sync materialize parent: {error}"),
            });
        }
        Ok(())
    }

    /// Destroy an unreferenced snapshot.
    ///
    /// Snapshot-backed branches hold durable lease records. Stale leases whose
    /// branch storage is already gone are pruned; any live branch storage makes
    /// destruction fail conservatively.
    pub fn destroy(&mut self) -> Result<(), SnapshotError> {
        self.ensure_live()?;
        let _lock = lock_snapshot_leases(&self.descriptor.snapshot_dir)?;
        let own_lease = self.handle_lease.as_ref().map(|lease| lease.path.clone());
        let leases = self.descriptor.snapshot_dir.join(SNAPSHOT_LEASES);
        let mut in_use = 0;
        for entry in
            fs::read_dir(&leases).map_err(|error| operation("list snapshot leases", error))?
        {
            let entry = entry.map_err(|error| operation("read snapshot lease", error))?;
            if own_lease.as_ref() == Some(&entry.path()) {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|error| operation("inspect snapshot lease", error))?
                .is_file()
            {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot lease is not a regular file".to_string(),
                ));
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(HANDLE_LEASE_PREFIX) {
                let file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(entry.path())
                    .map_err(|error| operation("open snapshot handle lease", error))?;
                let result =
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if result == 0 {
                    fs::remove_file(entry.path())
                        .map_err(|error| operation("prune stale snapshot handle lease", error))?;
                } else {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        in_use += 1;
                    } else {
                        return Err(operation("inspect snapshot handle lease", error));
                    }
                }
                continue;
            }
            if !name.starts_with(BRANCH_LEASE_PREFIX) {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot lease has an unknown kind".to_string(),
                ));
            }
            let bytes =
                fs::read(entry.path()).map_err(|error| operation("read snapshot lease", error))?;
            let record: SnapshotLeaseRecord = serde_json::from_slice(&bytes).map_err(|error| {
                SnapshotError::InvalidDescriptor(format!("parse snapshot lease: {error}"))
            })?;
            validate_lease_id(&record.lease_id)?;
            if entry.file_name()
                != std::ffi::OsString::from(format!(
                    "{BRANCH_LEASE_PREFIX}{}.json",
                    record.lease_id
                ))
            {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot lease filename does not match its record".to_string(),
                ));
            }
            if record.snapshot_dir != self.descriptor.snapshot_dir {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot lease refers to a different snapshot".to_string(),
                ));
            }
            let lease_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(entry.path())
                .map_err(|error| operation("open snapshot branch lease", error))?;
            let lease_locked =
                unsafe { libc::flock(lease_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            let lease_is_live = if lease_locked == 0 {
                false
            } else {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    true
                } else {
                    return Err(operation("inspect snapshot branch lease", error));
                }
            };
            match fs::symlink_metadata(&record.branch_dir) {
                Ok(_) if lease_is_live => in_use += 1,
                Ok(_) if branch_has_recovery_marker(&record.branch_dir) => in_use += 1,
                Ok(_) => {
                    make_tree_removable(&record.branch_dir).map_err(|error| {
                        operation("prepare orphaned branch storage removal", error)
                    })?;
                    fs::remove_dir_all(&record.branch_dir)
                        .map_err(|error| operation("remove orphaned branch storage", error))?;
                    fs::remove_file(entry.path())
                        .map_err(|error| operation("prune orphaned branch lease", error))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::remove_file(entry.path())
                        .map_err(|error| operation("prune stale snapshot branch lease", error))?;
                }
                Err(error) => return Err(operation("inspect leased branch storage", error)),
            }
        }
        if in_use != 0 {
            return Err(SnapshotError::InUse { count: in_use });
        }
        if self.handle_lease.is_none() {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot handle lease is unavailable".to_string(),
            ));
        }
        let published_descriptor = self.descriptor.clone();

        // Atomically remove the snapshot from the discoverable namespace
        // before touching its tree. The dot-prefixed tombstone is ignored by
        // discovery, and the original descriptor can no longer be reopened.
        // A crash or partial recursive removal can therefore leave garbage to
        // reclaim without ever presenting a damaged tree as a valid revision.
        let tombstone = self
            .descriptor
            .snapshot_dir
            .parent()
            .ok_or_else(|| {
                SnapshotError::InvalidDescriptor("snapshot directory has no parent".to_string())
            })?
            .join(format!(".{}.destroying", self.descriptor.id));
        if let Err(error) = rename_noreplace(&self.descriptor.snapshot_dir, &tombstone) {
            return Err(operation("publish snapshot destruction tombstone", error));
        }
        self.descriptor.snapshot_dir = tombstone.clone();
        self.tree_dir = tombstone.join(SNAPSHOT_TREE);
        if let Some(lease) = self.handle_lease.as_mut() {
            lease.path = tombstone
                .join(SNAPSHOT_LEASES)
                .join(lease.path.file_name().expect("handle lease has a filename"));
        }
        if let Some(parent) = tombstone.parent() {
            if let Err(error) = sync_directory(parent) {
                self.destroyed = true;
                return Err(SnapshotError::Destroyed {
                    descriptor: Box::new(published_descriptor.clone()),
                    message: format!("sync snapshot destruction tombstone: {error}"),
                });
            }
        }
        #[cfg(test)]
        if FAIL_AFTER_DESTROY_TOMBSTONE.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: "injected failure after destruction tombstone".to_string(),
            });
        }

        // Teardown is deliberately ordered so the named handle lease remains
        // visible until all snapshot data and metadata have been removed. A
        // recursive removal of the snapshot root could unlink the lease first
        // and then fail halfway through the tree, making a partial snapshot
        // appear unleased to another process.
        let own_lease = self
            .handle_lease
            .as_ref()
            .map(|lease| lease.path.clone())
            .expect("a live snapshot has a handle lease");
        let leases = self.descriptor.snapshot_dir.join(SNAPSHOT_LEASES);
        let tree = self.descriptor.snapshot_dir.join(SNAPSHOT_TREE);
        if let Err(error) = make_tree_removable(&tree) {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: format!("prepare snapshot tree removal: {error}"),
            });
        }
        if let Err(error) = fs::remove_dir_all(&tree) {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: format!("remove snapshot tree: {error}"),
            });
        }
        if let Err(error) = fs::remove_file(self.descriptor.snapshot_dir.join(SNAPSHOT_METADATA)) {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: format!("remove snapshot metadata: {error}"),
            });
        }
        if let Err(error) = fs::remove_file(self.descriptor.snapshot_dir.join(SNAPSHOT_INDEX)) {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: format!("remove snapshot index: {error}"),
            });
        }
        if let Err(error) =
            fs::remove_file(self.descriptor.snapshot_dir.join(SNAPSHOT_DIRECTORY_MODES))
        {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: format!("remove snapshot directory modes: {error}"),
            });
        }
        if let Err(error) = fs::remove_file(&own_lease) {
            self.destroyed = true;
            return Err(SnapshotError::Destroyed {
                descriptor: Box::new(published_descriptor.clone()),
                message: format!("remove final snapshot handle lease: {error}"),
            });
        }
        if let Some(lease) = self.handle_lease.as_mut() {
            // The file is already deliberately unlinked. Prevent Drop from
            // trying to take the same lease lock recursively while destroy
            // still holds it.
            lease.path = PathBuf::new();
        }
        self.handle_lease = None;
        for (path, context) in [
            (leases, "remove snapshot lease directory"),
            (
                self.descriptor.snapshot_dir.join(SNAPSHOT_LEASE_LOCK),
                "remove snapshot lease lock",
            ),
            (
                self.descriptor.snapshot_dir.clone(),
                "remove snapshot directory",
            ),
        ] {
            let result = if path == self.descriptor.snapshot_dir.join(SNAPSHOT_LEASE_LOCK) {
                fs::remove_file(&path)
            } else {
                fs::remove_dir(&path)
            };
            if matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
                && path == self.descriptor.snapshot_dir
            {
                continue;
            }
            if let Err(error) = result {
                self.destroyed = true;
                return Err(SnapshotError::Destroyed {
                    descriptor: Box::new(published_descriptor.clone()),
                    message: format!("{context}: {error}"),
                });
            }
        }
        if let Some(parent) = self.descriptor.snapshot_dir.parent() {
            if let Err(error) = sync_directory(parent) {
                self.destroyed = true;
                return Err(SnapshotError::Destroyed {
                    descriptor: Box::new(published_descriptor.clone()),
                    message: error.to_string(),
                });
            }
        }
        self.destroyed = true;
        Ok(())
    }

    pub(crate) fn checkpoint_branch(
        source: &Path,
        source_snapshot_dir: Option<&Path>,
        source_directory_modes: &BTreeMap<PathBuf, u32>,
        upper: &Path,
        deleted: impl IntoIterator<Item = String>,
        directory_modes: impl IntoIterator<Item = (String, u32)>,
        storage: &Path,
    ) -> Result<Self, SnapshotError> {
        let canonical_source = source
            .canonicalize()
            .map_err(|error| operation("canonicalize branch lower", error))?;
        let canonical_upper = upper
            .canonicalize()
            .map_err(|error| operation("canonicalize branch upper", error))?;
        if canonical_upper.starts_with(&canonical_source) {
            return Err(SnapshotError::Operation(
                "branch upper must not be inside its lower".to_string(),
            ));
        }
        let deleted = deleted.into_iter().collect::<Vec<_>>();
        let directory_modes = directory_modes
            .into_iter()
            .map(|(path, mode)| (PathBuf::from(path), mode))
            .collect::<BTreeMap<_, _>>();
        let source_index = source_snapshot_dir
            .map(|snapshot_dir| {
                let metadata = read_metadata(snapshot_dir)?;
                read_index(snapshot_dir, metadata.root_hash)
            })
            .transpose()?;
        capture_with_overlay(
            &canonical_source,
            storage,
            Some(source_directory_modes),
            source_index.as_ref(),
            move |root, modes| {
                apply_deletions(root, &deleted, modes)?;
                apply_upper(root, &canonical_upper, &directory_modes, modes)?;
                Ok(SnapshotIndexUpdate::Branch {
                    upper: canonical_upper,
                    deleted: deleted.into_iter().map(PathBuf::from).collect(),
                    changed_directories: directory_modes.into_keys().collect(),
                })
            },
        )
    }

    pub(crate) fn acquire_branch_lease(
        &self,
        branch_dir: &Path,
    ) -> Result<SnapshotLease, SnapshotError> {
        self.ensure_live()?;
        let _lock = lock_snapshot_leases(&self.descriptor.snapshot_dir)?;
        let lease_id = uuid::Uuid::new_v4().to_string();
        let branch_dir = branch_dir
            .canonicalize()
            .map_err(|error| operation("canonicalize leased branch storage", error))?;
        let path = self
            .descriptor
            .snapshot_dir
            .join(SNAPSHOT_LEASES)
            .join(format!("{BRANCH_LEASE_PREFIX}{lease_id}.json"));
        let record = SnapshotLeaseRecord {
            snapshot_dir: self.descriptor.snapshot_dir.clone(),
            branch_dir,
            lease_id,
        };
        write_json_new(&path, &record)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| operation("open new snapshot branch lease", error))?;
        lock_shared(&file, "lock new snapshot branch lease")?;
        sync_directory(path.parent().expect("lease has a parent"))?;
        Ok(SnapshotLease {
            record,
            path,
            _file: file,
        })
    }

    fn ensure_live(&self) -> Result<(), SnapshotError> {
        if self.destroyed {
            Err(SnapshotError::AlreadyDestroyed)
        } else {
            Ok(())
        }
    }
}

fn reap_destroy_tombstone(path: &Path, name: &std::ffi::OsStr) -> Result<(), SnapshotError> {
    let Some(name) = name.to_str() else {
        return Ok(());
    };
    let Some(id) = name
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".destroying"))
    else {
        return Ok(());
    };
    let parsed = uuid::Uuid::parse_str(id).map_err(|error| {
        SnapshotError::InvalidDescriptor(format!("invalid snapshot tombstone id: {error}"))
    })?;
    if parsed.to_string() != id {
        return Err(SnapshotError::InvalidDescriptor(
            "snapshot tombstone id is not canonical".to_string(),
        ));
    }
    validate_plain_directory(path, "snapshot destruction tombstone")?;
    let tombstone_lock = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.join(SNAPSHOT_LEASE_LOCK))
    {
        Ok(lock) => {
            let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                return Err(operation("lock snapshot tombstone for reaping", error));
            }
            Some(lock)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(operation("open snapshot tombstone lock", error)),
    };
    match fs::symlink_metadata(path.join(SNAPSHOT_METADATA)) {
        Ok(_) => {
            let metadata = read_metadata(path)?;
            if metadata.id != id {
                return Err(SnapshotError::InvalidDescriptor(
                    "snapshot tombstone does not match its metadata".to_string(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(operation("inspect snapshot tombstone metadata", error)),
    }
    let tree = path.join(SNAPSHOT_TREE);
    match fs::symlink_metadata(&tree) {
        Ok(_) => make_tree_removable(&tree)
            .map_err(|error| operation("prepare snapshot tombstone removal", error))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(operation("inspect snapshot tombstone tree", error)),
    }
    fs::remove_dir_all(path).map_err(|error| operation("reap snapshot tombstone", error))?;
    drop(tombstone_lock);
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

/// Durable link from a snapshot to one branch using it as a lower.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SnapshotLeaseRecord {
    snapshot_dir: PathBuf,
    branch_dir: PathBuf,
    lease_id: String,
}

#[derive(Debug)]
pub(crate) struct SnapshotLease {
    record: SnapshotLeaseRecord,
    path: PathBuf,
    _file: fs::File,
}

#[derive(Debug)]
struct SnapshotHandleLease {
    path: PathBuf,
    _file: fs::File,
}

impl Drop for SnapshotHandleLease {
    fn drop(&mut self) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let snapshot_dir = self
            .path
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        if let Some(snapshot_dir) = snapshot_dir {
            let lock = lock_snapshot_leases(&snapshot_dir);
            if lock.is_ok() && fs::remove_file(&self.path).is_ok() {
                if let Some(parent) = self.path.parent() {
                    let _ = sync_directory(parent);
                }
            }
        }
    }
}

fn acquire_handle_lease(
    descriptor: &FsSnapshotDescriptor,
) -> Result<SnapshotHandleLease, SnapshotError> {
    let _lock = lock_snapshot_leases(&descriptor.snapshot_dir)?;
    let lease_id = uuid::Uuid::new_v4().to_string();
    let path = descriptor
        .snapshot_dir
        .join(SNAPSHOT_LEASES)
        .join(format!("{HANDLE_LEASE_PREFIX}{lease_id}"));
    let lease = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| operation("create snapshot handle lease", error))?;
    loop {
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_SH) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(operation("lock snapshot handle lease", error));
        }
    }
    lease
        .sync_all()
        .map_err(|error| operation("sync snapshot handle lease", error))?;
    sync_directory(path.parent().expect("handle lease has a parent"))?;
    Ok(SnapshotHandleLease { path, _file: lease })
}

impl SnapshotLease {
    pub(crate) fn record(&self) -> &SnapshotLeaseRecord {
        &self.record
    }

    pub(crate) fn snapshot_dir(&self) -> &Path {
        &self.record.snapshot_dir
    }

    pub(crate) fn from_record(record: SnapshotLeaseRecord) -> Result<Self, SnapshotError> {
        validate_lease_id(&record.lease_id)?;
        let snapshot_dir = record.snapshot_dir.canonicalize().map_err(|error| {
            SnapshotError::InvalidDescriptor(format!(
                "canonicalize snapshot branch lease root: {error}"
            ))
        })?;
        let branch_dir = record.branch_dir.canonicalize().map_err(|error| {
            SnapshotError::InvalidDescriptor(format!("canonicalize leased branch storage: {error}"))
        })?;
        if snapshot_dir != record.snapshot_dir || branch_dir != record.branch_dir {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot branch lease paths are not canonical".to_string(),
            ));
        }
        let path = record
            .snapshot_dir
            .join(SNAPSHOT_LEASES)
            .join(format!("{BRANCH_LEASE_PREFIX}{}.json", record.lease_id));
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| operation("open snapshot branch lease", error))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| operation("read snapshot branch lease", error))?;
        let recorded: SnapshotLeaseRecord = serde_json::from_slice(&bytes).map_err(|error| {
            SnapshotError::InvalidDescriptor(format!("parse snapshot lease: {error}"))
        })?;
        if recorded.snapshot_dir != record.snapshot_dir
            || recorded.branch_dir != record.branch_dir
            || recorded.lease_id != record.lease_id
        {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot branch lease changed before reopen".to_string(),
            ));
        }
        lock_shared(&file, "lock snapshot branch lease")?;
        Ok(Self {
            record,
            path,
            _file: file,
        })
    }

    pub(crate) fn release(&self) -> Result<(), SnapshotError> {
        let _lock = lock_snapshot_leases(&self.record.snapshot_dir)?;
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(operation("release snapshot branch lease", error)),
        }
        sync_directory(self.path.parent().expect("branch lease has a parent"))
    }
}

fn validate_lease_id(lease_id: &str) -> Result<(), SnapshotError> {
    let parsed = uuid::Uuid::parse_str(lease_id).map_err(|error| {
        SnapshotError::InvalidDescriptor(format!("invalid snapshot lease id: {error}"))
    })?;
    if parsed.to_string() != lease_id {
        return Err(SnapshotError::InvalidDescriptor(
            "snapshot lease id is not canonical".to_string(),
        ));
    }
    Ok(())
}

fn lock_shared(file: &fs::File, context: &str) -> Result<(), SnapshotError> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(operation(context, error));
        }
    }
}

fn branch_has_recovery_marker(branch_dir: &Path) -> bool {
    fs::symlink_metadata(branch_dir.join(BRANCH_PRESERVED_MARKER))
        .is_ok_and(|metadata| metadata.file_type().is_file())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryStamp {
    kind: SnapshotEntryKind,
    mode: u32,
    len: u64,
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    symlink_target: Option<PathBuf>,
}

fn capture_with_overlay(
    source: &Path,
    storage: &Path,
    source_directory_modes: Option<&BTreeMap<PathBuf, u32>>,
    source_index: Option<&SnapshotIndex>,
    overlay: impl FnOnce(
        &Path,
        &mut BTreeMap<PathBuf, u32>,
    ) -> Result<SnapshotIndexUpdate, SnapshotError>,
) -> Result<FsSnapshot, SnapshotError> {
    let source = source
        .canonicalize()
        .map_err(|error| operation("canonicalize snapshot source", error))?;
    validate_plain_directory(&source, "snapshot source")?;
    ensure_storage_base(storage)?;
    let storage = storage
        .canonicalize()
        .map_err(|error| operation("canonicalize snapshot storage", error))?;
    if storage.starts_with(&source) {
        return Err(SnapshotError::Operation(format!(
            "snapshot storage must not be inside its source: {}",
            storage.display()
        )));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let staging = storage.join(format!(".{id}.tmp"));
    let snapshot_dir = storage.join(&id);
    let mut cleanup = StagingCleanup::new(staging.clone());
    create_private_directory(&staging)?;
    let tree_dir = staging.join(SNAPSHOT_TREE);
    fs::create_dir(&tree_dir).map_err(|error| operation("create snapshot tree", error))?;
    fs::create_dir(staging.join(SNAPSHOT_LEASES))
        .map_err(|error| operation("create snapshot lease directory", error))?;
    let lease_lock = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging.join(SNAPSHOT_LEASE_LOCK))
        .map_err(|error| operation("create snapshot lease lock", error))?;
    lease_lock
        .sync_all()
        .map_err(|error| operation("sync snapshot lease lock", error))?;

    let before = inventory(&source)?;
    let mut directory_modes = copy_tree_with_modes(&source, &tree_dir, source_directory_modes)?;
    let after = inventory(&source)?;
    if before != after {
        return Err(SnapshotError::SourceChanged);
    }
    let index_update = overlay(&tree_dir, &mut directory_modes)?;
    let final_source = inventory(&source)?;
    if before != final_source {
        return Err(SnapshotError::SourceChanged);
    }
    // Validate the final view and enforce the same hard entry/path budgets
    // used by inspection before publishing it as a complete snapshot. Do so
    // while staged directories still have owner traversal rights; final modes
    // such as 0000 are applied only after all recursive validation is done.
    let _ = inventory(&tree_dir)?;
    let index = match (source_index, index_update) {
        (Some(index), SnapshotIndexUpdate::None) => index.clone(),
        (Some(index), SnapshotIndexUpdate::RefreshPaths(paths)) => {
            index.refresh_paths(&tree_dir, &directory_modes, paths)?
        }
        (
            Some(index),
            SnapshotIndexUpdate::Branch {
                upper,
                deleted,
                changed_directories,
            },
        ) => index.apply_branch(
            &tree_dir,
            &directory_modes,
            &upper,
            &deleted,
            &changed_directories,
        )?,
        (None, _) => SnapshotIndex::build(&tree_dir, &directory_modes)?,
    };
    let root_hash = index.root_hash()?;
    index.write(&staging.join(SNAPSHOT_INDEX))?;
    write_json_new(&staging.join(SNAPSHOT_DIRECTORY_MODES), &directory_modes)?;

    let metadata = SnapshotMetadata {
        id: id.clone(),
        root_hash,
    };
    write_json_new(&staging.join(SNAPSHOT_METADATA), &metadata)?;
    sync_directory(&staging.join(SNAPSHOT_LEASES))?;
    sync_directory(&staging)?;
    rename_noreplace(&staging, &snapshot_dir)
        .map_err(|error| operation("publish snapshot", error))?;
    cleanup.published = true;

    let descriptor = FsSnapshotDescriptor {
        snapshot_dir: snapshot_dir.clone(),
        id,
    };
    #[cfg(test)]
    if FAIL_AFTER_SNAPSHOT_PUBLISH.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err(SnapshotError::Published {
            descriptor: Box::new(descriptor),
            message: "injected failure after snapshot publication".to_string(),
        });
    }
    if let Err(error) = sync_directory(&storage) {
        return Err(SnapshotError::Published {
            descriptor: Box::new(descriptor),
            message: error.to_string(),
        });
    }
    let handle_lease =
        acquire_handle_lease(&descriptor).map_err(|error| SnapshotError::Published {
            descriptor: Box::new(descriptor.clone()),
            message: format!("establish initial snapshot handle: {error}"),
        })?;
    Ok(FsSnapshot {
        descriptor,
        tree_dir: snapshot_dir.join(SNAPSHOT_TREE),
        root_hash,
        handle_lease: Some(handle_lease),
        destroyed: false,
    })
}

fn ensure_storage_base(storage: &Path) -> Result<(), SnapshotError> {
    match fs::symlink_metadata(storage) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            Ok(())
        }
        Ok(_) => Err(SnapshotError::Operation(format!(
            "snapshot storage is not a plain directory: {}",
            storage.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(storage)
                .map_err(|error| operation("create snapshot storage", error))?;
            validate_plain_directory(storage, "snapshot storage")
        }
        Err(error) => Err(operation("inspect snapshot storage", error)),
    }
}

fn create_private_directory(path: &Path) -> Result<(), SnapshotError> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| operation("create private snapshot directory", error))
}

fn validate_plain_directory(path: &Path, label: &str) -> Result<(), SnapshotError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SnapshotError::InvalidDescriptor(format!("inspect {label}: {error}")))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(SnapshotError::InvalidDescriptor(format!(
            "{label} is not a plain directory"
        )));
    }
    Ok(())
}

fn validate_plain_file(path: &Path, label: &str) -> Result<(), SnapshotError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SnapshotError::InvalidDescriptor(format!("inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SnapshotError::InvalidDescriptor(format!(
            "{label} is not a plain file"
        )));
    }
    Ok(())
}

fn lock_snapshot_leases(snapshot_dir: &Path) -> Result<fs::File, SnapshotError> {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(snapshot_dir.join(SNAPSHOT_LEASE_LOCK))
        .map_err(|error| operation("open snapshot lease lock", error))?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(lock);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(operation("lock snapshot leases", error));
        }
    }
}

fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let destination = std::ffi::CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn mkdirat_private(parent_fd: i32, name: &std::ffi::OsStr) -> Result<(), SnapshotError> {
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| SnapshotError::InvalidPath("directory name contains NUL".to_string()))?;
    if unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(operation(
            "create private materialize staging",
            std::io::Error::last_os_error(),
        ))
    }
}

fn rename_noreplace_at(
    parent_fd: i32,
    source: &Path,
    destination: &std::ffi::OsStr,
) -> std::io::Result<()> {
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let destination = std::ffi::CString::new(destination.as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent_fd,
            source.as_ptr(),
            parent_fd,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn copy_tree_with_modes(
    source: &Path,
    destination: &Path,
    source_directory_modes: Option<&BTreeMap<PathBuf, u32>>,
) -> Result<BTreeMap<PathBuf, u32>, SnapshotError> {
    let root_metadata =
        fs::symlink_metadata(source).map_err(|error| operation("inspect source root", error))?;
    if !root_metadata.file_type().is_dir() {
        return Err(SnapshotError::UnsupportedFileType(PathBuf::new()));
    }
    let empty_modes = BTreeMap::new();
    let backend_directory_modes = source_directory_modes.unwrap_or(&empty_modes);
    let mut directory_modes = BTreeMap::new();
    directory_modes.insert(
        PathBuf::new(),
        backend_directory_modes
            .get(Path::new(""))
            .copied()
            .unwrap_or(root_metadata.mode() & 0o7777),
    );

    let entries = walkdir::WalkDir::new(source)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    for entry in entries {
        let entry =
            entry.map_err(|error| SnapshotError::Operation(format!("walk source: {error}")))?;
        let rel = entry
            .path()
            .strip_prefix(source)
            .expect("walk entry is below source");
        let target = destination.join(rel);
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| operation("inspect source entry", error))?;
        if metadata.file_type().is_dir() {
            create_private_directory(&target)?;
            directory_modes.insert(
                rel.to_path_buf(),
                backend_directory_modes
                    .get(rel)
                    .copied()
                    .unwrap_or(metadata.mode() & 0o7777),
            );
        } else if metadata.file_type().is_file() {
            copy_regular_file(entry.path(), &target, metadata.mode() & 0o7777)?;
        } else if metadata.file_type().is_symlink() {
            let link = fs::read_link(entry.path())
                .map_err(|error| operation("read source symlink", error))?;
            std::os::unix::fs::symlink(link, &target)
                .map_err(|error| operation("copy source symlink", error))?;
        } else {
            return Err(SnapshotError::UnsupportedFileType(rel.to_path_buf()));
        }
    }
    Ok(directory_modes)
}

fn read_backend_directory_modes(
    tree: &Path,
) -> Result<Option<BTreeMap<PathBuf, u32>>, SnapshotError> {
    let Some(snapshot_dir) = tree.parent() else {
        return Ok(None);
    };
    if tree.file_name() != Some(std::ffi::OsStr::new(SNAPSHOT_TREE)) {
        return Ok(None);
    }
    let path = snapshot_dir.join(SNAPSHOT_DIRECTORY_MODES);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(operation("read snapshot directory modes", error)),
    };
    let modes: BTreeMap<PathBuf, u32> = serde_json::from_slice(&bytes).map_err(|error| {
        SnapshotError::InvalidDescriptor(format!("parse snapshot directory modes: {error}"))
    })?;
    Ok(Some(modes))
}

pub(crate) fn copy_regular_file(
    source: &Path,
    destination: &Path,
    mode: u32,
) -> Result<(), SnapshotError> {
    copy_regular_file_inner(source, destination, mode, true).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileCopyMethod {
    Reflink,
    Buffered,
}

fn copy_regular_file_inner(
    source: &Path,
    destination: &Path,
    mode: u32,
    try_reflink: bool,
) -> Result<FileCopyMethod, SnapshotError> {
    let before = fs::symlink_metadata(source)
        .map_err(|error| operation("inspect source file before copy", error))?;
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| operation("open source file", error))?;
    let opened_before = input
        .metadata()
        .map_err(|error| operation("inspect opened source file", error))?;
    if file_identity(&before) != file_identity(&opened_before) {
        return Err(SnapshotError::SourceChanged);
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)
        .map_err(|error| operation("create snapshot file", error))?;
    let method = if try_reflink && reflink_file(&input, &output)? {
        FileCopyMethod::Reflink
    } else {
        input
            .seek(SeekFrom::Start(0))
            .map_err(|error| operation("rewind snapshot source", error))?;
        output
            .seek(SeekFrom::Start(0))
            .map_err(|error| operation("rewind snapshot destination", error))?;
        output
            .set_len(0)
            .map_err(|error| operation("reset snapshot destination", error))?;
        std::io::copy(&mut input, &mut output)
            .map_err(|error| operation("copy snapshot file", error))?;
        FileCopyMethod::Buffered
    };
    let opened_after = input
        .metadata()
        .map_err(|error| operation("inspect copied source file", error))?;
    let path_after = fs::symlink_metadata(source)
        .map_err(|error| operation("inspect source file after copy", error))?;
    if file_identity(&before) != file_identity(&opened_after)
        || file_identity(&before) != file_identity(&path_after)
    {
        return Err(SnapshotError::SourceChanged);
    }
    output
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| operation("set snapshot file mode", error))?;
    output
        .sync_all()
        .map_err(|error| operation("sync snapshot file", error))?;
    Ok(method)
}

#[cfg(target_os = "linux")]
fn reflink_file(source: &fs::File, destination: &fs::File) -> Result<bool, SnapshotError> {
    const FICLONE_IOCTL: libc::c_ulong = 0x4004_9409;
    let result = unsafe { libc::ioctl(destination.as_raw_fd(), FICLONE_IOCTL, source.as_raw_fd()) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(errno)
            if matches!(
                errno,
                libc::EOPNOTSUPP
                    | libc::ENOTTY
                    | libc::EXDEV
                    | libc::EINVAL
                    | libc::ENOSYS
                    | libc::EPERM
                    | libc::EACCES
            )
    ) {
        Ok(false)
    } else {
        Err(operation("reflink snapshot file", error))
    }
}

#[cfg(not(target_os = "linux"))]
fn reflink_file(_source: &fs::File, _destination: &fs::File) -> Result<bool, SnapshotError> {
    Ok(false)
}

fn file_identity(metadata: &fs::Metadata) -> (u64, u64, u32, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn finalize_directories(
    root: &Path,
    directory_modes: &BTreeMap<PathBuf, u32>,
) -> Result<(), SnapshotError> {
    for (rel, mode) in directory_modes.iter().rev() {
        let path = root.join(rel);
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| operation("open snapshot directory for finalization", error))?;
        directory
            .set_permissions(fs::Permissions::from_mode(*mode))
            .map_err(|error| operation("set snapshot directory mode", error))?;
        directory
            .sync_all()
            .map_err(|error| operation("sync snapshot directory", error))?;
    }
    Ok(())
}

fn apply_deletions(
    root: &Path,
    deleted: &[String],
    directory_modes: &mut BTreeMap<PathBuf, u32>,
) -> Result<(), SnapshotError> {
    for rel in deleted {
        let path = PathBuf::from(rel);
        let metadata = crate::sys::fs::statat_in_root(root, rel, false);
        let result = match metadata {
            Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFDIR => {
                crate::sys::fs::remove_dir_all_in_root(root, rel)
            }
            Ok(_) => crate::sys::fs::unlinkat_in_root(root, rel, false),
            Err(libc::ENOENT) => Ok(()),
            Err(errno) => Err(errno),
        };
        result.map_err(|errno| {
            SnapshotError::Operation(format!(
                "apply branch deletion {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(errno)
            ))
        })?;
        directory_modes.retain(|candidate, _| candidate != &path && !candidate.starts_with(&path));
    }
    Ok(())
}

fn apply_upper(
    root: &Path,
    upper: &Path,
    upper_directory_modes: &BTreeMap<PathBuf, u32>,
    directory_modes: &mut BTreeMap<PathBuf, u32>,
) -> Result<(), SnapshotError> {
    if let Some(mode) = upper_directory_modes
        .get(Path::new(""))
        .or_else(|| upper_directory_modes.get(Path::new(".")))
    {
        directory_modes.insert(PathBuf::new(), *mode);
    }
    let entries = walkdir::WalkDir::new(upper)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    for entry in entries {
        let entry = entry
            .map_err(|error| SnapshotError::Operation(format!("walk branch upper: {error}")))?;
        let rel = entry
            .path()
            .strip_prefix(upper)
            .expect("upper entry is below upper");
        let rel_str = rel.to_str().ok_or_else(|| {
            SnapshotError::InvalidPath(format!("branch path is not valid UTF-8: {}", rel.display()))
        })?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| operation("inspect branch upper entry", error))?;
        if metadata.file_type().is_dir() {
            ensure_overlay_directory(root, rel_str)?;
            if let Some(mode) = upper_directory_modes.get(rel) {
                directory_modes.insert(rel.to_path_buf(), *mode & 0o7777);
            }
            continue;
        }

        remove_overlay_entry(root, rel_str)?;
        if let Some(parent) = rel.parent().and_then(Path::to_str) {
            crate::sys::fs::mkdirp_in_root(root, parent, 0o700).map_err(|errno| {
                SnapshotError::Operation(format!(
                    "create snapshot overlay parent: {}",
                    std::io::Error::from_raw_os_error(errno)
                ))
            })?;
        }
        directory_modes.retain(|candidate, _| candidate != rel && !candidate.starts_with(rel));
        let target = root.join(rel);
        if metadata.file_type().is_file() {
            copy_regular_file(entry.path(), &target, metadata.mode() & 0o7777)?;
        } else if metadata.file_type().is_symlink() {
            let link = fs::read_link(entry.path())
                .map_err(|error| operation("read branch symlink", error))?;
            std::os::unix::fs::symlink(link, &target)
                .map_err(|error| operation("copy branch symlink", error))?;
        } else {
            return Err(SnapshotError::UnsupportedFileType(rel.to_path_buf()));
        }
    }
    Ok(())
}

fn ensure_overlay_directory(root: &Path, rel: &str) -> Result<(), SnapshotError> {
    match crate::sys::fs::statat_in_root(root, rel, false) {
        Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFDIR => Ok(()),
        Ok(stat) => {
            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                crate::sys::fs::remove_dir_all_in_root(root, rel)
            } else {
                crate::sys::fs::unlinkat_in_root(root, rel, false)
            }
            .map_err(|errno| operation_errno("replace snapshot overlay directory", errno))?;
            if let Some(parent) = Path::new(rel).parent().and_then(Path::to_str) {
                crate::sys::fs::mkdirp_in_root(root, parent, 0o700)
                    .map_err(|errno| operation_errno("create snapshot overlay parent", errno))?;
            }
            crate::sys::fs::mkdir_in_root(root, rel, 0o700)
                .map_err(|errno| operation_errno("create snapshot overlay directory", errno))
        }
        Err(libc::ENOENT) => {
            if let Some(parent) = Path::new(rel).parent().and_then(Path::to_str) {
                crate::sys::fs::mkdirp_in_root(root, parent, 0o700)
                    .map_err(|errno| operation_errno("create snapshot overlay parent", errno))?;
            }
            crate::sys::fs::mkdir_in_root(root, rel, 0o700)
                .map_err(|errno| operation_errno("create snapshot overlay directory", errno))
        }
        Err(errno) => Err(operation_errno("inspect snapshot overlay directory", errno)),
    }
}

fn remove_overlay_entry(root: &Path, rel: &str) -> Result<(), SnapshotError> {
    match crate::sys::fs::statat_in_root(root, rel, false) {
        Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFDIR => {
            crate::sys::fs::remove_dir_all_in_root(root, rel)
                .map_err(|errno| operation_errno("remove snapshot overlay directory", errno))
        }
        Ok(_) => crate::sys::fs::unlinkat_in_root(root, rel, false)
            .map_err(|errno| operation_errno("remove snapshot overlay entry", errno)),
        Err(libc::ENOENT) => Ok(()),
        Err(errno) => Err(operation_errno("inspect snapshot overlay entry", errno)),
    }
}

fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, EntryStamp>, SnapshotError> {
    inventory_bounded(
        root,
        DEFAULT_SCAN_ENTRY_BUDGET,
        DEFAULT_SCAN_PATH_BYTE_BUDGET,
    )
}

fn inventory_bounded(
    root: &Path,
    max_entries: usize,
    max_path_bytes: usize,
) -> Result<BTreeMap<PathBuf, EntryStamp>, SnapshotError> {
    inventory_bounded_with_modes(root, max_entries, max_path_bytes, None)
}

fn inventory_bounded_with_modes(
    root: &Path,
    max_entries: usize,
    max_path_bytes: usize,
    source_directory_modes: Option<&BTreeMap<PathBuf, u32>>,
) -> Result<BTreeMap<PathBuf, EntryStamp>, SnapshotError> {
    let mut result = BTreeMap::new();
    let empty_modes = BTreeMap::new();
    let directory_modes = source_directory_modes.unwrap_or(&empty_modes);
    let mut path_bytes = 0_usize;
    let root_metadata =
        fs::symlink_metadata(root).map_err(|error| operation("inspect inventory root", error))?;
    let mut root_stamp = stamp(root, &root_metadata)?;
    if let Some(mode) = directory_modes.get(Path::new("")) {
        root_stamp.mode = *mode;
    }
    result.insert(PathBuf::new(), root_stamp);
    for entry in walkdir::WalkDir::new(root)
        .min_depth(1)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry =
            entry.map_err(|error| SnapshotError::Operation(format!("walk inventory: {error}")))?;
        if result.len() >= max_entries {
            return Err(SnapshotError::LimitExceeded(format!(
                "snapshot contains more than {max_entries} entries"
            )));
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("inventory entry is below root")
            .to_path_buf();
        path_bytes = path_bytes
            .checked_add(rel.as_os_str().as_bytes().len())
            .ok_or_else(|| {
                SnapshotError::LimitExceeded("snapshot path budget overflow".to_string())
            })?;
        if path_bytes > max_path_bytes {
            return Err(SnapshotError::LimitExceeded(format!(
                "snapshot path data exceeds {max_path_bytes} bytes"
            )));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| operation("inspect inventory entry", error))?;
        let mut entry_stamp = stamp(entry.path(), &metadata)?;
        if entry_stamp.kind == SnapshotEntryKind::Directory {
            if let Some(mode) = directory_modes.get(&rel) {
                entry_stamp.mode = *mode;
            }
        }
        result.insert(rel, entry_stamp);
    }
    Ok(result)
}

fn stamp(path: &Path, metadata: &fs::Metadata) -> Result<EntryStamp, SnapshotError> {
    let kind = if metadata.file_type().is_file() {
        SnapshotEntryKind::File
    } else if metadata.file_type().is_dir() {
        SnapshotEntryKind::Directory
    } else if metadata.file_type().is_symlink() {
        SnapshotEntryKind::Symlink
    } else {
        return Err(SnapshotError::UnsupportedFileType(path.to_path_buf()));
    };
    let symlink_target = if kind == SnapshotEntryKind::Symlink {
        Some(fs::read_link(path).map_err(|error| operation("read inventory symlink", error))?)
    } else {
        None
    };
    Ok(EntryStamp {
        kind,
        mode: metadata.mode() & 0o7777,
        len: metadata.len(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        symlink_target,
    })
}

fn snapshot_entry(root: &Path, path: &Path) -> Result<SnapshotEntry, SnapshotError> {
    let rel = normalize_relative(path)?;
    let full = contained_final_path(root, &rel)?;
    let metadata =
        fs::symlink_metadata(&full).map_err(|error| operation("inspect snapshot entry", error))?;
    let kind = if metadata.file_type().is_file() {
        SnapshotEntryKind::File
    } else if metadata.file_type().is_dir() {
        SnapshotEntryKind::Directory
    } else if metadata.file_type().is_symlink() {
        SnapshotEntryKind::Symlink
    } else {
        return Err(SnapshotError::UnsupportedFileType(rel));
    };
    let symlink_target = if kind == SnapshotEntryKind::Symlink {
        Some(fs::read_link(&full).map_err(|error| operation("read snapshot symlink", error))?)
    } else {
        None
    };
    let mode = if kind == SnapshotEntryKind::Directory {
        read_backend_directory_modes(root)?
            .and_then(|modes| modes.get(&rel).copied())
            .unwrap_or(metadata.mode() & 0o7777)
    } else {
        metadata.mode() & 0o7777
    };
    Ok(SnapshotEntry {
        path: rel,
        kind,
        mode,
        len: metadata.len(),
        symlink_target,
    })
}

fn indexed_change_kind(
    before: &SnapshotIndexEntry,
    after: &SnapshotIndexEntry,
) -> Option<SnapshotChangeKind> {
    if before.kind != after.kind {
        return Some(SnapshotChangeKind::TypeChanged);
    }
    match before.kind {
        SnapshotEntryKind::File if before.len != after.len || before.hash != after.hash => {
            return Some(SnapshotChangeKind::Modified);
        }
        SnapshotEntryKind::Symlink if before.hash != after.hash => {
            return Some(SnapshotChangeKind::SymlinkTargetChanged);
        }
        SnapshotEntryKind::Directory | SnapshotEntryKind::File | SnapshotEntryKind::Symlink => {}
    }
    (before.mode != after.mode).then_some(SnapshotChangeKind::ModeChanged)
}

fn compare_entry(
    before_root: &Path,
    after_root: &Path,
    path: &Path,
    before: &EntryStamp,
    after: &EntryStamp,
    content_budget: &mut u64,
) -> Result<Option<SnapshotChangeKind>, SnapshotError> {
    if before.kind != after.kind {
        return Ok(Some(SnapshotChangeKind::TypeChanged));
    }
    match before.kind {
        SnapshotEntryKind::File => {
            if before.len != after.len
                || !files_equal(
                    &before_root.join(path),
                    &after_root.join(path),
                    content_budget,
                )?
            {
                return Ok(Some(SnapshotChangeKind::Modified));
            }
        }
        SnapshotEntryKind::Symlink if before.symlink_target != after.symlink_target => {
            return Ok(Some(SnapshotChangeKind::SymlinkTargetChanged));
        }
        SnapshotEntryKind::Directory | SnapshotEntryKind::Symlink => {}
    }
    if before.mode != after.mode {
        Ok(Some(SnapshotChangeKind::ModeChanged))
    } else {
        Ok(None)
    }
}

fn files_equal(left: &Path, right: &Path, content_budget: &mut u64) -> Result<bool, SnapshotError> {
    let mut left = fs::File::open(left).map_err(|error| operation("open diff source", error))?;
    let mut right = fs::File::open(right).map_err(|error| operation("open diff target", error))?;
    let mut left_buf = [0u8; 64 * 1024];
    let mut right_buf = [0u8; 64 * 1024];
    loop {
        let left_len = left
            .read(&mut left_buf)
            .map_err(|error| operation("read diff source", error))?;
        let right_len = right
            .read(&mut right_buf)
            .map_err(|error| operation("read diff target", error))?;
        let compared = left_len.saturating_add(right_len);
        *content_budget = content_budget
            .checked_sub(u64::try_from(compared).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                SnapshotError::LimitExceeded(format!(
                    "snapshot diff read more than {DEFAULT_DIFF_CONTENT_BYTE_BUDGET} content bytes"
                ))
            })?;
        if left_len != right_len || left_buf[..left_len] != right_buf[..right_len] {
            return Ok(false);
        }
        if left_len == 0 {
            return Ok(true);
        }
    }
}

fn normalize_relative(path: &Path) -> Result<PathBuf, SnapshotError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => normalized.push(component),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(SnapshotError::InvalidPath(path.display().to_string()))
            }
        }
    }
    Ok(normalized)
}

fn contained_final_path(root: &Path, rel: &Path) -> Result<PathBuf, SnapshotError> {
    let full = root.join(rel);
    let parent = full.parent().unwrap_or(root);
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| operation("resolve snapshot entry parent", error))?;
    if !canonical_parent.starts_with(root) {
        return Err(SnapshotError::InvalidPath(rel.display().to_string()));
    }
    Ok(full)
}

fn contained_directory(root: &Path, rel: &Path) -> Result<PathBuf, SnapshotError> {
    let full = root.join(rel);
    let canonical = full
        .canonicalize()
        .map_err(|error| operation("resolve snapshot directory", error))?;
    if !canonical.starts_with(root) {
        return Err(SnapshotError::InvalidPath(rel.display().to_string()));
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| operation("inspect snapshot directory", error))?;
    if !metadata.file_type().is_dir() {
        return Err(SnapshotError::Operation(format!(
            "{} is not a directory",
            rel.display()
        )));
    }
    Ok(canonical)
}

fn read_metadata(snapshot_dir: &Path) -> Result<SnapshotMetadata, SnapshotError> {
    let bytes = fs::read(snapshot_dir.join(SNAPSHOT_METADATA)).map_err(|error| {
        SnapshotError::InvalidDescriptor(format!("read snapshot metadata: {error}"))
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        SnapshotError::InvalidDescriptor(format!("parse snapshot metadata: {error}"))
    })
}

fn read_index(
    snapshot_dir: &Path,
    expected_root_hash: [u8; 32],
) -> Result<SnapshotIndex, SnapshotError> {
    let path = snapshot_dir.join(SNAPSHOT_INDEX);
    validate_plain_file(&path, "snapshot index")?;
    let index = SnapshotIndex::load(&path)?;
    if index.root_hash()? != expected_root_hash {
        return Err(SnapshotError::InvalidDescriptor(
            "snapshot index root does not match snapshot metadata".to_string(),
        ));
    }
    Ok(index)
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), SnapshotError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        SnapshotError::Operation(format!("serialize snapshot metadata: {error}"))
    })?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| operation("create snapshot metadata", error))?;
    file.write_all(&bytes)
        .map_err(|error| operation("write snapshot metadata", error))?;
    file.sync_all()
        .map_err(|error| operation("sync snapshot metadata", error))
}

fn sync_directory(path: &Path) -> Result<(), SnapshotError> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| operation("open directory for sync", error))?
        .sync_all()
        .map_err(|error| operation("sync directory", error))
}

fn operation(context: &str, error: std::io::Error) -> SnapshotError {
    SnapshotError::Operation(format!("{context}: {error}"))
}

fn operation_errno(context: &str, errno: i32) -> SnapshotError {
    operation(context, std::io::Error::from_raw_os_error(errno))
}

struct StagingCleanup {
    path: PathBuf,
    published: bool,
}

impl StagingCleanup {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if !self.published {
            let _ = make_tree_removable(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn make_tree_removable(root: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let child = entry.path();
                fs::set_permissions(&child, fs::Permissions::from_mode(0o700))?;
                pending.push(child);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_metadata_has_no_storage_format_version() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();

        let metadata =
            fs::read_to_string(snapshot.descriptor().snapshot_dir.join(SNAPSHOT_METADATA)).unwrap();
        assert!(!metadata.contains("version"));
        assert!(snapshot
            .descriptor()
            .snapshot_dir
            .join(SNAPSHOT_INDEX)
            .is_file());
    }

    #[test]
    fn equivalent_snapshots_have_the_same_merkle_root() {
        let source = tempfile::tempdir().unwrap();
        let first_storage = tempfile::tempdir().unwrap();
        let second_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("directory")).unwrap();
        fs::write(source.path().join("directory/file"), b"content").unwrap();

        let first = FsSnapshot::capture(source.path(), first_storage.path()).unwrap();
        let second = FsSnapshot::capture(source.path(), second_storage.path()).unwrap();

        assert_eq!(first.root_hash, second.root_hash);
        assert_eq!(first.diff(&second, 1).unwrap().changed_paths, 0);
    }

    #[test]
    fn regular_file_clone_keeps_source_and_destination_independent() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("destination");
        fs::write(&source, b"source content").unwrap();

        let method = copy_regular_file_inner(&source, &destination, 0o640, true).unwrap();
        assert!(matches!(
            method,
            FileCopyMethod::Reflink | FileCopyMethod::Buffered
        ));
        fs::write(&destination, b"changed").unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"source content");
        assert_eq!(
            fs::symlink_metadata(&destination).unwrap().mode() & 0o7777,
            0o640
        );

        let forced_copy = directory.path().join("forced-copy");
        assert_eq!(
            copy_regular_file_inner(&source, &forced_copy, 0o600, false).unwrap(),
            FileCopyMethod::Buffered
        );
        assert_eq!(fs::read(forced_copy).unwrap(), b"source content");
    }

    #[test]
    fn reopen_rejects_a_missing_snapshot_index() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let descriptor = snapshot.descriptor().clone();
        fs::remove_file(descriptor.snapshot_dir.join(SNAPSHOT_INDEX)).unwrap();

        assert!(matches!(
            FsSnapshot::reopen(descriptor),
            Err(SnapshotError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn capture_is_immutable_reopenable_and_materializable() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("empty")).unwrap();
        fs::write(source.path().join("file.txt"), b"before").unwrap();
        std::os::unix::fs::symlink("file.txt", source.path().join("link")).unwrap();

        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let descriptor = snapshot.descriptor().clone();
        fs::write(source.path().join("file.txt"), b"after").unwrap();
        assert_eq!(snapshot.read_range("file.txt", 0, 32).unwrap(), b"before");
        assert_eq!(
            snapshot.stat("link").unwrap().symlink_target,
            Some(PathBuf::from("file.txt"))
        );

        let reopened = FsSnapshot::reopen(descriptor).unwrap();
        assert_eq!(reopened.read_range("file.txt", 1, 3).unwrap(), b"efo");
        let destination = storage.path().join("materialized");
        reopened.materialize(&destination).unwrap();
        assert_eq!(fs::read(destination.join("file.txt")).unwrap(), b"before");
        assert!(destination.join("empty").is_dir());
    }

    #[test]
    fn ordinary_tree_named_source_cannot_spoof_backend_modes() {
        let controlled = tempfile::tempdir().unwrap();
        let source = controlled.path().join("tree");
        let storage = tempfile::tempdir().unwrap();
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(source.join("dir")).unwrap();
        fs::set_permissions(source.join("dir"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            controlled.path().join(SNAPSHOT_DIRECTORY_MODES),
            br#"{"dir":0}"#,
        )
        .unwrap();

        let snapshot = FsSnapshot::capture(&source, storage.path()).unwrap();
        assert_eq!(snapshot.stat("dir").unwrap().mode, 0o755);
    }

    #[test]
    fn discover_recovers_a_published_descriptor() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let expected = snapshot.descriptor().clone();
        drop(snapshot);

        assert_eq!(
            FsSnapshot::discover(storage.path()).unwrap(),
            vec![expected]
        );
    }

    #[test]
    fn failure_after_snapshot_publish_returns_a_reopenable_descriptor() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        FAIL_AFTER_SNAPSHOT_PUBLISH.store(true, std::sync::atomic::Ordering::SeqCst);

        let descriptor = match FsSnapshot::capture(source.path(), storage.path()) {
            Err(SnapshotError::Published { descriptor, .. }) => *descriptor,
            other => panic!("expected published outcome, got {other:?}"),
        };
        let mut reopened = FsSnapshot::reopen(descriptor).unwrap();
        assert_eq!(reopened.read_range("file", 0, 32).unwrap(), b"content");
        reopened.destroy().unwrap();
    }

    #[test]
    fn destroy_tombstone_hides_a_partially_destroyed_snapshot() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let mut snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let published = snapshot.descriptor().clone();
        FAIL_AFTER_DESTROY_TOMBSTONE.store(true, std::sync::atomic::Ordering::SeqCst);

        let destroyed_descriptor = match snapshot.destroy() {
            Err(SnapshotError::Destroyed { descriptor, .. }) => *descriptor,
            other => panic!("expected destroyed outcome, got {other:?}"),
        };
        assert_eq!(destroyed_descriptor, published);
        assert!(FsSnapshot::reopen(destroyed_descriptor).is_err());
        assert!(FsSnapshot::reopen(published).is_err());
        assert!(FsSnapshot::discover(storage.path()).unwrap().is_empty());
    }

    #[test]
    fn failure_after_materialize_publish_reports_the_destination() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let destination = storage.path().join("destination");
        FAIL_AFTER_MATERIALIZE_PUBLISH.store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(matches!(
            snapshot.materialize(&destination),
            Err(SnapshotError::Materialized {
                destination: ref published,
                ..
            }) if published == &destination
        ));
        assert_eq!(fs::read(destination.join("file")).unwrap(), b"content");
    }

    #[test]
    fn materialize_rejects_a_symlink_parent() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let real_parent = tempfile::tempdir().unwrap();
        let link_parent = storage.path().join("parent-link");
        std::os::unix::fs::symlink(real_parent.path(), &link_parent).unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();

        assert!(matches!(
            snapshot.materialize(link_parent.join("destination")),
            Err(SnapshotError::Operation(_))
        ));
        assert!(!real_parent.path().join("destination").exists());
    }

    #[test]
    fn diff_reports_content_mode_type_and_symlink_changes() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("content"), b"one").unwrap();
        fs::write(source.path().join("mode"), b"same").unwrap();
        fs::write(source.path().join("kind"), b"file").unwrap();
        std::os::unix::fs::symlink("one", source.path().join("link")).unwrap();
        let before = FsSnapshot::capture(source.path(), storage.path()).unwrap();

        fs::write(source.path().join("content"), b"two").unwrap();
        fs::set_permissions(
            source.path().join("mode"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::remove_file(source.path().join("kind")).unwrap();
        fs::create_dir(source.path().join("kind")).unwrap();
        fs::remove_file(source.path().join("link")).unwrap();
        std::os::unix::fs::symlink("two", source.path().join("link")).unwrap();
        fs::write(source.path().join("added"), b"new").unwrap();
        let after = FsSnapshot::capture(source.path(), storage.path()).unwrap();

        let diff = before.diff(&after, 16).unwrap();
        assert_eq!(diff.changed_paths, 5);
        let kinds = diff
            .changes
            .into_iter()
            .map(|change| (change.path, change.kind))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(kinds[Path::new("content")], SnapshotChangeKind::Modified);
        assert_eq!(kinds[Path::new("mode")], SnapshotChangeKind::ModeChanged);
        assert_eq!(kinds[Path::new("kind")], SnapshotChangeKind::TypeChanged);
        assert_eq!(
            kinds[Path::new("link")],
            SnapshotChangeKind::SymlinkTargetChanged
        );
        assert_eq!(kinds[Path::new("added")], SnapshotChangeKind::Added);

        let first = before.diff(&after, 2).unwrap();
        assert_eq!(first.changes.len(), 2);
        assert!(first.truncated);
        let second = before
            .diff_after(&after, first.next_path.as_deref(), 16)
            .unwrap();
        assert_eq!(second.changes.len(), 3);
        assert!(!second.truncated);
        assert_eq!(second.changed_paths, 5);
    }

    #[test]
    fn failed_capture_removes_staging() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let fifo = source.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            FsSnapshot::capture(source.path(), storage.path()),
            Err(SnapshotError::UnsupportedFileType(_))
        ));
        assert_eq!(fs::read_dir(storage.path()).unwrap().count(), 0);
    }

    #[test]
    fn capture_rejects_storage_inside_source() {
        let source = tempfile::tempdir().unwrap();
        let storage = source.path().join("snapshots");
        fs::write(source.path().join("file"), b"content").unwrap();

        assert!(matches!(
            FsSnapshot::capture(source.path(), &storage),
            Err(SnapshotError::Operation(_))
        ));
        assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
    }

    #[test]
    fn destroy_prunes_a_stale_branch_lease() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let mut snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let missing_branch = storage.path().join("crashed-branch");
        fs::create_dir(&missing_branch).unwrap();
        let _lease = snapshot.acquire_branch_lease(&missing_branch).unwrap();
        fs::remove_dir(&missing_branch).unwrap();

        snapshot.destroy().unwrap();
        assert!(!snapshot.descriptor.snapshot_dir.exists());
    }

    #[test]
    fn destroy_rejects_another_active_snapshot_handle() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let mut snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let reopened = FsSnapshot::reopen(snapshot.descriptor().clone()).unwrap();

        assert!(matches!(
            snapshot.destroy(),
            Err(SnapshotError::InUse { count: 1 })
        ));
        drop(reopened);
        snapshot.destroy().unwrap();
    }

    #[test]
    fn branch_lease_uses_a_canonical_storage_path() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let branch_parent = tempfile::tempdir().unwrap();
        let branch_dir = branch_parent.path().join("branch");
        fs::create_dir(&branch_dir).unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();

        let lease = snapshot.acquire_branch_lease(&branch_dir).unwrap();
        assert_eq!(lease.record.branch_dir, branch_dir.canonicalize().unwrap());
    }

    #[test]
    fn destroy_fails_conservatively_on_a_corrupt_lease() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let branch = tempfile::tempdir().unwrap();
        let mut snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let lease = snapshot.acquire_branch_lease(branch.path()).unwrap();
        fs::write(&lease.path, b"not json").unwrap();

        assert!(matches!(
            snapshot.destroy(),
            Err(SnapshotError::InvalidDescriptor(_))
        ));
        fs::write(&lease.path, serde_json::to_vec(&lease.record).unwrap()).unwrap();
        drop(lease);
        drop(branch);
        snapshot.destroy().unwrap();
    }

    #[test]
    fn destroy_reclaims_an_unpublished_orphan_branch() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let branch_parent = tempfile::tempdir().unwrap();
        let branch_dir = branch_parent.path().join("orphan");
        fs::create_dir_all(branch_dir.join("upper")).unwrap();
        fs::write(source.path().join("file"), b"content").unwrap();
        let mut snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let lease = snapshot.acquire_branch_lease(&branch_dir).unwrap();
        drop(lease);

        snapshot.destroy().unwrap();
        assert!(!branch_dir.exists());
    }

    #[test]
    fn path_access_does_not_escape_snapshot_root() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", source.path().join("outside")).unwrap();
        let snapshot = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        assert!(matches!(
            snapshot.read_range("outside/passwd", 0, 8),
            Err(SnapshotError::InvalidPath(_))
        ));
        assert!(matches!(
            snapshot.stat("../escape"),
            Err(SnapshotError::InvalidPath(_))
        ));
        assert!(matches!(
            snapshot.list(".", DEFAULT_SCAN_ENTRY_BUDGET, 1),
            Err(SnapshotError::LimitExceeded(_))
        ));
    }

    #[test]
    fn no_replace_publication_preserves_an_existing_destination() {
        let parent = tempfile::tempdir().unwrap();
        let source = parent.path().join("source");
        let destination = parent.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("owner"), b"existing").unwrap();

        let error = rename_noreplace(&source, &destination).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(destination.join("owner")).unwrap(), b"existing");
        assert!(source.is_dir());
    }
}
