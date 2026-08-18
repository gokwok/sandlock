//! Bounded immutable snapshot deltas and conflict-checked directory application.

use super::{
    compare_entry, copy_regular_file, files_equal, inventory_bounded_with_modes,
    normalize_relative, operation, snapshot_entry, sync_directory, validate_plain_directory,
    EntryStamp, FsSnapshot, SnapshotChange, SnapshotChangeKind, SnapshotCompareLimits,
    SnapshotEntry, SnapshotEntryKind, SnapshotRequirement,
};
use crate::cow::seccomp::{acquire_commit_lock_polling, LockFailure};
use crate::error::SnapshotError;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_DELTA_PATH_LIMIT: usize = 4096;
const DEFAULT_DELTA_BYTE_LIMIT: u64 = 256 * 1024 * 1024;
const DEFAULT_COMPARE_BYTE_LIMIT: u64 = 1024 * 1024 * 1024;

/// Hard budgets enforced while preparing and validating a snapshot delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotDeltaLimits {
    pub max_changed_paths: usize,
    pub max_changed_bytes: u64,
    pub max_compared_bytes: u64,
}

impl Default for SnapshotDeltaLimits {
    fn default() -> Self {
        Self {
            max_changed_paths: DEFAULT_DELTA_PATH_LIMIT,
            max_changed_bytes: DEFAULT_DELTA_BYTE_LIMIT,
            max_compared_bytes: DEFAULT_COMPARE_BYTE_LIMIT,
        }
    }
}

/// Generic filesystem policy applied before a delta can touch a destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDeltaPolicy {
    pub allow_symlinks: bool,
    pub protected_paths: Vec<PathBuf>,
}

impl Default for SnapshotDeltaPolicy {
    fn default() -> Self {
        Self {
            allow_symlinks: true,
            protected_paths: Vec::new(),
        }
    }
}

/// Whether destination validation expects an untouched base or resumes an earlier apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotDeltaApplyMode {
    Initial,
    Resume,
}

/// Complete bounded summary of one immutable snapshot delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotDeltaSummary {
    pub changed_paths: usize,
    pub changed_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct DeltaEntry {
    pub(crate) change: SnapshotChange,
    pub(crate) before: Option<SnapshotEntry>,
    pub(crate) after: Option<SnapshotEntry>,
}

/// A complete, bounded BASE-to-TARGET delta that borrows both immutable snapshots.
pub struct SnapshotDelta<'a> {
    pub(crate) base: &'a FsSnapshot,
    pub(crate) target: &'a FsSnapshot,
    pub(crate) entries: Vec<DeltaEntry>,
    summary: SnapshotDeltaSummary,
    limits: SnapshotDeltaLimits,
}

impl std::fmt::Debug for SnapshotDelta<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotDelta")
            .field("base", &self.base.id())
            .field("target", &self.target.id())
            .field("summary", &self.summary)
            .finish()
    }
}

impl FsSnapshot {
    /// Prepare a complete bounded delta from this base to `target`.
    pub fn delta_to<'a>(
        &'a self,
        target: &'a FsSnapshot,
        limits: SnapshotDeltaLimits,
        policy: &SnapshotDeltaPolicy,
    ) -> Result<SnapshotDelta<'a>, SnapshotError> {
        self.ensure_live()?;
        target.ensure_live()?;
        let retained = limits.max_changed_paths.saturating_add(1);
        let diff = self.diff(target, retained)?;
        if diff.changed_paths > limits.max_changed_paths {
            return Err(SnapshotError::LimitExceeded(format!(
                "snapshot delta has {} changed paths; limit is {}",
                diff.changed_paths, limits.max_changed_paths
            )));
        }
        let protected = prepare_protected_paths(&policy.protected_paths)?;
        let mut entries = Vec::with_capacity(diff.changes.len());
        let mut changed_bytes = 0_u64;
        for change in diff.changes {
            let path = normalize_relative(&change.path)?;
            if path.as_os_str().is_empty() {
                return Err(SnapshotError::InvalidPath(
                    "snapshot root cannot be part of a delta".to_string(),
                ));
            }
            if let Some(protected) = protected.iter().find(|protected| {
                path == **protected || path.starts_with(protected) || protected.starts_with(&path)
            }) {
                return Err(SnapshotError::DeltaRejected {
                    path,
                    reason: format!("change overlaps protected path {}", protected.display()),
                });
            }
            let (before, after) = change_entries(self, target, &change)?;
            if !policy.allow_symlinks
                && before
                    .as_ref()
                    .into_iter()
                    .chain(after.as_ref())
                    .any(|entry| entry.kind == SnapshotEntryKind::Symlink)
            {
                return Err(SnapshotError::DeltaRejected {
                    path: change.path,
                    reason: "symbolic links are disabled by delta policy".to_string(),
                });
            }
            changed_bytes = changed_bytes
                .checked_add(after.as_ref().map_or(0, replacement_bytes))
                .ok_or_else(|| {
                    SnapshotError::LimitExceeded("snapshot delta byte overflow".to_string())
                })?;
            if changed_bytes > limits.max_changed_bytes {
                return Err(SnapshotError::LimitExceeded(format!(
                    "snapshot delta replacement bytes exceed {}",
                    limits.max_changed_bytes
                )));
            }
            entries.push(DeltaEntry {
                change,
                before,
                after,
            });
        }
        Ok(SnapshotDelta {
            base: self,
            target,
            entries,
            summary: SnapshotDeltaSummary {
                changed_paths: diff.changed_paths,
                changed_bytes,
            },
            limits,
        })
    }
}

impl SnapshotDelta<'_> {
    pub fn summary(&self) -> SnapshotDeltaSummary {
        self.summary
    }

    pub fn changes(&self) -> Vec<SnapshotChange> {
        self.entries
            .iter()
            .map(|entry| entry.change.clone())
            .collect()
    }

    /// Check whether an immutable current view is compatible with this delta.
    pub fn validate_snapshot(
        &self,
        current: &FsSnapshot,
        mode: SnapshotDeltaApplyMode,
    ) -> Result<(), SnapshotError> {
        current.ensure_live()?;
        let current_modes = current.directory_modes()?;
        let current_inventory = inventory_bounded_with_modes(
            &current.tree_dir,
            super::DEFAULT_SCAN_ENTRY_BUDGET,
            super::DEFAULT_SCAN_PATH_BYTE_BUDGET,
            Some(&current_modes),
        )?;
        let conflicts = self.validate_inventory(&current.tree_dir, &current_inventory, mode)?;
        if conflicts == 0 {
            Ok(())
        } else {
            Err(SnapshotError::DeltaConflict { count: conflicts })
        }
    }

    /// Apply the delta to a real directory under the same cross-process commit lock used by COW.
    ///
    /// Initial mode rejects every conflict before writing. Resume mode accepts paths already equal
    /// to TARGET and converges an earlier partial apply. A failure after the first path mutation is
    /// reported as `DeltaApplyIncomplete`; retrying with `Resume` is the recovery operation.
    pub fn apply_to_directory(
        &self,
        destination: impl AsRef<Path>,
        mode: SnapshotDeltaApplyMode,
        lock_wait: Duration,
    ) -> Result<SnapshotDeltaSummary, SnapshotError> {
        self.apply_to_directory_with_requirements(
            destination,
            mode,
            &[],
            SnapshotCompareLimits::default(),
            lock_wait,
        )
    }

    /// Validate declared dependencies and apply this delta under one destination commit lock.
    ///
    /// Initial mode requires every dependency to match BASE before the first write. Resume mode
    /// accepts BASE or TARGET dependency state so an interrupted apply can converge. After apply,
    /// every dependency must match TARGET; a mismatch after any mutation is reported as
    /// `DeltaApplyIncomplete` so the caller keeps its writer fence and recovery marker.
    pub fn apply_to_directory_with_requirements(
        &self,
        destination: impl AsRef<Path>,
        mode: SnapshotDeltaApplyMode,
        requirements: &[SnapshotRequirement],
        compare_limits: SnapshotCompareLimits,
        lock_wait: Duration,
    ) -> Result<SnapshotDeltaSummary, SnapshotError> {
        self.apply_to_directory_inner(
            destination.as_ref(),
            mode,
            requirements,
            compare_limits,
            lock_wait,
            || {},
        )
    }

    fn apply_to_directory_inner(
        &self,
        destination: &Path,
        mode: SnapshotDeltaApplyMode,
        requirements: &[SnapshotRequirement],
        compare_limits: SnapshotCompareLimits,
        lock_wait: Duration,
        before_apply: impl FnOnce(),
    ) -> Result<SnapshotDeltaSummary, SnapshotError> {
        let destination = destination.as_ref();
        validate_plain_directory(destination, "snapshot delta destination")?;
        let _lock = acquire_commit_lock_polling(destination, lock_wait, std::thread::sleep)
            .map_err(|failure| match failure {
                LockFailure::Contended(wait) => SnapshotError::DeltaDeferred(format!(
                    "destination lock was contended for {wait:?}"
                )),
                LockFailure::Io(error) => operation("lock snapshot delta destination", error),
            })?;
        let dependencies_match = if mode == SnapshotDeltaApplyMode::Resume {
            self.base
                .compare_directory_requirements_allowing(
                    self.target,
                    destination,
                    requirements,
                    compare_limits,
                )?
                .matched
        } else {
            self.base
                .compare_directory_requirements(destination, requirements, compare_limits)?
                .matched
        };
        if !dependencies_match {
            return Err(SnapshotError::DeltaConflict { count: 1 });
        }
        before_apply();
        let destination_modes = None;
        let inventory = inventory_bounded_with_modes(
            destination,
            super::DEFAULT_SCAN_ENTRY_BUDGET,
            super::DEFAULT_SCAN_PATH_BYTE_BUDGET,
            destination_modes,
        )?;
        let conflicts = self.validate_inventory(destination, &inventory, mode)?;
        if conflicts != 0 {
            return Err(SnapshotError::DeltaConflict { count: conflicts });
        }

        let mut applied_paths = 0_usize;
        let result = self.apply_entries(destination, &mut applied_paths);
        if let Err(error) = result {
            return if applied_paths == 0 {
                Err(error)
            } else {
                Err(SnapshotError::DeltaApplyIncomplete {
                    applied_paths: Some(applied_paths),
                    message: error.to_string(),
                })
            };
        }

        let inventory = inventory_bounded_with_modes(
            destination,
            super::DEFAULT_SCAN_ENTRY_BUDGET,
            super::DEFAULT_SCAN_PATH_BYTE_BUDGET,
            None,
        )?;
        let conflicts = self.validate_target_inventory(destination, &inventory)?;
        if conflicts != 0 {
            return Err(SnapshotError::DeltaApplyIncomplete {
                applied_paths: Some(applied_paths),
                message: format!("target verification found {conflicts} conflicting path(s)"),
            });
        }
        let target_dependencies = self.target.compare_directory_requirements(
            destination,
            requirements,
            compare_limits,
        )?;
        if !target_dependencies.matched {
            return if applied_paths == 0 {
                Err(SnapshotError::DeltaConflict { count: 1 })
            } else {
                Err(SnapshotError::DeltaApplyIncomplete {
                    applied_paths: Some(applied_paths),
                    message: "dependency changed while applying snapshot delta".to_string(),
                })
            };
        }
        sync_directory(destination)?;
        Ok(self.summary)
    }

    fn validate_inventory(
        &self,
        current_root: &Path,
        current: &BTreeMap<PathBuf, EntryStamp>,
        mode: SnapshotDeltaApplyMode,
    ) -> Result<usize, SnapshotError> {
        let base_modes = self.base.directory_modes()?;
        let base = inventory_bounded_with_modes(
            &self.base.tree_dir,
            super::DEFAULT_SCAN_ENTRY_BUDGET,
            super::DEFAULT_SCAN_PATH_BYTE_BUDGET,
            Some(&base_modes),
        )?;
        let target_modes = self.target.directory_modes()?;
        let target = inventory_bounded_with_modes(
            &self.target.tree_dir,
            super::DEFAULT_SCAN_ENTRY_BUDGET,
            super::DEFAULT_SCAN_PATH_BYTE_BUDGET,
            Some(&target_modes),
        )?;
        let mut compared_bytes = self.limits.max_compared_bytes;
        let mut conflicts = 0_usize;
        for entry in &self.entries {
            let matches_base = inventory_entry_equal(
                &self.base.tree_dir,
                &base,
                current_root,
                current,
                &entry.change.path,
                &mut compared_bytes,
            )?;
            let matches_target = mode == SnapshotDeltaApplyMode::Resume
                && inventory_entry_equal(
                    &self.target.tree_dir,
                    &target,
                    current_root,
                    current,
                    &entry.change.path,
                    &mut compared_bytes,
                )?;
            if !matches_base && !matches_target {
                conflicts = conflicts.saturating_add(1);
            }
        }
        for root in self.destructive_directory_roots() {
            let paths = base
                .keys()
                .chain(target.keys())
                .chain(current.keys())
                .filter(|candidate| *candidate == root || candidate.starts_with(root))
                .cloned()
                .collect::<BTreeSet<_>>();
            for path in paths {
                let matches_base = inventory_entry_equal(
                    &self.base.tree_dir,
                    &base,
                    current_root,
                    current,
                    &path,
                    &mut compared_bytes,
                )?;
                let matches_target = mode == SnapshotDeltaApplyMode::Resume
                    && inventory_entry_equal(
                        &self.target.tree_dir,
                        &target,
                        current_root,
                        current,
                        &path,
                        &mut compared_bytes,
                    )?;
                if !matches_base && !matches_target {
                    conflicts = conflicts.saturating_add(1);
                }
            }
        }
        Ok(conflicts)
    }

    fn validate_target_inventory(
        &self,
        current_root: &Path,
        current: &BTreeMap<PathBuf, EntryStamp>,
    ) -> Result<usize, SnapshotError> {
        let target_modes = self.target.directory_modes()?;
        let target = inventory_bounded_with_modes(
            &self.target.tree_dir,
            super::DEFAULT_SCAN_ENTRY_BUDGET,
            super::DEFAULT_SCAN_PATH_BYTE_BUDGET,
            Some(&target_modes),
        )?;
        let mut compared_bytes = self.limits.max_compared_bytes;
        let mut conflicts = 0_usize;
        for entry in &self.entries {
            if !inventory_entry_equal(
                &self.target.tree_dir,
                &target,
                current_root,
                current,
                &entry.change.path,
                &mut compared_bytes,
            )? {
                conflicts = conflicts.saturating_add(1);
            }
        }
        for root in self.destructive_directory_roots() {
            let paths = target
                .keys()
                .chain(current.keys())
                .filter(|candidate| *candidate == root || candidate.starts_with(root))
                .cloned()
                .collect::<BTreeSet<_>>();
            for path in paths {
                if !inventory_entry_equal(
                    &self.target.tree_dir,
                    &target,
                    current_root,
                    current,
                    &path,
                    &mut compared_bytes,
                )? {
                    conflicts = conflicts.saturating_add(1);
                }
            }
        }
        Ok(conflicts)
    }

    fn destructive_directory_roots(&self) -> Vec<&Path> {
        self.entries
            .iter()
            .filter_map(|entry| {
                (entry
                    .before
                    .as_ref()
                    .is_some_and(|before| before.kind == SnapshotEntryKind::Directory)
                    && entry
                        .after
                        .as_ref()
                        .is_none_or(|after| after.kind != SnapshotEntryKind::Directory))
                .then_some(entry.change.path.as_path())
            })
            .collect()
    }

    fn apply_entries(
        &self,
        destination: &Path,
        applied_paths: &mut usize,
    ) -> Result<(), SnapshotError> {
        let mut removals = self
            .entries
            .iter()
            .filter(|entry| {
                entry.before.is_some()
                    && entry.after.as_ref().is_none_or(|after| {
                        entry
                            .before
                            .as_ref()
                            .is_some_and(|before| before.kind != after.kind)
                    })
            })
            .collect::<Vec<_>>();
        removals.sort_by(|left, right| {
            path_depth(&right.change.path).cmp(&path_depth(&left.change.path))
        });
        for entry in removals {
            if live_matches_target(
                self.target,
                entry.after.as_ref(),
                destination,
                &entry.change.path,
                self.limits.max_compared_bytes,
            )? {
                continue;
            }
            ensure_live_matches_either(self, entry, destination, *applied_paths)?;
            remove_live_entry(
                destination,
                &entry.change.path,
                entry.before.as_ref().expect("removal has a base"),
            )?;
            *applied_paths = applied_paths.saturating_add(1);
        }

        let mut directories = self
            .entries
            .iter()
            .filter(|entry| {
                entry
                    .after
                    .as_ref()
                    .is_some_and(|after| after.kind == SnapshotEntryKind::Directory)
                    && entry
                        .before
                        .as_ref()
                        .is_none_or(|before| before.kind != SnapshotEntryKind::Directory)
            })
            .collect::<Vec<_>>();
        directories.sort_by_key(|entry| path_depth(&entry.change.path));
        for entry in directories {
            if live_matches_target(
                self.target,
                entry.after.as_ref(),
                destination,
                &entry.change.path,
                self.limits.max_compared_bytes,
            )? {
                continue;
            }
            ensure_live_matches_either(self, entry, destination, *applied_paths)?;
            ensure_plain_parent(destination, &entry.change.path)?;
            fs::create_dir(destination.join(&entry.change.path))
                .map_err(|error| operation("create snapshot delta directory", error))?;
            *applied_paths = applied_paths.saturating_add(1);
        }

        for entry in self.entries.iter().filter(|entry| {
            entry
                .after
                .as_ref()
                .is_some_and(|after| after.kind != SnapshotEntryKind::Directory)
                && entry.change.kind != SnapshotChangeKind::Deleted
        }) {
            if live_matches_target(
                self.target,
                entry.after.as_ref(),
                destination,
                &entry.change.path,
                self.limits.max_compared_bytes,
            )? {
                continue;
            }
            ensure_live_matches_either(self, entry, destination, *applied_paths)?;
            put_target_entry(
                self.target,
                destination,
                entry.after.as_ref().expect("put has target"),
            )?;
            *applied_paths = applied_paths.saturating_add(1);
        }

        let mut modes = self
            .entries
            .iter()
            .filter(|entry| entry.after.is_some())
            .collect::<Vec<_>>();
        modes.sort_by(|left, right| {
            path_depth(&right.change.path).cmp(&path_depth(&left.change.path))
        });
        for entry in modes {
            let after = entry.after.as_ref().expect("mode target exists");
            if after.kind == SnapshotEntryKind::Symlink {
                continue;
            }
            let target = destination.join(&entry.change.path);
            let metadata = fs::symlink_metadata(&target)
                .map_err(|error| operation("inspect snapshot delta mode target", error))?;
            if metadata.permissions().mode() & 0o7777 != after.mode {
                fs::set_permissions(&target, fs::Permissions::from_mode(after.mode))
                    .map_err(|error| operation("set snapshot delta mode", error))?;
                *applied_paths = applied_paths.saturating_add(1);
            }
        }
        Ok(())
    }
}

fn prepare_protected_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, SnapshotError> {
    let mut result = paths
        .iter()
        .map(|path| normalize_relative(path))
        .collect::<Result<Vec<_>, _>>()?;
    if result.iter().any(|path| path.as_os_str().is_empty()) {
        return Err(SnapshotError::InvalidPath(
            "snapshot delta cannot protect the root implicitly".to_string(),
        ));
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn change_entries(
    base: &FsSnapshot,
    target: &FsSnapshot,
    change: &SnapshotChange,
) -> Result<(Option<SnapshotEntry>, Option<SnapshotEntry>), SnapshotError> {
    match change.kind {
        SnapshotChangeKind::Added => Ok((None, Some(target.stat(&change.path)?))),
        SnapshotChangeKind::Deleted => Ok((Some(base.stat(&change.path)?), None)),
        SnapshotChangeKind::Modified
        | SnapshotChangeKind::TypeChanged
        | SnapshotChangeKind::ModeChanged
        | SnapshotChangeKind::SymlinkTargetChanged => Ok((
            Some(base.stat(&change.path)?),
            Some(target.stat(&change.path)?),
        )),
    }
}

fn replacement_bytes(entry: &SnapshotEntry) -> u64 {
    match entry.kind {
        SnapshotEntryKind::File => entry.len,
        SnapshotEntryKind::Symlink => entry.symlink_target.as_ref().map_or(0, |target| {
            u64::try_from(target.as_os_str().as_bytes().len()).unwrap_or(u64::MAX)
        }),
        SnapshotEntryKind::Directory => 0,
    }
}

fn inventory_entry_equal(
    expected_root: &Path,
    expected: &BTreeMap<PathBuf, EntryStamp>,
    current_root: &Path,
    current: &BTreeMap<PathBuf, EntryStamp>,
    path: &Path,
    content_budget: &mut u64,
) -> Result<bool, SnapshotError> {
    match (expected.get(path), current.get(path)) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => Ok(compare_entry(
            expected_root,
            current_root,
            path,
            left,
            right,
            content_budget,
        )?
        .is_none()),
        _ => Ok(false),
    }
}

fn live_matches_target(
    target: &FsSnapshot,
    expected: Option<&SnapshotEntry>,
    destination: &Path,
    path: &Path,
    content_budget: u64,
) -> Result<bool, SnapshotError> {
    live_matches_snapshot(target, expected, destination, path, content_budget)
}

fn live_matches_snapshot(
    snapshot: &FsSnapshot,
    expected: Option<&SnapshotEntry>,
    destination: &Path,
    path: &Path,
    mut content_budget: u64,
) -> Result<bool, SnapshotError> {
    let current = match snapshot_entry(destination, path) {
        Ok(entry) => Some(entry),
        Err(_) if !destination.join(path).exists() && !destination.join(path).is_symlink() => None,
        Err(error) => return Err(error),
    };
    let Some(expected) = expected else {
        return Ok(current.is_none());
    };
    let Some(current) = current else {
        return Ok(false);
    };
    if expected.kind != current.kind || expected.mode != current.mode {
        return Ok(false);
    }
    match expected.kind {
        SnapshotEntryKind::File => files_equal(
            &snapshot.tree_dir.join(path),
            &destination.join(path),
            &mut content_budget,
        ),
        SnapshotEntryKind::Directory => Ok(true),
        SnapshotEntryKind::Symlink => Ok(expected.symlink_target == current.symlink_target),
    }
}

fn ensure_live_matches_either(
    delta: &SnapshotDelta<'_>,
    entry: &DeltaEntry,
    destination: &Path,
    applied_paths: usize,
) -> Result<(), SnapshotError> {
    let matches_base = live_matches_snapshot(
        delta.base,
        entry.before.as_ref(),
        destination,
        &entry.change.path,
        delta.limits.max_compared_bytes,
    )?;
    let matches_target = live_matches_snapshot(
        delta.target,
        entry.after.as_ref(),
        destination,
        &entry.change.path,
        delta.limits.max_compared_bytes,
    )?;
    if matches_base || matches_target {
        Ok(())
    } else if applied_paths == 0 {
        Err(SnapshotError::DeltaConflict { count: 1 })
    } else {
        Err(SnapshotError::DeltaApplyIncomplete {
            applied_paths: Some(applied_paths),
            message: format!("destination changed at {}", entry.change.path.display()),
        })
    }
}

fn remove_live_entry(
    destination: &Path,
    path: &Path,
    before: &SnapshotEntry,
) -> Result<(), SnapshotError> {
    ensure_plain_parent(destination, path)?;
    let target = destination.join(path);
    match before.kind {
        SnapshotEntryKind::Directory => fs::remove_dir(&target)
            .map_err(|error| operation("remove snapshot delta directory", error)),
        SnapshotEntryKind::File | SnapshotEntryKind::Symlink => fs::remove_file(&target)
            .map_err(|error| operation("remove snapshot delta entry", error)),
    }
}

fn put_target_entry(
    target_snapshot: &FsSnapshot,
    destination: &Path,
    entry: &SnapshotEntry,
) -> Result<(), SnapshotError> {
    ensure_plain_parent(destination, &entry.path)?;
    let target = destination.join(&entry.path);
    let parent = target.parent().expect("delta target has a parent");
    let temporary = parent.join(format!(".sandlock-delta-{}.tmp", uuid::Uuid::new_v4()));
    let mut published = false;
    let result = (|| match entry.kind {
        SnapshotEntryKind::File => {
            copy_regular_file(
                &target_snapshot.tree_dir.join(&entry.path),
                &temporary,
                entry.mode,
            )?;
            fs::rename(&temporary, &target)
                .map_err(|error| operation("publish snapshot delta file", error))?;
            published = true;
            Ok(())
        }
        SnapshotEntryKind::Symlink => {
            let link = entry.symlink_target.as_ref().ok_or_else(|| {
                SnapshotError::Operation("snapshot symlink target is missing".to_string())
            })?;
            std::os::unix::fs::symlink(link, &temporary)
                .map_err(|error| operation("stage snapshot delta symlink", error))?;
            fs::rename(&temporary, &target)
                .map_err(|error| operation("publish snapshot delta symlink", error))?;
            published = true;
            Ok(())
        }
        SnapshotEntryKind::Directory => Err(SnapshotError::Operation(
            "directory passed to snapshot delta file publisher".to_string(),
        )),
    })();
    if !published {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    sync_directory(parent)
}

fn ensure_plain_parent(root: &Path, path: &Path) -> Result<(), SnapshotError> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(SnapshotError::InvalidPath(path.display().to_string()));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| operation("inspect snapshot delta parent", error))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(SnapshotError::InvalidPath(path.display().to_string()));
        }
    }
    Ok(())
}

fn path_depth(path: &Path) -> usize {
    path.components().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshots() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        tempfile::TempDir,
        FsSnapshot,
        FsSnapshot,
    ) {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let target_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("remove-dir")).unwrap();
        fs::write(source.path().join("remove-dir/value"), b"remove").unwrap();
        fs::write(source.path().join("modify"), b"base").unwrap();
        fs::write(source.path().join("delete"), b"delete").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();

        fs::remove_dir_all(source.path().join("remove-dir")).unwrap();
        fs::write(source.path().join("modify"), b"target").unwrap();
        fs::remove_file(source.path().join("delete")).unwrap();
        fs::create_dir(source.path().join("added-dir")).unwrap();
        fs::write(source.path().join("added-dir/value"), b"added").unwrap();
        let target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
        (source, base_storage, target_storage, base, target)
    }

    #[test]
    fn delta_applies_changed_paths_and_preserves_unrelated_changes() {
        let (_source, _base_storage, _target_storage, base, target) = snapshots();
        let destination = tempfile::tempdir().unwrap();
        base.materialize(destination.path().join("workspace"))
            .unwrap();
        let workspace = destination.path().join("workspace");
        fs::write(workspace.join("unrelated"), b"live").unwrap();

        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy {
                    allow_symlinks: false,
                    protected_paths: Vec::new(),
                },
            )
            .unwrap();
        delta
            .apply_to_directory(
                &workspace,
                SnapshotDeltaApplyMode::Initial,
                Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(fs::read(workspace.join("modify")).unwrap(), b"target");
        assert!(!workspace.join("delete").exists());
        assert!(!workspace.join("remove-dir").exists());
        assert_eq!(
            fs::read(workspace.join("added-dir/value")).unwrap(),
            b"added"
        );
        assert_eq!(fs::read(workspace.join("unrelated")).unwrap(), b"live");
    }

    #[test]
    fn delta_conflict_is_detected_before_writing() {
        let (_source, _base_storage, _target_storage, base, target) = snapshots();
        let destination = tempfile::tempdir().unwrap();
        base.materialize(destination.path().join("workspace"))
            .unwrap();
        let workspace = destination.path().join("workspace");
        fs::write(workspace.join("modify"), b"conflict").unwrap();
        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy::default(),
            )
            .unwrap();

        assert!(matches!(
            delta.apply_to_directory(
                &workspace,
                SnapshotDeltaApplyMode::Initial,
                Duration::from_secs(1),
            ),
            Err(SnapshotError::DeltaConflict { .. })
        ));
        assert_eq!(fs::read(workspace.join("modify")).unwrap(), b"conflict");
        assert!(workspace.join("delete").exists());
    }

    #[test]
    fn delta_rejects_protected_paths_and_symlinks() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let target_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join(".git")).unwrap();
        fs::write(source.path().join(".git/config"), b"base").unwrap();
        std::os::unix::fs::symlink("one", source.path().join("link")).unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join(".git/config"), b"target").unwrap();
        fs::remove_file(source.path().join("link")).unwrap();
        std::os::unix::fs::symlink("two", source.path().join("link")).unwrap();
        let target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();

        assert!(matches!(
            base.delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy {
                    allow_symlinks: true,
                    protected_paths: vec![PathBuf::from(".git")],
                },
            ),
            Err(SnapshotError::DeltaRejected { .. })
        ));
        assert!(matches!(
            base.delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy {
                    allow_symlinks: false,
                    protected_paths: Vec::new(),
                },
            ),
            Err(SnapshotError::DeltaRejected { .. })
        ));
    }

    #[test]
    fn resume_accepts_a_mixture_of_base_and_target_paths() {
        let (_source, _base_storage, _target_storage, base, target) = snapshots();
        let destination = tempfile::tempdir().unwrap();
        base.materialize(destination.path().join("workspace"))
            .unwrap();
        let workspace = destination.path().join("workspace");
        fs::write(workspace.join("modify"), b"target").unwrap();
        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy::default(),
            )
            .unwrap();

        delta
            .apply_to_directory(
                &workspace,
                SnapshotDeltaApplyMode::Resume,
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(fs::read(workspace.join("modify")).unwrap(), b"target");
        assert!(!workspace.join("delete").exists());
    }

    #[test]
    fn delta_defers_before_writing_when_the_shared_workdir_lock_is_contended() {
        use std::os::fd::AsRawFd as _;

        let (_source, _base_storage, _target_storage, base, target) = snapshots();
        let destination = tempfile::tempdir().unwrap();
        base.materialize(destination.path().join("workspace"))
            .unwrap();
        let workspace = destination.path().join("workspace");
        let held = fs::File::open(&workspace).unwrap();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy::default(),
            )
            .unwrap();

        assert!(matches!(
            delta.apply_to_directory(&workspace, SnapshotDeltaApplyMode::Initial, Duration::ZERO,),
            Err(SnapshotError::DeltaDeferred(_))
        ));
        assert_eq!(fs::read(workspace.join("modify")).unwrap(), b"base");
        assert!(workspace.join("delete").exists());
    }

    #[test]
    fn dependency_conflict_is_checked_under_the_delta_lock_before_writing() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let target_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("dependency"), b"base").unwrap();
        fs::write(source.path().join("output"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join("output"), b"target").unwrap();
        let target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
        let workspace_parent = tempfile::tempdir().unwrap();
        base.materialize(workspace_parent.path().join("workspace"))
            .unwrap();
        let workspace = workspace_parent.path().join("workspace");
        fs::write(workspace.join("dependency"), b"stale").unwrap();
        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy::default(),
            )
            .unwrap();

        assert!(matches!(
            delta.apply_to_directory_with_requirements(
                &workspace,
                SnapshotDeltaApplyMode::Initial,
                &[SnapshotRequirement {
                    path: "dependency".into(),
                    scope: crate::snapshot::SnapshotCompareScope::Content,
                }],
                SnapshotCompareLimits::default(),
                Duration::from_secs(1),
            ),
            Err(SnapshotError::DeltaConflict { .. })
        ));
        assert_eq!(fs::read(workspace.join("output")).unwrap(), b"base");
    }

    #[test]
    fn dependency_change_during_apply_is_fail_closed_after_writing() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let target_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("dependency"), b"base").unwrap();
        fs::write(source.path().join("output"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join("output"), b"target").unwrap();
        let target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
        let workspace_parent = tempfile::tempdir().unwrap();
        base.materialize(workspace_parent.path().join("workspace"))
            .unwrap();
        let workspace = workspace_parent.path().join("workspace");
        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy::default(),
            )
            .unwrap();
        let dependency = workspace.join("dependency");

        assert!(matches!(
            delta.apply_to_directory_inner(
                &workspace,
                SnapshotDeltaApplyMode::Initial,
                &[SnapshotRequirement {
                    path: "dependency".into(),
                    scope: crate::snapshot::SnapshotCompareScope::Content,
                }],
                SnapshotCompareLimits::default(),
                Duration::from_secs(1),
                || fs::write(dependency, b"raced").unwrap(),
            ),
            Err(SnapshotError::DeltaApplyIncomplete { .. })
        ));
        assert_eq!(fs::read(workspace.join("output")).unwrap(), b"target");
        assert_eq!(fs::read(workspace.join("dependency")).unwrap(), b"raced");
    }

    #[test]
    fn resume_accepts_each_dependency_at_base_or_target_state() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let target_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("one"), b"base").unwrap();
        fs::write(source.path().join("two"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join("one"), b"target").unwrap();
        fs::write(source.path().join("two"), b"target").unwrap();
        let target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
        let workspace_parent = tempfile::tempdir().unwrap();
        base.materialize(workspace_parent.path().join("workspace"))
            .unwrap();
        let workspace = workspace_parent.path().join("workspace");
        fs::write(workspace.join("one"), b"target").unwrap();
        let delta = base
            .delta_to(
                &target,
                SnapshotDeltaLimits::default(),
                &SnapshotDeltaPolicy::default(),
            )
            .unwrap();
        let requirements = ["one", "two"].map(|path| SnapshotRequirement {
            path: path.into(),
            scope: crate::snapshot::SnapshotCompareScope::Content,
        });

        delta
            .apply_to_directory_with_requirements(
                &workspace,
                SnapshotDeltaApplyMode::Resume,
                &requirements,
                SnapshotCompareLimits::default(),
                Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(fs::read(workspace.join("one")).unwrap(), b"target");
        assert_eq!(fs::read(workspace.join("two")).unwrap(), b"target");
    }
}
