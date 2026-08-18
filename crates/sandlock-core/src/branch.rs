//! Explicit lifecycle control for completed COW filesystem branches.

use crate::cow::seccomp::SeccompCowBranch;
use crate::dry_run::Change;
use crate::error::BranchError;
use crate::recovery::PreservedBranch;
use crate::result::RunResult;
use crate::snapshot::FsSnapshot;
use std::fmt;
use std::path::{Path, PathBuf};

/// Resolution state of a retained COW branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchState {
    /// The branch is retained and may be committed or aborted.
    Pending,
    /// The branch was merged into its workdir.
    Committed,
    /// The branch was discarded.
    Aborted,
    /// The branch was persisted for a later process to reopen.
    Persisted,
    /// The branch is temporarily owned by a sandbox process.
    Attached,
    /// The branch was preserved for manual recovery.
    Kept,
}

/// Bounded view of a pending branch.
#[derive(Debug)]
pub struct BranchInspection {
    /// Retained changed paths, up to the caller's per-list limit.
    pub changes: Vec<Change>,
    /// Total number of changed paths in the branch.
    pub changed_paths: usize,
    /// Retained conflicting paths, up to the caller's per-list limit.
    pub conflicts: Vec<PathBuf>,
    /// Total number of conflicting paths in the branch.
    pub conflicting_paths: usize,
}

/// A completed sandbox run whose COW filesystem changes await an explicit
/// commit or abort decision.
#[derive(Debug)]
#[must_use = "dropping the result aborts its pending COW branch"]
pub struct PendingRunResult {
    /// Exit status and captured standard output/error from the command.
    pub run_result: RunResult,
    /// Retained COW filesystem branch for the command.
    pub branch: FsBranch,
}

impl PendingRunResult {
    /// Split the command result from the retained filesystem branch.
    pub fn into_parts(self) -> (RunResult, FsBranch) {
        (self.run_result, self.branch)
    }
}

/// A reusable copy-on-write filesystem branch.
///
/// Commands may be run serially against the branch with
/// [`crate::Sandbox::run_in_branch`]. Each command sees changes staged by
/// earlier commands in the same branch while the lower directory remains
/// unchanged until commit.
///
/// Dropping an unresolved handle aborts the branch, so callers must explicitly
/// call [`FsBranch::commit`] to publish its changes.
#[must_use = "dropping an unresolved branch aborts its staged changes"]
pub struct FsBranch {
    inner: Option<SeccompCowBranch>,
    workdir: PathBuf,
    upper_dir: PathBuf,
    state: BranchState,
}

impl FsBranch {
    /// Create a branch with temporary on-disk COW storage.
    pub fn create(workdir: impl AsRef<Path>) -> Result<Self, BranchError> {
        SeccompCowBranch::create(workdir.as_ref(), None, 0).map(Self::new)
    }

    /// Create a branch whose immutable lower is `snapshot`.
    ///
    /// The branch holds a durable lease on the snapshot until it is aborted,
    /// dropped, or otherwise disposed. Snapshot-backed branches cannot be
    /// committed into their lower; use [`FsBranch::checkpoint`] to publish a
    /// new immutable snapshot instead.
    pub fn from_snapshot(
        snapshot: &FsSnapshot,
        storage: impl AsRef<Path>,
    ) -> Result<Self, BranchError> {
        Self::from_snapshot_options(snapshot, Some(storage.as_ref()), 0)
    }

    /// Create a quota-limited branch whose immutable lower is `snapshot`.
    pub fn from_snapshot_with_quota(
        snapshot: &FsSnapshot,
        storage: impl AsRef<Path>,
        max_disk_bytes: u64,
    ) -> Result<Self, BranchError> {
        Self::from_snapshot_options(snapshot, Some(storage.as_ref()), max_disk_bytes)
    }

    pub(crate) fn from_snapshot_options(
        snapshot: &FsSnapshot,
        storage: Option<&Path>,
        max_disk_bytes: u64,
    ) -> Result<Self, BranchError> {
        let mut branch = SeccompCowBranch::create(snapshot.root_dir(), storage, max_disk_bytes)?;
        branch.set_lower_directory_modes(
            snapshot
                .directory_modes()
                .map_err(BranchError::Snapshot)?,
        );
        let lease = snapshot
            .acquire_branch_lease(branch.storage_dir())
            .map_err(BranchError::Snapshot)?;
        branch.set_snapshot_lease(lease);
        Ok(Self::new(branch))
    }

    pub(crate) fn new(mut branch: SeccompCowBranch) -> Self {
        branch.track_conflicts();
        Self {
            workdir: branch.workdir().to_path_buf(),
            upper_dir: branch.upper_dir().to_path_buf(),
            inner: Some(branch),
            state: BranchState::Pending,
        }
    }

    /// Current resolution state.
    pub fn state(&self) -> BranchState {
        self.state
    }

    /// Lower workdir into which a successful commit is merged.
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// Alias for [`FsBranch::workdir`] that describes its role as the lower
    /// COW layer.
    pub fn lower_dir(&self) -> &Path {
        &self.workdir
    }

    /// On-disk upper directory containing staged file additions and writes.
    ///
    /// The directory is removed after commit, abort, or dropping a pending
    /// branch.
    pub fn upper_dir(&self) -> &Path {
        &self.upper_dir
    }

    /// Return the staged added, modified, and deleted paths.
    pub fn changes(&self) -> Result<Vec<Change>, BranchError> {
        self.pending()?.changes()
    }

    /// Inspect the branch while retaining at most `max_paths` entries from
    /// each list. Total counts always cover the complete branch.
    pub fn inspect(&self, max_paths: usize) -> Result<BranchInspection, BranchError> {
        let (changes, changed_paths, conflicts, conflicting_paths) =
            self.pending()?.inspect(max_paths)?;
        Ok(BranchInspection {
            changes,
            changed_paths,
            conflicts,
            conflicting_paths,
        })
    }

    /// Paths whose lower-layer state changed after this branch first modified
    /// them. An empty result means no write conflict was detected.
    pub fn conflicts(&self) -> Result<Vec<PathBuf>, BranchError> {
        Ok(self.pending()?.conflicts())
    }

    /// Capture the branch's current merged view as a new immutable snapshot.
    ///
    /// This is non-terminal: the branch and its staged changes remain usable,
    /// and later changes do not affect the returned snapshot.
    pub fn checkpoint(
        &self,
        snapshot_storage: impl AsRef<Path>,
    ) -> Result<FsSnapshot, BranchError> {
        self.pending()?.checkpoint(snapshot_storage.as_ref())
    }

    /// Apply a validated immutable snapshot delta to this pending branch.
    ///
    /// The delta is written into the existing upper and whiteout state. The branch stays pending
    /// and may be checkpointed or used by later sandbox runs. Callers must first validate the
    /// branch's quiescent merged view against the delta base.
    pub fn apply_snapshot_delta(
        &mut self,
        delta: &crate::snapshot::SnapshotDelta<'_>,
    ) -> Result<crate::snapshot::SnapshotDeltaSummary, BranchError> {
        self.pending_mut()?.apply_snapshot_delta(delta)
    }

    /// Whether this branch uses an immutable snapshot as its lower.
    pub fn is_snapshot_backed(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(SeccompCowBranch::is_snapshot_backed)
    }

    /// Merge this branch into its workdir.
    ///
    /// The merge is rejected before writing when [`FsBranch::conflicts`]
    /// reports a lower-layer change.
    ///
    /// A failed commit leaves the handle pending so the caller can inspect,
    /// retry, or abort it. The merge is not atomic: a failure may occur after
    /// some paths have already been applied.
    pub fn commit(&mut self) -> Result<(), BranchError> {
        self.pending_mut()?.commit()?;
        self.inner = None;
        self.state = BranchState::Committed;
        Ok(())
    }

    /// Discard all staged changes.
    ///
    /// A failed abort leaves the handle pending so the caller can retry.
    pub fn abort(&mut self) -> Result<(), BranchError> {
        self.pending_mut()?.abort()?;
        self.inner = None;
        self.state = BranchState::Aborted;
        Ok(())
    }

    /// Persist this branch so another process can reopen it.
    ///
    /// Accepts an open branch or a commit deferred before publication. A branch
    /// whose merge may have started requires recovery instead. On success this
    /// handle is resolved and [`FsBranch::reopen`] becomes the only supported
    /// way to continue using its staged changes.
    pub fn persist(&mut self) -> Result<PreservedBranch, BranchError> {
        match self.pending_mut()?.persist_for_reopen() {
            Ok(preserved) => {
                self.inner = None;
                self.state = BranchState::Persisted;
                Ok(preserved)
            }
            Err(error @ BranchError::Published { .. }) => {
                self.inner = None;
                self.state = BranchState::Persisted;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Preserve staged changes for manual recovery without merging them.
    ///
    /// This is a terminal disposition. If durable publication fails, the
    /// branch storage is still retained and this handle is resolved so that
    /// dropping it cannot discard the only remaining copy.
    pub fn keep(&mut self) -> Result<PreservedBranch, BranchError> {
        match self.pending_mut()?.keep_for_recovery() {
            Ok(preserved) => {
                self.inner = None;
                self.state = BranchState::Kept;
                Ok(preserved)
            }
            Err(error @ BranchError::Published { .. }) => {
                self.inner = None;
                self.state = BranchState::Kept;
                Err(error)
            }
            Err(error) => {
                if self.pending()?.is_preserved() {
                    self.inner = None;
                    self.state = BranchState::Kept;
                }
                Err(error)
            }
        }
    }

    /// Reopen a branch previously resolved with [`FsBranch::persist`].
    pub fn reopen(preserved: PreservedBranch) -> Result<Self, BranchError> {
        SeccompCowBranch::reopen(preserved).map(Self::new)
    }

    fn pending(&self) -> Result<&SeccompCowBranch, BranchError> {
        self.inner.as_ref().ok_or(BranchError::AlreadyResolved)
    }

    fn pending_mut(&mut self) -> Result<&mut SeccompCowBranch, BranchError> {
        self.inner.as_mut().ok_or(BranchError::AlreadyResolved)
    }

    pub(crate) fn take_cow(&mut self) -> Result<SeccompCowBranch, BranchError> {
        let branch = self.inner.take().ok_or(BranchError::AlreadyResolved)?;
        self.state = BranchState::Attached;
        Ok(branch)
    }

    pub(crate) fn replace_cow(&mut self, branch: SeccompCowBranch) {
        self.workdir = branch.workdir().to_path_buf();
        self.upper_dir = branch.upper_dir().to_path_buf();
        self.inner = Some(branch);
        self.state = BranchState::Pending;
    }
}

impl fmt::Debug for FsBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsBranch")
            .field("workdir", &self.workdir)
            .field("upper_dir", &self.upper_dir)
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for FsBranch {
    fn drop(&mut self) {
        if let Some(ref mut branch) = self.inner {
            let _ = branch.abort();
        }
    }
}

/// Backwards-compatible name for an [`FsBranch`] returned by
/// [`crate::Sandbox::run_pending`].
pub type PendingBranch = FsBranch;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dry_run::ChangeKind;
    use crate::error::SnapshotError;
    use std::fs;

    fn pending_branch() -> (tempfile::TempDir, tempfile::TempDir, PendingBranch) {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("existing.txt"), "original").unwrap();

        let branch = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        fs::write(branch.upper_dir().join("existing.txt"), "changed").unwrap();
        fs::write(branch.upper_dir().join("added.txt"), "added").unwrap();

        (workdir, storage, PendingBranch::new(branch))
    }

    #[test]
    fn commit_publishes_retained_changes() {
        let (workdir, _storage, mut branch) = pending_branch();
        let upper = branch.upper_dir().to_path_buf();

        let changes = branch.changes().unwrap();
        assert!(changes
            .iter()
            .any(|c| c.kind == ChangeKind::Modified && c.path == Path::new("existing.txt")));
        assert!(changes
            .iter()
            .any(|c| c.kind == ChangeKind::Added && c.path == Path::new("added.txt")));

        branch.commit().unwrap();

        assert_eq!(branch.state(), BranchState::Committed);
        assert_eq!(
            fs::read_to_string(workdir.path().join("existing.txt")).unwrap(),
            "changed"
        );
        assert_eq!(
            fs::read_to_string(workdir.path().join("added.txt")).unwrap(),
            "added"
        );
        assert!(!upper.exists());
        assert!(matches!(branch.commit(), Err(BranchError::AlreadyResolved)));
    }

    #[test]
    fn abort_discards_retained_changes() {
        let (workdir, _storage, mut branch) = pending_branch();
        let upper = branch.upper_dir().to_path_buf();

        branch.abort().unwrap();

        assert_eq!(branch.state(), BranchState::Aborted);
        assert_eq!(
            fs::read_to_string(workdir.path().join("existing.txt")).unwrap(),
            "original"
        );
        assert!(!workdir.path().join("added.txt").exists());
        assert!(!upper.exists());
        assert!(matches!(
            branch.changes(),
            Err(BranchError::AlreadyResolved)
        ));
    }

    #[test]
    fn dropping_pending_branch_aborts_it() {
        let (workdir, _storage, branch) = pending_branch();
        let upper = branch.upper_dir().to_path_buf();

        drop(branch);

        assert_eq!(
            fs::read_to_string(workdir.path().join("existing.txt")).unwrap(),
            "original"
        );
        assert!(!workdir.path().join("added.txt").exists());
        assert!(!upper.exists());
    }

    #[test]
    fn snapshot_branch_checkpoint_is_non_terminal_and_holds_a_lease() {
        let source = tempfile::tempdir().unwrap();
        let snapshot_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        let checkpoint_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("existing.txt"), b"original").unwrap();
        fs::write(source.path().join("deleted.txt"), b"remove me").unwrap();
        let mut base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();

        let mut branch = FsBranch::from_snapshot(&base, branch_storage.path()).unwrap();
        fs::write(branch.upper_dir().join("existing.txt"), b"checkpointed").unwrap();
        fs::write(branch.upper_dir().join("added.txt"), b"added").unwrap();
        branch.inner.as_mut().unwrap().mark_deleted("deleted.txt");

        assert!(matches!(
            base.destroy(),
            Err(SnapshotError::InUse { count: 1 })
        ));
        assert!(matches!(branch.commit(), Err(BranchError::Denied)));
        assert_eq!(branch.state(), BranchState::Pending);

        let checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
        fs::write(branch.upper_dir().join("existing.txt"), b"later").unwrap();
        assert_eq!(
            checkpoint.read_range("existing.txt", 0, 64).unwrap(),
            b"checkpointed"
        );
        assert_eq!(checkpoint.read_range("added.txt", 0, 64).unwrap(), b"added");
        assert!(checkpoint.stat("deleted.txt").is_err());

        branch.abort().unwrap();
        base.destroy().unwrap();
    }

    #[test]
    fn checkpoint_does_not_publish_placeholder_parent_modes() {
        use std::os::unix::fs::PermissionsExt;

        let source = tempfile::tempdir().unwrap();
        let snapshot_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        let checkpoint_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("private")).unwrap();
        fs::set_permissions(
            source.path().join("private"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(source.path().join("private/file"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
        let mut branch = FsBranch::from_snapshot(&base, branch_storage.path()).unwrap();

        let upper = branch
            .pending_mut()
            .unwrap()
            .ensure_cow_copy("private/file")
            .unwrap();
        fs::write(upper, b"changed").unwrap();
        let checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();

        assert_eq!(
            checkpoint.stat("private").unwrap().mode,
            0o700
        );
    }

    #[test]
    fn checkpoint_does_not_publish_placeholder_descendant_modes() {
        use std::os::unix::fs::PermissionsExt;

        let source = tempfile::tempdir().unwrap();
        let snapshot_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        let checkpoint_storage = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("a/b")).unwrap();
        fs::set_permissions(source.path().join("a/b"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(source.path().join("a/b/file"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
        let mut branch = FsBranch::from_snapshot(&base, branch_storage.path()).unwrap();
        let lower_a = base.root_dir().join("a");
        branch
            .pending_mut()
            .unwrap()
            .handle_chmod(lower_a.to_str().unwrap(), 0o711)
            .unwrap();
        let upper = branch
            .pending_mut()
            .unwrap()
            .ensure_cow_copy("a/b/file")
            .unwrap();
        fs::write(upper, b"changed").unwrap();

        let checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
        assert_eq!(
            checkpoint.stat("a").unwrap().mode,
            0o711
        );
        assert_eq!(
            checkpoint.stat("a/b").unwrap().mode,
            0o700
        );
    }

    #[test]
    fn checkpoint_preserves_modes_in_a_renamed_directory_tree() {
        use std::os::unix::fs::PermissionsExt;

        let source = tempfile::tempdir().unwrap();
        let snapshot_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        let checkpoint_storage = tempfile::tempdir().unwrap();
        fs::create_dir_all(source.path().join("old/child/grandchild")).unwrap();
        fs::set_permissions(
            source.path().join("old"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::set_permissions(
            source.path().join("old/child"),
            fs::Permissions::from_mode(0o711),
        )
        .unwrap();
        fs::set_permissions(
            source.path().join("old/child/grandchild"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
        let mut branch = FsBranch::from_snapshot(&base, branch_storage.path()).unwrap();
        let old = base.root_dir().join("old");
        let new = base.root_dir().join("new");

        assert!(branch
            .pending_mut()
            .unwrap()
            .handle_rename(old.to_str().unwrap(), new.to_str().unwrap())
            .unwrap());
        let checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();

        for (path, expected) in [
            ("new", 0o750),
            ("new/child", 0o711),
            ("new/child/grandchild", 0o700),
        ] {
            assert_eq!(
                checkpoint.stat(path).unwrap().mode,
                expected,
                "mode mismatch for {path}"
            );
        }
        assert!(!checkpoint.root_dir().join("old").exists());
    }

    #[test]
    fn snapshot_lower_modes_follow_merged_type_and_metadata_copy_up() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let first_branch_storage = tempfile::tempdir().unwrap();
        let first_checkpoint_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("restricted")).unwrap();
        let base = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let mut first = FsBranch::from_snapshot(&base, first_branch_storage.path()).unwrap();
        let restricted = base.root_dir().join("restricted");
        first
            .pending_mut()
            .unwrap()
            .handle_chmod(restricted.to_str().unwrap(), 0o000)
            .unwrap();
        let restricted_snapshot = first.checkpoint(first_checkpoint_storage.path()).unwrap();
        assert_eq!(restricted_snapshot.stat("restricted").unwrap().mode, 0o000);

        let copy_branch_storage = tempfile::tempdir().unwrap();
        let copy_checkpoint_storage = tempfile::tempdir().unwrap();
        let mut copied =
            FsBranch::from_snapshot(&restricted_snapshot, copy_branch_storage.path()).unwrap();
        let restricted = restricted_snapshot.root_dir().join("restricted");
        copied
            .pending_mut()
            .unwrap()
            .handle_chown(restricted.to_str().unwrap(), 0, 0)
            .unwrap();
        let copied_checkpoint = copied.checkpoint(copy_checkpoint_storage.path()).unwrap();
        assert_eq!(copied_checkpoint.stat("restricted").unwrap().mode, 0o000);

        let replace_branch_storage = tempfile::tempdir().unwrap();
        let replace_checkpoint_storage = tempfile::tempdir().unwrap();
        let mut replaced =
            FsBranch::from_snapshot(&restricted_snapshot, replace_branch_storage.path()).unwrap();
        assert!(replaced
            .pending_mut()
            .unwrap()
            .handle_unlink(restricted.to_str().unwrap(), true)
            .unwrap());
        assert!(replaced
            .pending_mut()
            .unwrap()
            .handle_mknod(restricted.to_str().unwrap(), libc::S_IFREG as u32 | 0o600, 0)
            .unwrap());
        assert!(replaced
            .pending()
            .unwrap()
            .logical_directory_mode(restricted.to_str().unwrap())
            .is_none());
        let replaced_checkpoint = replaced.checkpoint(replace_checkpoint_storage.path()).unwrap();
        assert_eq!(
            replaced_checkpoint.stat("restricted").unwrap().kind,
            crate::snapshot::SnapshotEntryKind::File
        );
    }

    #[test]
    fn persisted_snapshot_branch_reopens_with_its_lease() {
        let source = tempfile::tempdir().unwrap();
        let snapshot_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file.txt"), b"base").unwrap();
        let mut snapshot = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
        let mut branch = FsBranch::from_snapshot(&snapshot, branch_storage.path()).unwrap();
        fs::write(branch.upper_dir().join("file.txt"), b"staged").unwrap();

        let preserved = branch.persist().unwrap();
        assert!(matches!(
            snapshot.destroy(),
            Err(SnapshotError::InUse { count: 1 })
        ));
        let mut reopened = FsBranch::reopen(preserved).unwrap();
        assert!(reopened.is_snapshot_backed());
        reopened.abort().unwrap();
        snapshot.destroy().unwrap();
    }

    #[test]
    fn snapshot_branch_uses_canonical_storage_and_schema_two() {
        let source = tempfile::tempdir().unwrap();
        let snapshot_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("file.txt"), b"base").unwrap();
        let snapshot = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
        let mut branch = FsBranch::from_snapshot(&snapshot, branch_storage.path()).unwrap();

        let storage_dir = branch.pending().unwrap().storage_dir().to_path_buf();
        assert!(storage_dir.is_absolute());
        let preserved = branch.persist().unwrap();
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(preserved.branch_dir.join("REOPEN.json")).unwrap())
                .unwrap();
        assert_eq!(metadata["schema_version"], 2);

        FsBranch::reopen(preserved).unwrap().abort().unwrap();
    }

    #[test]
    fn persisted_branch_reopens_with_its_conflict_baseline() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("changed.txt"), "original").unwrap();
        fs::write(workdir.path().join("deleted.txt"), "original").unwrap();

        let cow = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let mut branch = FsBranch::new(cow);
        let upper = branch
            .pending_mut()
            .unwrap()
            .ensure_cow_copy("changed.txt")
            .unwrap();
        fs::write(upper, "staged").unwrap();
        branch.pending_mut().unwrap().mark_deleted("deleted.txt");
        fs::write(workdir.path().join("changed.txt"), "lower changed").unwrap();

        let preserved = branch.persist().unwrap();
        assert_eq!(branch.state(), BranchState::Persisted);
        fs::write(preserved.branch_dir.join("deleted.log"), "").unwrap();

        let mut reopened = FsBranch::reopen(preserved).unwrap();
        assert_eq!(reopened.state(), BranchState::Pending);
        assert_eq!(
            reopened.conflicts().unwrap(),
            vec![PathBuf::from("changed.txt")]
        );
        assert!(reopened
            .changes()
            .unwrap()
            .iter()
            .any(|change| change.path == Path::new("deleted.txt")));
        reopened.abort().unwrap();
    }

    #[test]
    fn reopen_uses_marker_deletions_instead_of_a_torn_log() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(workdir.path().join("foo"), "keep").unwrap();
        fs::write(workdir.path().join("foobar"), "delete").unwrap();

        let cow = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let mut branch = FsBranch::new(cow);
        branch.pending_mut().unwrap().mark_deleted("foobar");
        let preserved = branch.persist().unwrap();
        fs::write(preserved.branch_dir.join("deleted.log"), "foo").unwrap();

        let mut reopened = FsBranch::reopen(preserved).unwrap();
        reopened.commit().unwrap();
        assert_eq!(
            fs::read_to_string(workdir.path().join("foo")).unwrap(),
            "keep"
        );
        assert!(!workdir.path().join("foobar").exists());
    }

    #[test]
    fn reopen_does_not_follow_upper_symlinks() {
        use std::os::unix::fs::symlink;

        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let cow = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let mut branch = FsBranch::new(cow);
        symlink(".", branch.upper_dir().join("loop")).unwrap();

        let preserved = branch.persist().unwrap();
        let mut reopened = FsBranch::reopen(preserved).unwrap();
        reopened.abort().unwrap();
    }

    #[test]
    fn keep_does_not_downgrade_an_interrupted_merge() {
        let (_workdir, _storage, mut branch) = pending_branch();
        branch
            .pending_mut()
            .unwrap()
            .preserve_durable(crate::recovery::PreserveReason::MergeInterrupted)
            .unwrap();

        branch.keep().unwrap();
        assert_eq!(branch.state(), BranchState::Kept);
        let preserved =
            crate::recovery::read_preserved(branch.upper_dir().parent().unwrap()).unwrap();
        assert_eq!(
            preserved.reason,
            crate::recovery::PreserveReason::MergeInterrupted
        );
    }

    #[test]
    fn failed_keep_still_retains_the_branch_storage() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let cow = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let mut branch = FsBranch::new(cow);
        let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();
        fs::create_dir(branch_dir.join(".PRESERVED.tmp")).unwrap();

        assert!(branch.keep().is_err());
        assert_eq!(branch.state(), BranchState::Kept);
        drop(branch);
        assert!(branch_dir.exists());
    }

    #[test]
    fn failed_persist_can_be_retried() {
        let workdir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let cow = SeccompCowBranch::create(workdir.path(), Some(storage.path()), 0).unwrap();
        let mut branch = FsBranch::new(cow);
        let obstruction = branch.upper_dir().parent().unwrap().join(".PRESERVED.tmp");
        fs::create_dir(&obstruction).unwrap();

        assert!(branch.persist().is_err());
        assert_eq!(branch.state(), BranchState::Pending);

        fs::remove_dir(obstruction).unwrap();
        let preserved = branch.persist().unwrap();
        let mut reopened = FsBranch::reopen(preserved).unwrap();
        reopened.abort().unwrap();
    }

    #[test]
    fn snapshot_delta_updates_a_pending_snapshot_branch_without_resolving_it() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let target_storage = tempfile::tempdir().unwrap();
        let branch_storage = tempfile::tempdir().unwrap();
        let checkpoint_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("value"), b"base").unwrap();
        fs::write(source.path().join("deleted"), b"gone").unwrap();
        let mut base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join("value"), b"target").unwrap();
        fs::remove_file(source.path().join("deleted")).unwrap();
        fs::write(source.path().join("added"), b"new").unwrap();
        let mut target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
        let delta = base
            .delta_to(
                &target,
                crate::snapshot::SnapshotDeltaLimits::default(),
                &crate::snapshot::SnapshotDeltaPolicy {
                    allow_symlinks: false,
                    protected_paths: Vec::new(),
                },
            )
            .unwrap();
        let mut branch = FsBranch::from_snapshot(&base, branch_storage.path()).unwrap();

        assert_eq!(branch.apply_snapshot_delta(&delta).unwrap(), delta.summary());
        assert_eq!(branch.state(), BranchState::Pending);
        let mut checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
        assert_eq!(checkpoint.read_range("value", 0, 16).unwrap(), b"target");
        assert_eq!(checkpoint.read_range("added", 0, 16).unwrap(), b"new");
        assert!(checkpoint.stat("deleted").is_err());
        assert_eq!(base.read_range("value", 0, 16).unwrap(), b"base");

        branch.abort().unwrap();
        checkpoint.destroy().unwrap();
        target.destroy().unwrap();
        base.destroy().unwrap();
    }
}
