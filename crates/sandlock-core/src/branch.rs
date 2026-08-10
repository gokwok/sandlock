//! Explicit lifecycle control for completed COW filesystem branches.

use crate::cow::seccomp::SeccompCowBranch;
use crate::dry_run::Change;
use crate::error::BranchError;
use crate::recovery::PreservedBranch;
use crate::result::RunResult;
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

    /// Paths whose lower-layer state changed after this branch first modified
    /// them. An empty result means no write conflict was detected.
    pub fn conflicts(&self) -> Result<Vec<PathBuf>, BranchError> {
        Ok(self.pending()?.conflicts())
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
    /// The branch must not have started a commit. On success this handle is
    /// resolved and [`FsBranch::reopen`] becomes the only supported way to
    /// continue using its staged changes.
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
            Err(error) => Err(error),
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

        assert!(branch.keep().is_err());
        assert_eq!(branch.state(), BranchState::Pending);
        let preserved =
            crate::recovery::read_preserved(branch.upper_dir().parent().unwrap()).unwrap();
        assert_eq!(
            preserved.reason,
            crate::recovery::PreserveReason::MergeInterrupted
        );
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
}
