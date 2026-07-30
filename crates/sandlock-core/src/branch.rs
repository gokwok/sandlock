//! Explicit lifecycle control for completed COW filesystem branches.

use crate::cow::seccomp::SeccompCowBranch;
use crate::dry_run::Change;
use crate::error::BranchError;
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
}

/// A completed sandbox run whose COW filesystem changes await an explicit
/// commit or abort decision.
#[derive(Debug)]
#[must_use = "dropping the result aborts its pending COW branch"]
pub struct PendingRunResult {
    /// Exit status and captured standard output/error from the command.
    pub run_result: RunResult,
    /// Retained COW filesystem branch for the command.
    pub branch: PendingBranch,
}

impl PendingRunResult {
    /// Split the command result from the retained filesystem branch.
    pub fn into_parts(self) -> (RunResult, PendingBranch) {
        (self.run_result, self.branch)
    }
}

/// A lightweight handle to a completed COW filesystem branch.
///
/// The sandbox process and its supervisor have already been reaped when this
/// handle is produced. File contents remain in the branch's on-disk upper
/// directory; only branch metadata is retained in memory.
///
/// Dropping a pending handle aborts the branch, so callers must explicitly
/// call [`PendingBranch::commit`] to publish its changes.
#[must_use = "dropping a pending branch aborts its staged changes"]
pub struct PendingBranch {
    inner: Option<SeccompCowBranch>,
    workdir: PathBuf,
    upper_dir: PathBuf,
    state: BranchState,
}

impl PendingBranch {
    pub(crate) fn new(branch: SeccompCowBranch) -> Self {
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

    /// Merge this branch into its workdir.
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

    fn pending(&self) -> Result<&SeccompCowBranch, BranchError> {
        self.inner.as_ref().ok_or(BranchError::AlreadyResolved)
    }

    fn pending_mut(&mut self) -> Result<&mut SeccompCowBranch, BranchError> {
        self.inner.as_mut().ok_or(BranchError::AlreadyResolved)
    }
}

impl fmt::Debug for PendingBranch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingBranch")
            .field("workdir", &self.workdir)
            .field("upper_dir", &self.upper_dir)
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for PendingBranch {
    fn drop(&mut self) {
        if let Some(ref mut branch) = self.inner {
            let _ = branch.abort();
        }
    }
}

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
}
