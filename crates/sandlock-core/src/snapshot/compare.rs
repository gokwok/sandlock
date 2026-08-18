//! Scoped comparison between immutable snapshots.

use super::{
    compare_entry, inventory_bounded_with_modes, normalize_relative, EntryStamp, FsSnapshot,
    SnapshotEntryKind,
};
use crate::error::SnapshotError;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DEFAULT_REQUIREMENT_LIMIT: usize = 256;
const DEFAULT_COMPARE_ENTRY_LIMIT: usize = 100_000;
const DEFAULT_COMPARE_PATH_BYTE_LIMIT: usize = 16 * 1024 * 1024;
const DEFAULT_COMPARE_CONTENT_BYTE_LIMIT: u64 = 1024 * 1024 * 1024;

/// Generic filesystem fields covered by one scoped snapshot requirement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SnapshotCompareScope {
    /// Exact state of one entry: existence, kind, mode, file bytes, or symlink target.
    Content,
    /// Immediate child names and entry kinds for one directory.
    Entries,
    /// Recursive descendant names and entry kinds.
    TreeEntries,
    /// Recursive exact entry state including modes and regular-file bytes.
    TreeContent,
}

/// One snapshot-relative dependency to compare.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SnapshotRequirement {
    pub path: PathBuf,
    pub scope: SnapshotCompareScope,
}

/// Hard limits for a scoped comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotCompareLimits {
    pub max_requirements: usize,
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_content_bytes: u64,
}

impl Default for SnapshotCompareLimits {
    fn default() -> Self {
        Self {
            max_requirements: DEFAULT_REQUIREMENT_LIMIT,
            max_entries: DEFAULT_COMPARE_ENTRY_LIMIT,
            max_path_bytes: DEFAULT_COMPARE_PATH_BYTE_LIMIT,
            max_content_bytes: DEFAULT_COMPARE_CONTENT_BYTE_LIMIT,
        }
    }
}

/// Result and complete metrics for a scoped immutable comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotComparison {
    pub matched: bool,
    pub compared_entries: usize,
    pub compared_bytes: u64,
}

impl FsSnapshot {
    /// Compare selected filesystem dependencies with another immutable snapshot.
    pub fn compare_requirements(
        &self,
        current: &FsSnapshot,
        requirements: &[SnapshotRequirement],
        limits: SnapshotCompareLimits,
    ) -> Result<SnapshotComparison, SnapshotError> {
        self.ensure_live()?;
        current.ensure_live()?;
        let requirements = prepare_requirements(requirements, limits.max_requirements)?;
        let expected_modes = self.directory_modes()?;
        let expected = inventory_bounded_with_modes(
            &self.tree_dir,
            limits.max_entries,
            limits.max_path_bytes,
            Some(&expected_modes),
        )?;
        let current_modes = current.directory_modes()?;
        let remaining_entries =
            limits
                .max_entries
                .checked_sub(expected.len())
                .ok_or_else(|| {
                    SnapshotError::LimitExceeded(
                        "snapshot compare entry budget was exceeded".to_string(),
                    )
                })?;
        let current_inventory = inventory_bounded_with_modes(
            &current.tree_dir,
            remaining_entries,
            limits.max_path_bytes,
            Some(&current_modes),
        )?;
        let mut content_budget = limits.max_content_bytes;
        let mut compared_entries = 0_usize;
        let mut matched = true;
        for requirement in requirements {
            let result = match requirement.scope {
                SnapshotCompareScope::Content => compare_exact_paths(
                    &self.tree_dir,
                    &expected,
                    &current.tree_dir,
                    &current_inventory,
                    std::iter::once(requirement.path.clone()),
                    &mut content_budget,
                    &mut compared_entries,
                )?,
                SnapshotCompareScope::Entries => compare_entry_names(
                    &expected,
                    &current_inventory,
                    &requirement.path,
                    false,
                    &mut compared_entries,
                ),
                SnapshotCompareScope::TreeEntries => compare_entry_names(
                    &expected,
                    &current_inventory,
                    &requirement.path,
                    true,
                    &mut compared_entries,
                ),
                SnapshotCompareScope::TreeContent => {
                    let paths = subtree_paths(&expected, &current_inventory, &requirement.path);
                    compare_exact_paths(
                        &self.tree_dir,
                        &expected,
                        &current.tree_dir,
                        &current_inventory,
                        paths,
                        &mut content_budget,
                        &mut compared_entries,
                    )?
                }
            };
            matched &= result;
        }
        Ok(SnapshotComparison {
            matched,
            compared_entries,
            compared_bytes: limits.max_content_bytes.saturating_sub(content_budget),
        })
    }
}

fn prepare_requirements(
    requirements: &[SnapshotRequirement],
    max_requirements: usize,
) -> Result<Vec<SnapshotRequirement>, SnapshotError> {
    if requirements.len() > max_requirements {
        return Err(SnapshotError::LimitExceeded(format!(
            "snapshot compare has {} requirements; limit is {max_requirements}",
            requirements.len()
        )));
    }
    let mut prepared = requirements
        .iter()
        .map(|requirement| {
            Ok(SnapshotRequirement {
                path: normalize_relative(&requirement.path)?,
                scope: requirement.scope,
            })
        })
        .collect::<Result<Vec<_>, SnapshotError>>()?;
    prepared.sort();
    prepared.dedup();
    Ok(prepared)
}

fn compare_exact_paths(
    expected_root: &Path,
    expected: &BTreeMap<PathBuf, EntryStamp>,
    current_root: &Path,
    current: &BTreeMap<PathBuf, EntryStamp>,
    paths: impl IntoIterator<Item = PathBuf>,
    content_budget: &mut u64,
    compared_entries: &mut usize,
) -> Result<bool, SnapshotError> {
    let mut matched = true;
    for path in paths {
        *compared_entries = compared_entries.saturating_add(1);
        matched &= match (expected.get(&path), current.get(&path)) {
            (None, None) => true,
            (Some(left), Some(right)) => compare_entry(
                expected_root,
                current_root,
                &path,
                left,
                right,
                content_budget,
            )?
            .is_none(),
            _ => false,
        };
    }
    Ok(matched)
}

fn compare_entry_names(
    expected: &BTreeMap<PathBuf, EntryStamp>,
    current: &BTreeMap<PathBuf, EntryStamp>,
    root: &Path,
    recursive: bool,
    compared_entries: &mut usize,
) -> bool {
    let expected_root = expected.get(root);
    let current_root = current.get(root);
    *compared_entries = compared_entries.saturating_add(1);
    if expected_root.map(|entry| entry.kind) != current_root.map(|entry| entry.kind) {
        return false;
    }
    if expected_root.is_some_and(|entry| entry.kind != SnapshotEntryKind::Directory) {
        return true;
    }
    let expected_entries = named_entries(expected, root, recursive);
    let current_entries = named_entries(current, root, recursive);
    *compared_entries =
        compared_entries.saturating_add(expected_entries.len().max(current_entries.len()));
    expected_entries == current_entries
}

fn named_entries(
    inventory: &BTreeMap<PathBuf, EntryStamp>,
    root: &Path,
    recursive: bool,
) -> BTreeMap<PathBuf, SnapshotEntryKind> {
    inventory
        .iter()
        .filter_map(|(path, entry)| {
            if path == root || !path.starts_with(root) {
                return None;
            }
            if !recursive && path.parent() != Some(root) {
                return None;
            }
            let relative = path.strip_prefix(root).ok()?.to_path_buf();
            Some((relative, entry.kind))
        })
        .collect()
}

fn subtree_paths(
    expected: &BTreeMap<PathBuf, EntryStamp>,
    current: &BTreeMap<PathBuf, EntryStamp>,
    root: &Path,
) -> BTreeSet<PathBuf> {
    expected
        .keys()
        .chain(current.keys())
        .filter(|path| *path == root || path.starts_with(root))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scoped_compare_distinguishes_content_entries_and_recursive_content() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let current_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("tree")).unwrap();
        fs::write(source.path().join("one"), b"base").unwrap();
        fs::write(source.path().join("tree/child"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join("one"), b"changed").unwrap();
        fs::write(source.path().join("tree/child"), b"changed").unwrap();
        let current = FsSnapshot::capture(source.path(), current_storage.path()).unwrap();

        assert!(
            !base
                .compare_requirements(
                    &current,
                    &[SnapshotRequirement {
                        path: "one".into(),
                        scope: SnapshotCompareScope::Content,
                    }],
                    SnapshotCompareLimits::default(),
                )
                .unwrap()
                .matched
        );
        assert!(
            base.compare_requirements(
                &current,
                &[SnapshotRequirement {
                    path: "tree".into(),
                    scope: SnapshotCompareScope::TreeEntries,
                }],
                SnapshotCompareLimits::default(),
            )
            .unwrap()
            .matched
        );
        assert!(
            !base
                .compare_requirements(
                    &current,
                    &[SnapshotRequirement {
                        path: "tree".into(),
                        scope: SnapshotCompareScope::TreeContent,
                    }],
                    SnapshotCompareLimits::default(),
                )
                .unwrap()
                .matched
        );
    }

    #[test]
    fn tree_entries_detects_additions_and_explicit_missing_content_matches() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let current_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("tree")).unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        fs::write(source.path().join("tree/added"), b"new").unwrap();
        let current = FsSnapshot::capture(source.path(), current_storage.path()).unwrap();

        assert!(
            !base
                .compare_requirements(
                    &current,
                    &[SnapshotRequirement {
                        path: "tree".into(),
                        scope: SnapshotCompareScope::TreeEntries,
                    }],
                    SnapshotCompareLimits::default(),
                )
                .unwrap()
                .matched
        );
        assert!(
            base.compare_requirements(
                &current,
                &[SnapshotRequirement {
                    path: "missing".into(),
                    scope: SnapshotCompareScope::Content,
                }],
                SnapshotCompareLimits::default(),
            )
            .unwrap()
            .matched
        );
    }

    #[test]
    fn compare_enforces_requirement_and_content_budgets() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        let current_storage = tempfile::tempdir().unwrap();
        fs::write(source.path().join("value"), b"content").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
        let current = FsSnapshot::capture(source.path(), current_storage.path()).unwrap();
        let requirement = SnapshotRequirement {
            path: "value".into(),
            scope: SnapshotCompareScope::Content,
        };

        assert!(matches!(
            base.compare_requirements(
                &current,
                &[requirement.clone()],
                SnapshotCompareLimits {
                    max_requirements: 0,
                    ..SnapshotCompareLimits::default()
                },
            ),
            Err(SnapshotError::LimitExceeded(_))
        ));
        assert!(matches!(
            base.compare_requirements(
                &current,
                &[requirement],
                SnapshotCompareLimits {
                    max_content_bytes: 1,
                    ..SnapshotCompareLimits::default()
                },
            ),
            Err(SnapshotError::LimitExceeded(_))
        ));
    }
}
