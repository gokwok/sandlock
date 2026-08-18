//! Scoped comparison between immutable snapshots.

use super::{
    compare_entry, inventory_bounded_with_modes, normalize_relative, stamp,
    validate_plain_directory, EntryStamp, FsSnapshot, SnapshotEntryKind,
};
use crate::error::SnapshotError;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
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

    /// Compare selected snapshot dependencies directly with a live directory.
    ///
    /// Only the declared exact path, immediate entries, or recursive subtree is scanned for each
    /// requirement. The destination is never copied into another snapshot.
    pub fn compare_directory_requirements(
        &self,
        current: impl AsRef<Path>,
        requirements: &[SnapshotRequirement],
        limits: SnapshotCompareLimits,
    ) -> Result<SnapshotComparison, SnapshotError> {
        self.ensure_live()?;
        let current = current.as_ref();
        validate_plain_directory(current, "snapshot requirement destination")?;
        let requirements = prepare_requirements(requirements, limits.max_requirements)?;
        let expected_modes = self.directory_modes()?;
        compare_directory_scopes(
            &self.tree_dir,
            Some(&expected_modes),
            None,
            current,
            &requirements,
            limits,
        )
    }

    /// Compare each declared dependency with either this snapshot or one alternative snapshot.
    ///
    /// This is used only for resumable delta recovery, where individual paths may already have
    /// reached TARGET while the remainder still matches BASE.
    pub fn compare_directory_requirements_allowing(
        &self,
        alternative: &FsSnapshot,
        current: impl AsRef<Path>,
        requirements: &[SnapshotRequirement],
        limits: SnapshotCompareLimits,
    ) -> Result<SnapshotComparison, SnapshotError> {
        self.ensure_live()?;
        alternative.ensure_live()?;
        let current = current.as_ref();
        validate_plain_directory(current, "snapshot requirement destination")?;
        let requirements = prepare_requirements(requirements, limits.max_requirements)?;
        let expected_modes = self.directory_modes()?;
        let alternative_modes = alternative.directory_modes()?;
        compare_directory_scopes(
            &self.tree_dir,
            Some(&expected_modes),
            Some((&alternative.tree_dir, &alternative_modes)),
            current,
            &requirements,
            limits,
        )
    }
}

fn compare_directory_scopes(
    expected_root: &Path,
    expected_modes: Option<&BTreeMap<PathBuf, u32>>,
    alternative: Option<(&Path, &BTreeMap<PathBuf, u32>)>,
    current_root: &Path,
    requirements: &[SnapshotRequirement],
    limits: SnapshotCompareLimits,
) -> Result<SnapshotComparison, SnapshotError> {
    let mut remaining_entries = limits.max_entries;
    let mut remaining_path_bytes = limits.max_path_bytes;
    let mut content_budget = limits.max_content_bytes;
    let mut compared_entries = 0_usize;
    let mut matched = true;
    for requirement in requirements {
        let scan = match requirement.scope {
            SnapshotCompareScope::Content => ScopedScan::Exact,
            SnapshotCompareScope::Entries => ScopedScan::Immediate,
            SnapshotCompareScope::TreeEntries | SnapshotCompareScope::TreeContent => {
                ScopedScan::Recursive
            }
        };
        let expected = scoped_inventory(
            expected_root,
            &requirement.path,
            scan,
            expected_modes,
            &mut remaining_entries,
            &mut remaining_path_bytes,
        )?;
        let current = scoped_inventory(
            current_root,
            &requirement.path,
            scan,
            None,
            &mut remaining_entries,
            &mut remaining_path_bytes,
        )?;
        let mut result = compare_one_scope(
            expected_root,
            &expected,
            current_root,
            &current,
            requirement,
            &mut content_budget,
            &mut compared_entries,
        )?;
        if !result {
            if let Some((alternative_root, alternative_modes)) = alternative {
                let alternative = scoped_inventory(
                    alternative_root,
                    &requirement.path,
                    scan,
                    Some(alternative_modes),
                    &mut remaining_entries,
                    &mut remaining_path_bytes,
                )?;
                result = compare_one_scope(
                    alternative_root,
                    &alternative,
                    current_root,
                    &current,
                    requirement,
                    &mut content_budget,
                    &mut compared_entries,
                )?;
            }
        }
        matched &= result;
    }
    Ok(SnapshotComparison {
        matched,
        compared_entries,
        compared_bytes: limits.max_content_bytes.saturating_sub(content_budget),
    })
}

fn compare_one_scope(
    expected_root: &Path,
    expected: &BTreeMap<PathBuf, EntryStamp>,
    current_root: &Path,
    current: &BTreeMap<PathBuf, EntryStamp>,
    requirement: &SnapshotRequirement,
    content_budget: &mut u64,
    compared_entries: &mut usize,
) -> Result<bool, SnapshotError> {
    match requirement.scope {
        SnapshotCompareScope::Content => compare_exact_paths(
            expected_root,
            expected,
            current_root,
            current,
            std::iter::once(requirement.path.clone()),
            content_budget,
            compared_entries,
        ),
        SnapshotCompareScope::Entries => Ok(compare_entry_names(
            expected,
            current,
            &requirement.path,
            false,
            compared_entries,
        )),
        SnapshotCompareScope::TreeEntries => Ok(compare_entry_names(
            expected,
            current,
            &requirement.path,
            true,
            compared_entries,
        )),
        SnapshotCompareScope::TreeContent => compare_exact_paths(
            expected_root,
            expected,
            current_root,
            current,
            subtree_paths(expected, current, &requirement.path),
            content_budget,
            compared_entries,
        ),
    }
}

#[derive(Clone, Copy)]
enum ScopedScan {
    Exact,
    Immediate,
    Recursive,
}

fn scoped_inventory(
    root: &Path,
    relative: &Path,
    scan: ScopedScan,
    directory_modes: Option<&BTreeMap<PathBuf, u32>>,
    remaining_entries: &mut usize,
    remaining_path_bytes: &mut usize,
) -> Result<BTreeMap<PathBuf, EntryStamp>, SnapshotError> {
    let relative = normalize_relative(relative)?;
    let mut full = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(SnapshotError::InvalidPath(relative.display().to_string()));
        };
        full.push(component);
        match fs::symlink_metadata(&full) {
            Ok(metadata) => {
                let is_final = full == root.join(&relative);
                if !is_final && (metadata.file_type().is_symlink() || !metadata.is_dir()) {
                    return Err(SnapshotError::InvalidPath(relative.display().to_string()));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(error) => {
                return Err(super::operation("inspect scoped requirement path", error));
            }
        }
    }
    let metadata = match fs::symlink_metadata(&full) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(super::operation("inspect scoped requirement", error)),
    };
    let mut result = BTreeMap::new();
    let mut root_stamp = stamp(&full, &metadata)?;
    if root_stamp.kind == SnapshotEntryKind::Directory {
        if let Some(mode) = directory_modes.and_then(|modes| modes.get(&relative)) {
            root_stamp.mode = *mode;
        }
    }
    let root_kind = root_stamp.kind;
    insert_scoped_entry(
        &mut result,
        relative.clone(),
        root_stamp,
        remaining_entries,
        remaining_path_bytes,
    )?;
    if root_kind != SnapshotEntryKind::Directory || matches!(scan, ScopedScan::Exact) {
        return Ok(result);
    }

    match scan {
        ScopedScan::Immediate => {
            let mut entries = fs::read_dir(&full)
                .map_err(|error| super::operation("read scoped requirement directory", error))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| super::operation("read scoped requirement entry", error))?;
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                let path = relative.join(entry.file_name());
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|error| super::operation("inspect scoped requirement entry", error))?;
                let mut entry_stamp = stamp(&entry.path(), &metadata)?;
                if entry_stamp.kind == SnapshotEntryKind::Directory {
                    if let Some(mode) = directory_modes.and_then(|modes| modes.get(&path)) {
                        entry_stamp.mode = *mode;
                    }
                }
                insert_scoped_entry(
                    &mut result,
                    path,
                    entry_stamp,
                    remaining_entries,
                    remaining_path_bytes,
                )?;
            }
        }
        ScopedScan::Recursive => {
            let scoped_modes = directory_modes.map(|modes| {
                modes
                    .iter()
                    .filter_map(|(path, mode)| {
                        path.strip_prefix(&relative)
                            .ok()
                            .map(|path| (path.to_path_buf(), *mode))
                    })
                    .collect::<BTreeMap<_, _>>()
            });
            let inventory = inventory_bounded_with_modes(
                &full,
                *remaining_entries,
                *remaining_path_bytes,
                scoped_modes.as_ref(),
            )?;
            // The root was already counted above.
            for (path, stamp) in inventory
                .into_iter()
                .filter(|(path, _)| !path.as_os_str().is_empty())
            {
                insert_scoped_entry(
                    &mut result,
                    relative.join(path),
                    stamp,
                    remaining_entries,
                    remaining_path_bytes,
                )?;
            }
        }
        ScopedScan::Exact => unreachable!("exact scan returned above"),
    }
    Ok(result)
}

fn insert_scoped_entry(
    inventory: &mut BTreeMap<PathBuf, EntryStamp>,
    path: PathBuf,
    stamp: EntryStamp,
    remaining_entries: &mut usize,
    remaining_path_bytes: &mut usize,
) -> Result<(), SnapshotError> {
    *remaining_entries = remaining_entries.checked_sub(1).ok_or_else(|| {
        SnapshotError::LimitExceeded("snapshot compare entry budget was exceeded".to_string())
    })?;
    *remaining_path_bytes = remaining_path_bytes
        .checked_sub(path.as_os_str().as_bytes().len())
        .ok_or_else(|| {
            SnapshotError::LimitExceeded("snapshot compare path budget was exceeded".to_string())
        })?;
    inventory.insert(path, stamp);
    Ok(())
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

    #[test]
    fn live_directory_compare_scans_only_declared_scopes() {
        let source = tempfile::tempdir().unwrap();
        let base_storage = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("tree")).unwrap();
        fs::write(source.path().join("dependency"), b"base").unwrap();
        fs::write(source.path().join("tree/child"), b"base").unwrap();
        fs::write(source.path().join("unrelated"), b"base").unwrap();
        let base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();

        fs::write(source.path().join("unrelated"), b"changed").unwrap();
        let comparison = base
            .compare_directory_requirements(
                source.path(),
                &[SnapshotRequirement {
                    path: "dependency".into(),
                    scope: SnapshotCompareScope::Content,
                }],
                SnapshotCompareLimits {
                    max_entries: 2,
                    max_path_bytes: 64,
                    ..SnapshotCompareLimits::default()
                },
            )
            .unwrap();
        assert!(comparison.matched);
        assert_eq!(comparison.compared_entries, 1);

        fs::write(source.path().join("dependency"), b"stale").unwrap();
        assert!(
            !base
                .compare_directory_requirements(
                    source.path(),
                    &[SnapshotRequirement {
                        path: "dependency".into(),
                        scope: SnapshotCompareScope::Content,
                    }],
                    SnapshotCompareLimits::default(),
                )
                .unwrap()
                .matched
        );

        fs::write(source.path().join("tree/child"), b"stale").unwrap();
        assert!(
            !base
                .compare_directory_requirements(
                    source.path(),
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
}
