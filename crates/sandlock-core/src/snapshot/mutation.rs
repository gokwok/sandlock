//! Trusted typed mutation of immutable snapshots.

use super::{
    capture_with_overlay, contained_final_path, copy_regular_file, normalize_relative, operation,
    FsSnapshot,
};
use crate::error::SnapshotError;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

const DEFAULT_MUTATION_LIMIT: usize = 256;
const DEFAULT_PAYLOAD_BYTE_LIMIT: u64 = 256 * 1024 * 1024;
const DEFAULT_NEW_FILE_MODE: u32 = 0o644;
const DEFAULT_NEW_DIRECTORY_MODE: u32 = 0o755;

/// One trusted mutation applied to an immutable snapshot when deriving a new snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotMutation {
    /// Create or replace one regular file from a trusted no-follow source file.
    PutFile {
        path: PathBuf,
        source: PathBuf,
        mode: Option<u32>,
    },
    /// Remove one existing regular file.
    RemoveFile { path: PathBuf },
    /// Create one directory whose parent already exists in the derived view.
    MakeDirectory { path: PathBuf, mode: Option<u32> },
    /// Remove one empty directory.
    RemoveDirectory { path: PathBuf },
}

impl SnapshotMutation {
    fn path(&self) -> &Path {
        match self {
            Self::PutFile { path, .. }
            | Self::RemoveFile { path }
            | Self::MakeDirectory { path, .. }
            | Self::RemoveDirectory { path } => path,
        }
    }
}

/// Hard limits checked before a snapshot mutation copies any payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotMutationLimits {
    pub max_mutations: usize,
    pub max_payload_bytes: u64,
}

impl Default for SnapshotMutationLimits {
    fn default() -> Self {
        Self {
            max_mutations: DEFAULT_MUTATION_LIMIT,
            max_payload_bytes: DEFAULT_PAYLOAD_BYTE_LIMIT,
        }
    }
}

impl FsSnapshot {
    /// Derive a new immutable snapshot by applying an ordered typed mutation batch.
    ///
    /// The base snapshot is never modified. Payload sources are trusted controller files,
    /// opened without following their final symlink and checked for concurrent replacement.
    pub fn derive(
        &self,
        storage: impl AsRef<Path>,
        mutations: &[SnapshotMutation],
        limits: SnapshotMutationLimits,
    ) -> Result<FsSnapshot, SnapshotError> {
        self.ensure_live()?;
        let prepared = prepare_mutations(mutations, limits)?;
        let base_modes = self.directory_modes()?;
        capture_with_overlay(
            &self.tree_dir,
            storage.as_ref(),
            Some(&base_modes),
            move |tree, directory_modes| apply_mutations(tree, directory_modes, &prepared),
        )
    }
}

#[derive(Clone, Debug)]
enum PreparedMutation {
    PutFile {
        path: PathBuf,
        source: PathBuf,
        mode: Option<u32>,
    },
    RemoveFile {
        path: PathBuf,
    },
    MakeDirectory {
        path: PathBuf,
        mode: u32,
    },
    RemoveDirectory {
        path: PathBuf,
    },
}

fn prepare_mutations(
    mutations: &[SnapshotMutation],
    limits: SnapshotMutationLimits,
) -> Result<Vec<PreparedMutation>, SnapshotError> {
    if mutations.len() > limits.max_mutations {
        return Err(SnapshotError::LimitExceeded(format!(
            "snapshot mutation count {} exceeds {}",
            mutations.len(),
            limits.max_mutations
        )));
    }
    let mut seen = BTreeSet::new();
    let mut payload_bytes = 0_u64;
    let mut prepared = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        let path = normalize_relative(mutation.path())?;
        if path.as_os_str().is_empty() {
            return Err(SnapshotError::InvalidPath(
                "snapshot root cannot be mutated".to_string(),
            ));
        }
        if !seen.insert(path.clone()) {
            return Err(SnapshotError::InvalidPath(format!(
                "duplicate snapshot mutation path: {}",
                path.display()
            )));
        }
        match mutation {
            SnapshotMutation::PutFile { source, mode, .. } => {
                validate_mode(*mode)?;
                let metadata = fs::symlink_metadata(source)
                    .map_err(|error| operation("inspect mutation payload", error))?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(SnapshotError::UnsupportedFileType(source.clone()));
                }
                payload_bytes = payload_bytes.checked_add(metadata.len()).ok_or_else(|| {
                    SnapshotError::LimitExceeded("snapshot mutation payload overflow".to_string())
                })?;
                if payload_bytes > limits.max_payload_bytes {
                    return Err(SnapshotError::LimitExceeded(format!(
                        "snapshot mutation payload exceeds {} bytes",
                        limits.max_payload_bytes
                    )));
                }
                prepared.push(PreparedMutation::PutFile {
                    path,
                    source: source.clone(),
                    mode: *mode,
                });
            }
            SnapshotMutation::RemoveFile { .. } => {
                prepared.push(PreparedMutation::RemoveFile { path });
            }
            SnapshotMutation::MakeDirectory { mode, .. } => {
                validate_mode(*mode)?;
                prepared.push(PreparedMutation::MakeDirectory {
                    path,
                    mode: mode.unwrap_or(DEFAULT_NEW_DIRECTORY_MODE),
                });
            }
            SnapshotMutation::RemoveDirectory { .. } => {
                prepared.push(PreparedMutation::RemoveDirectory { path });
            }
        }
    }
    Ok(prepared)
}

fn validate_mode(mode: Option<u32>) -> Result<(), SnapshotError> {
    if mode.is_some_and(|mode| mode > 0o7777) {
        return Err(SnapshotError::Operation(
            "snapshot mutation mode exceeds 0o7777".to_string(),
        ));
    }
    Ok(())
}

fn apply_mutations(
    tree: &Path,
    directory_modes: &mut BTreeMap<PathBuf, u32>,
    mutations: &[PreparedMutation],
) -> Result<(), SnapshotError> {
    for mutation in mutations {
        match mutation {
            PreparedMutation::PutFile { path, source, mode } => {
                ensure_plain_parent(tree, path)?;
                let target = tree.join(path);
                let selected_mode = match fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.file_type().is_file() => {
                        fs::remove_file(&target)
                            .map_err(|error| operation("replace derived snapshot file", error))?;
                        mode.unwrap_or(metadata.mode() & 0o7777)
                    }
                    Ok(_) => {
                        return Err(SnapshotError::UnsupportedFileType(path.clone()));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        mode.unwrap_or(DEFAULT_NEW_FILE_MODE)
                    }
                    Err(error) => return Err(operation("inspect derived snapshot target", error)),
                };
                copy_regular_file(source, &target, selected_mode)?;
                directory_modes
                    .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
            }
            PreparedMutation::RemoveFile { path } => {
                ensure_plain_parent(tree, path)?;
                let target = contained_final_path(tree, path)?;
                let metadata = fs::symlink_metadata(&target)
                    .map_err(|error| operation("inspect removed snapshot file", error))?;
                if !metadata.file_type().is_file() {
                    return Err(SnapshotError::UnsupportedFileType(path.clone()));
                }
                fs::remove_file(&target)
                    .map_err(|error| operation("remove derived snapshot file", error))?;
            }
            PreparedMutation::MakeDirectory { path, mode } => {
                ensure_plain_parent(tree, path)?;
                let target = tree.join(path);
                match fs::symlink_metadata(&target) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        return Err(SnapshotError::Operation(format!(
                            "derived snapshot path already exists: {}",
                            path.display()
                        )));
                    }
                    Err(error) => {
                        return Err(operation("inspect derived snapshot directory", error));
                    }
                }
                super::create_private_directory(&target)?;
                directory_modes.insert(path.clone(), *mode);
            }
            PreparedMutation::RemoveDirectory { path } => {
                ensure_plain_parent(tree, path)?;
                let target = contained_final_path(tree, path)?;
                let metadata = fs::symlink_metadata(&target)
                    .map_err(|error| operation("inspect removed snapshot directory", error))?;
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(SnapshotError::UnsupportedFileType(path.clone()));
                }
                fs::remove_dir(&target)
                    .map_err(|error| operation("remove derived snapshot directory", error))?;
                directory_modes
                    .retain(|candidate, _| candidate != path && !candidate.starts_with(path));
            }
        }
    }
    Ok(())
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
            .map_err(|error| operation("inspect mutation parent", error))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(SnapshotError::InvalidPath(path.display().to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_applies_ordered_regular_file_and_directory_mutations() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let derived_storage = tempfile::tempdir().unwrap();
        let payloads = tempfile::tempdir().unwrap();
        fs::write(source.path().join("replace"), b"before").unwrap();
        fs::write(source.path().join("remove"), b"gone").unwrap();
        fs::create_dir(source.path().join("empty")).unwrap();
        fs::write(payloads.path().join("replace"), b"after").unwrap();
        fs::write(payloads.path().join("nested"), b"nested").unwrap();

        let base = FsSnapshot::capture(source.path(), storage.path()).unwrap();
        let derived = base
            .derive(
                derived_storage.path(),
                &[
                    SnapshotMutation::PutFile {
                        path: PathBuf::from("replace"),
                        source: payloads.path().join("replace"),
                        mode: Some(0o755),
                    },
                    SnapshotMutation::RemoveFile {
                        path: PathBuf::from("remove"),
                    },
                    SnapshotMutation::RemoveDirectory {
                        path: PathBuf::from("empty"),
                    },
                    SnapshotMutation::MakeDirectory {
                        path: PathBuf::from("new"),
                        mode: Some(0o750),
                    },
                    SnapshotMutation::PutFile {
                        path: PathBuf::from("new/value"),
                        source: payloads.path().join("nested"),
                        mode: None,
                    },
                ],
                SnapshotMutationLimits::default(),
            )
            .unwrap();

        assert_eq!(derived.read_range("replace", 0, 16).unwrap(), b"after");
        assert_eq!(derived.stat("replace").unwrap().mode, 0o755);
        assert_eq!(derived.read_range("new/value", 0, 16).unwrap(), b"nested");
        assert_eq!(derived.stat("new").unwrap().mode, 0o750);
        assert!(derived.stat("remove").is_err());
        assert!(derived.stat("empty").is_err());
        assert_eq!(base.read_range("replace", 0, 16).unwrap(), b"before");
    }

    #[test]
    fn derive_rejects_duplicate_paths_symlink_parents_and_payload_overflow() {
        let source = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let derived_storage = tempfile::tempdir().unwrap();
        let payloads = tempfile::tempdir().unwrap();
        fs::write(payloads.path().join("value"), b"value").unwrap();
        fs::create_dir(source.path().join("real")).unwrap();
        std::os::unix::fs::symlink("real", source.path().join("link")).unwrap();
        let base = FsSnapshot::capture(source.path(), storage.path()).unwrap();

        assert!(matches!(
            base.derive(
                derived_storage.path(),
                &[
                    SnapshotMutation::RemoveFile { path: "x".into() },
                    SnapshotMutation::RemoveFile { path: "x".into() },
                ],
                SnapshotMutationLimits::default(),
            ),
            Err(SnapshotError::InvalidPath(_))
        ));
        assert!(matches!(
            base.derive(
                derived_storage.path(),
                &[SnapshotMutation::PutFile {
                    path: "link/value".into(),
                    source: payloads.path().join("value"),
                    mode: None,
                }],
                SnapshotMutationLimits::default(),
            ),
            Err(SnapshotError::InvalidPath(_))
        ));
        assert!(matches!(
            base.derive(
                derived_storage.path(),
                &[SnapshotMutation::PutFile {
                    path: "value".into(),
                    source: payloads.path().join("value"),
                    mode: None,
                }],
                SnapshotMutationLimits {
                    max_mutations: 1,
                    max_payload_bytes: 1,
                },
            ),
            Err(SnapshotError::LimitExceeded(_))
        ));
    }
}
