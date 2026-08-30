//! Persistent file hashes and directory Merkle nodes for immutable snapshots.

use super::{
    normalize_relative, operation, SnapshotEntryKind, DEFAULT_SCAN_ENTRY_BUDGET,
    DEFAULT_SCAN_PATH_BYTE_BUDGET,
};
use crate::error::SnapshotError;
use bincode::Options as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const FILE_DOMAIN: &[u8] = b"sandlock snapshot file\0";
const SYMLINK_DOMAIN: &[u8] = b"sandlock snapshot symlink\0";
const DIRECTORY_DOMAIN: &[u8] = b"sandlock snapshot directory\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum StoredEntryKind {
    File,
    Directory,
    Symlink,
}

impl From<SnapshotEntryKind> for StoredEntryKind {
    fn from(value: SnapshotEntryKind) -> Self {
        match value {
            SnapshotEntryKind::File => Self::File,
            SnapshotEntryKind::Directory => Self::Directory,
            SnapshotEntryKind::Symlink => Self::Symlink,
        }
    }
}

impl From<StoredEntryKind> for SnapshotEntryKind {
    fn from(value: StoredEntryKind) -> Self {
        match value {
            StoredEntryKind::File => Self::File,
            StoredEntryKind::Directory => Self::Directory,
            StoredEntryKind::Symlink => Self::Symlink,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredIndexEntry {
    path: Vec<u8>,
    kind: StoredEntryKind,
    mode: u32,
    len: u64,
    hash: [u8; 32],
    subtree_entries: u64,
    content_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredSnapshotIndex {
    entries: Vec<StoredIndexEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SnapshotIndexEntry {
    pub(super) kind: SnapshotEntryKind,
    pub(super) mode: u32,
    pub(super) len: u64,
    pub(super) hash: [u8; 32],
    pub(super) subtree_entries: u64,
    pub(super) content_bytes: u64,
}

#[derive(Clone, Debug)]
pub(super) struct SnapshotIndex {
    pub(super) entries: BTreeMap<PathBuf, SnapshotIndexEntry>,
}

impl SnapshotIndex {
    pub(super) fn build(
        tree: &Path,
        directory_modes: &BTreeMap<PathBuf, u32>,
    ) -> Result<Self, SnapshotError> {
        let root_metadata = fs::symlink_metadata(tree)
            .map_err(|error| operation("inspect snapshot index root", error))?;
        if !root_metadata.file_type().is_dir() {
            return Err(SnapshotError::UnsupportedFileType(PathBuf::new()));
        }
        let mut entries = BTreeMap::new();
        entries.insert(
            PathBuf::new(),
            index_entry(
                tree,
                SnapshotEntryKind::Directory,
                directory_modes
                    .get(Path::new(""))
                    .copied()
                    .unwrap_or(root_metadata.mode() & 0o7777),
                &root_metadata,
            )?,
        );
        let mut path_bytes = 0_usize;
        for entry in walkdir::WalkDir::new(tree)
            .min_depth(1)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|error| {
                SnapshotError::Operation(format!("walk snapshot index source: {error}"))
            })?;
            if entries.len() >= DEFAULT_SCAN_ENTRY_BUDGET {
                return Err(SnapshotError::LimitExceeded(format!(
                    "snapshot contains more than {DEFAULT_SCAN_ENTRY_BUDGET} entries"
                )));
            }
            let path = entry
                .path()
                .strip_prefix(tree)
                .expect("snapshot index entry is below root")
                .to_path_buf();
            path_bytes = checked_path_bytes(path_bytes, &path)?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| operation("inspect snapshot index entry", error))?;
            let kind = entry_kind(&path, &metadata)?;
            let mode = if kind == SnapshotEntryKind::Directory {
                directory_modes
                    .get(&path)
                    .copied()
                    .unwrap_or(metadata.mode() & 0o7777)
            } else {
                metadata.mode() & 0o7777
            };
            entries.insert(path, index_entry(entry.path(), kind, mode, &metadata)?);
        }
        let mut index = Self { entries };
        index.recompute_directories()?;
        index.validate_structure()?;
        Ok(index)
    }

    pub(super) fn load(path: &Path) -> Result<Self, SnapshotError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| {
                SnapshotError::InvalidDescriptor(format!("open snapshot index: {error}"))
            })?;
        let length = file
            .metadata()
            .map_err(|error| {
                SnapshotError::InvalidDescriptor(format!("inspect snapshot index: {error}"))
            })?
            .len();
        if length > MAX_INDEX_BYTES {
            return Err(SnapshotError::InvalidDescriptor(format!(
                "snapshot index exceeds {MAX_INDEX_BYTES} bytes"
            )));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
        file.read_to_end(&mut bytes).map_err(|error| {
            SnapshotError::InvalidDescriptor(format!("read snapshot index: {error}"))
        })?;
        let stored: StoredSnapshotIndex = index_options().deserialize(&bytes).map_err(|error| {
            SnapshotError::InvalidDescriptor(format!("parse snapshot index: {error}"))
        })?;
        let mut entries = BTreeMap::new();
        let mut path_bytes = 0_usize;
        if stored.entries.len() > DEFAULT_SCAN_ENTRY_BUDGET {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot index entry budget was exceeded".to_string(),
            ));
        }
        for stored in stored.entries {
            let path = PathBuf::from(OsString::from_vec(stored.path));
            let normalized = normalize_relative(&path).map_err(|_| {
                SnapshotError::InvalidDescriptor(format!(
                    "snapshot index contains an invalid path: {}",
                    path.display()
                ))
            })?;
            if normalized != path {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "snapshot index path is not normalized: {}",
                    path.display()
                )));
            }
            path_bytes = checked_index_path_bytes(path_bytes, &path)?;
            let entry = SnapshotIndexEntry {
                kind: stored.kind.into(),
                mode: stored.mode,
                len: stored.len,
                hash: stored.hash,
                subtree_entries: stored.subtree_entries,
                content_bytes: stored.content_bytes,
            };
            if entries.insert(path.clone(), entry).is_some() {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "snapshot index contains a duplicate path: {}",
                    path.display()
                )));
            }
        }
        let index = Self { entries };
        index.validate_structure()?;
        index.validate_directory_nodes()?;
        Ok(index)
    }

    pub(super) fn write(&self, path: &Path) -> Result<(), SnapshotError> {
        self.validate_structure()?;
        let stored = StoredSnapshotIndex {
            entries: self
                .entries
                .iter()
                .map(|(path, entry)| StoredIndexEntry {
                    path: path.as_os_str().as_bytes().to_vec(),
                    kind: entry.kind.into(),
                    mode: entry.mode,
                    len: entry.len,
                    hash: entry.hash,
                    subtree_entries: entry.subtree_entries,
                    content_bytes: entry.content_bytes,
                })
                .collect(),
        };
        let bytes = index_options().serialize(&stored).map_err(|error| {
            SnapshotError::Operation(format!("serialize snapshot index: {error}"))
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_INDEX_BYTES {
            return Err(SnapshotError::LimitExceeded(format!(
                "snapshot index exceeds {MAX_INDEX_BYTES} bytes"
            )));
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| operation("create snapshot index", error))?;
        file.write_all(&bytes)
            .map_err(|error| operation("write snapshot index", error))?;
        file.sync_all()
            .map_err(|error| operation("sync snapshot index", error))
    }

    pub(super) fn root_hash(&self) -> Result<[u8; 32], SnapshotError> {
        self.entries
            .get(Path::new(""))
            .map(|entry| entry.hash)
            .ok_or_else(|| {
                SnapshotError::InvalidDescriptor(
                    "snapshot index does not contain its root".to_string(),
                )
            })
    }

    pub(super) fn refresh_paths(
        &self,
        tree: &Path,
        directory_modes: &BTreeMap<PathBuf, u32>,
        paths: impl IntoIterator<Item = PathBuf>,
    ) -> Result<Self, SnapshotError> {
        let paths = minimize_paths(paths)?;
        let mut index = self.clone();
        for path in paths {
            index.remove_subtree(&path);
            index.add_subtree(tree, directory_modes, &path)?;
        }
        index.recompute_directories()?;
        index.validate_structure()?;
        Ok(index)
    }

    pub(super) fn apply_branch(
        &self,
        tree: &Path,
        directory_modes: &BTreeMap<PathBuf, u32>,
        upper: &Path,
        deleted: &[PathBuf],
        changed_directories: &BTreeSet<PathBuf>,
    ) -> Result<Self, SnapshotError> {
        let mut index = self.clone();
        for path in minimize_paths(deleted.iter().cloned())? {
            index.remove_subtree(&path);
        }
        for entry in walkdir::WalkDir::new(upper)
            .min_depth(1)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|error| {
                SnapshotError::Operation(format!("walk branch index overlay: {error}"))
            })?;
            let path = entry
                .path()
                .strip_prefix(upper)
                .expect("branch index entry is below upper")
                .to_path_buf();
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| operation("inspect branch index overlay", error))?;
            let kind = entry_kind(&path, &metadata)?;
            if kind == SnapshotEntryKind::Directory
                && !changed_directories.contains(&path)
                && index
                    .entries
                    .get(&path)
                    .is_some_and(|current| current.kind == SnapshotEntryKind::Directory)
            {
                continue;
            }
            if kind != SnapshotEntryKind::Directory
                || index
                    .entries
                    .get(&path)
                    .is_some_and(|current| current.kind != SnapshotEntryKind::Directory)
            {
                index.remove_subtree(&path);
            }
            let final_path = tree.join(&path);
            let final_metadata = fs::symlink_metadata(&final_path)
                .map_err(|error| operation("inspect materialized branch index entry", error))?;
            let final_kind = entry_kind(&path, &final_metadata)?;
            let mode = if final_kind == SnapshotEntryKind::Directory {
                directory_modes
                    .get(&path)
                    .copied()
                    .unwrap_or(final_metadata.mode() & 0o7777)
            } else {
                final_metadata.mode() & 0o7777
            };
            index.entries.insert(
                path,
                index_entry(&final_path, final_kind, mode, &final_metadata)?,
            );
        }
        if let Some(mode) = directory_modes.get(Path::new("")) {
            if let Some(root) = index.entries.get_mut(Path::new("")) {
                root.mode = *mode;
            }
        }
        index.recompute_directories()?;
        index.validate_structure()?;
        Ok(index)
    }

    fn add_subtree(
        &mut self,
        tree: &Path,
        directory_modes: &BTreeMap<PathBuf, u32>,
        relative: &Path,
    ) -> Result<(), SnapshotError> {
        let full = tree.join(relative);
        let metadata = match fs::symlink_metadata(&full) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(operation("inspect refreshed snapshot index path", error)),
        };
        let kind = entry_kind(relative, &metadata)?;
        let mode = if kind == SnapshotEntryKind::Directory {
            directory_modes
                .get(relative)
                .copied()
                .unwrap_or(metadata.mode() & 0o7777)
        } else {
            metadata.mode() & 0o7777
        };
        self.entries.insert(
            relative.to_path_buf(),
            index_entry(&full, kind, mode, &metadata)?,
        );
        if kind != SnapshotEntryKind::Directory {
            return Ok(());
        }
        for entry in walkdir::WalkDir::new(&full)
            .min_depth(1)
            .follow_links(false)
            .sort_by_file_name()
        {
            let entry = entry.map_err(|error| {
                SnapshotError::Operation(format!("walk refreshed snapshot index path: {error}"))
            })?;
            let suffix = entry
                .path()
                .strip_prefix(&full)
                .expect("refreshed index entry is below its root");
            let path = relative.join(suffix);
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| operation("inspect refreshed snapshot index entry", error))?;
            let kind = entry_kind(&path, &metadata)?;
            let mode = if kind == SnapshotEntryKind::Directory {
                directory_modes
                    .get(&path)
                    .copied()
                    .unwrap_or(metadata.mode() & 0o7777)
            } else {
                metadata.mode() & 0o7777
            };
            self.entries
                .insert(path, index_entry(entry.path(), kind, mode, &metadata)?);
        }
        Ok(())
    }

    fn remove_subtree(&mut self, root: &Path) {
        self.entries
            .retain(|path, _| path != root && !path.starts_with(root));
    }

    fn recompute_directories(&mut self) -> Result<(), SnapshotError> {
        let mut children = BTreeMap::<PathBuf, Vec<PathBuf>>::new();
        for path in self
            .entries
            .keys()
            .filter(|path| !path.as_os_str().is_empty())
        {
            let parent = path.parent().unwrap_or(Path::new("")).to_path_buf();
            children.entry(parent).or_default().push(path.clone());
        }
        let mut directories = self
            .entries
            .iter()
            .filter_map(|(path, entry)| {
                (entry.kind == SnapshotEntryKind::Directory).then_some(path.clone())
            })
            .collect::<Vec<_>>();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            let mode = self
                .entries
                .get(&directory)
                .expect("directory came from index")
                .mode;
            let child_entries = children
                .get(&directory)
                .into_iter()
                .flatten()
                .map(|path| {
                    let name = path
                        .file_name()
                        .expect("non-root index entry has a file name")
                        .as_bytes()
                        .to_vec();
                    let entry = self
                        .entries
                        .get(path)
                        .expect("directory child came from index")
                        .clone();
                    (name, entry)
                })
                .collect::<Vec<_>>();
            let mut hasher = blake3::Hasher::new();
            hasher.update(DIRECTORY_DOMAIN);
            hasher.update(&mode.to_le_bytes());
            let mut subtree_entries = 1_u64;
            let mut content_bytes = 0_u64;
            for (name, child) in child_entries {
                hash_length_prefixed(&mut hasher, &name);
                hasher.update(&[kind_tag(child.kind)]);
                hasher.update(&child.mode.to_le_bytes());
                let semantic_len = if child.kind == SnapshotEntryKind::File {
                    child.len
                } else {
                    0
                };
                hasher.update(&semantic_len.to_le_bytes());
                hasher.update(&child.hash);
                subtree_entries = subtree_entries
                    .checked_add(child.subtree_entries)
                    .ok_or_else(|| {
                        SnapshotError::LimitExceeded(
                            "snapshot index entry count overflow".to_string(),
                        )
                    })?;
                content_bytes =
                    content_bytes
                        .checked_add(child.content_bytes)
                        .ok_or_else(|| {
                            SnapshotError::LimitExceeded(
                                "snapshot index content byte count overflow".to_string(),
                            )
                        })?;
            }
            let entry = self
                .entries
                .get_mut(&directory)
                .expect("directory came from index");
            entry.hash = *hasher.finalize().as_bytes();
            entry.subtree_entries = subtree_entries;
            entry.content_bytes = content_bytes;
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), SnapshotError> {
        let root = self.entries.get(Path::new("")).ok_or_else(|| {
            SnapshotError::InvalidDescriptor(
                "snapshot index does not contain a root entry".to_string(),
            )
        })?;
        if root.kind != SnapshotEntryKind::Directory {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot index root is not a directory".to_string(),
            ));
        }
        if self.entries.len() > DEFAULT_SCAN_ENTRY_BUDGET {
            return Err(SnapshotError::InvalidDescriptor(
                "snapshot index entry budget was exceeded".to_string(),
            ));
        }
        let mut path_bytes = 0_usize;
        for (path, entry) in &self.entries {
            path_bytes = checked_index_path_bytes(path_bytes, path)?;
            if entry.mode & !0o7777 != 0 {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "snapshot index contains an invalid mode for {}",
                    path.display()
                )));
            }
            let leaf_metrics_are_valid = match entry.kind {
                SnapshotEntryKind::File => {
                    entry.subtree_entries == 1 && entry.content_bytes == entry.len
                }
                SnapshotEntryKind::Symlink => {
                    entry.subtree_entries == 1 && entry.content_bytes == 0
                }
                SnapshotEntryKind::Directory => true,
            };
            if !leaf_metrics_are_valid {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "snapshot index leaf metrics are inconsistent: {}",
                    path.display()
                )));
            }
            if path.as_os_str().is_empty() {
                continue;
            }
            let parent = path.parent().unwrap_or(Path::new(""));
            if !self
                .entries
                .get(parent)
                .is_some_and(|entry| entry.kind == SnapshotEntryKind::Directory)
            {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "snapshot index parent is missing or not a directory: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    fn validate_directory_nodes(&self) -> Result<(), SnapshotError> {
        let mut rebuilt = self.clone();
        rebuilt.recompute_directories()?;
        for (path, entry) in &self.entries {
            if entry.kind != SnapshotEntryKind::Directory {
                continue;
            }
            let rebuilt = rebuilt.entries.get(path).expect("rebuilt entry exists");
            if entry.hash != rebuilt.hash
                || entry.subtree_entries != rebuilt.subtree_entries
                || entry.content_bytes != rebuilt.content_bytes
            {
                return Err(SnapshotError::InvalidDescriptor(format!(
                    "snapshot index directory node is inconsistent: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }
}

fn index_options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_INDEX_BYTES)
        .reject_trailing_bytes()
}

fn entry_kind(path: &Path, metadata: &fs::Metadata) -> Result<SnapshotEntryKind, SnapshotError> {
    if metadata.file_type().is_file() {
        Ok(SnapshotEntryKind::File)
    } else if metadata.file_type().is_dir() {
        Ok(SnapshotEntryKind::Directory)
    } else if metadata.file_type().is_symlink() {
        Ok(SnapshotEntryKind::Symlink)
    } else {
        Err(SnapshotError::UnsupportedFileType(path.to_path_buf()))
    }
}

fn index_entry(
    path: &Path,
    kind: SnapshotEntryKind,
    mode: u32,
    metadata: &fs::Metadata,
) -> Result<SnapshotIndexEntry, SnapshotError> {
    let (hash, subtree_entries, content_bytes) = match kind {
        SnapshotEntryKind::File => {
            let hash = hash_regular_file(path)?;
            (hash, 1, metadata.len())
        }
        SnapshotEntryKind::Directory => ([0; 32], 1, 0),
        SnapshotEntryKind::Symlink => {
            let target = fs::read_link(path)
                .map_err(|error| operation("read snapshot index symlink", error))?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(SYMLINK_DOMAIN);
            hash_length_prefixed(&mut hasher, target.as_os_str().as_bytes());
            (*hasher.finalize().as_bytes(), 1, 0)
        }
    };
    Ok(SnapshotIndexEntry {
        kind,
        mode,
        len: if kind == SnapshotEntryKind::File {
            metadata.len()
        } else {
            0
        },
        hash,
        subtree_entries,
        content_bytes,
    })
}

fn hash_regular_file(path: &Path) -> Result<[u8; 32], SnapshotError> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| operation("open snapshot file for indexing", error))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(FILE_DOMAIN);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| operation("read snapshot file for indexing", error))?;
        if read == 0 {
            return Ok(*hasher.finalize().as_bytes());
        }
        hasher.update(&buffer[..read]);
    }
}

fn hash_length_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn kind_tag(kind: SnapshotEntryKind) -> u8 {
    match kind {
        SnapshotEntryKind::File => 1,
        SnapshotEntryKind::Directory => 2,
        SnapshotEntryKind::Symlink => 3,
    }
}

fn minimize_paths(paths: impl IntoIterator<Item = PathBuf>) -> Result<Vec<PathBuf>, SnapshotError> {
    let mut normalized = paths
        .into_iter()
        .map(|path| normalize_relative(&path))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    normalized.dedup();
    let mut roots = Vec::<PathBuf>::new();
    for path in normalized {
        if roots.iter().any(|root| path.starts_with(root)) {
            continue;
        }
        roots.push(path);
    }
    Ok(roots)
}

fn checked_path_bytes(current: usize, path: &Path) -> Result<usize, SnapshotError> {
    let next = current
        .checked_add(path.as_os_str().as_bytes().len())
        .ok_or_else(|| SnapshotError::LimitExceeded("snapshot path budget overflow".to_string()))?;
    if next > DEFAULT_SCAN_PATH_BYTE_BUDGET {
        return Err(SnapshotError::LimitExceeded(format!(
            "snapshot path data exceeds {DEFAULT_SCAN_PATH_BYTE_BUDGET} bytes"
        )));
    }
    Ok(next)
}

fn checked_index_path_bytes(current: usize, path: &Path) -> Result<usize, SnapshotError> {
    checked_path_bytes(current, path).map_err(|error| match error {
        SnapshotError::LimitExceeded(message) => SnapshotError::InvalidDescriptor(message),
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn persisted_index_round_trips_non_utf8_paths_and_merkle_nodes() {
        let tree = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let name = OsString::from_vec(vec![b'f', 0x80]);
        fs::write(tree.path().join(&name), b"content").unwrap();
        let index = SnapshotIndex::build(tree.path(), &BTreeMap::new()).unwrap();
        let path = storage.path().join("index");
        index.write(&path).unwrap();

        let loaded = SnapshotIndex::load(&path).unwrap();
        assert_eq!(loaded.root_hash().unwrap(), index.root_hash().unwrap());
        assert!(loaded.entries.contains_key(Path::new(&name)));
    }

    #[test]
    fn branch_update_hashes_only_upper_file_content() {
        let tree = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        fs::write(tree.path().join("unchanged"), b"base").unwrap();
        let base = SnapshotIndex::build(tree.path(), &BTreeMap::new()).unwrap();
        fs::write(tree.path().join("added"), b"new").unwrap();
        fs::write(upper.path().join("added"), b"new").unwrap();
        fs::set_permissions(
            tree.path().join("unchanged"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();

        let updated = base
            .apply_branch(
                tree.path(),
                &BTreeMap::new(),
                upper.path(),
                &[],
                &BTreeSet::new(),
            )
            .unwrap();
        assert!(updated.entries.contains_key(Path::new("unchanged")));
        assert!(updated.entries.contains_key(Path::new("added")));
        assert_ne!(updated.root_hash().unwrap(), base.root_hash().unwrap());
    }

    #[test]
    fn branch_update_matches_a_full_rebuild_across_type_changes() {
        let tree = tempfile::tempdir().unwrap();
        let upper = tempfile::tempdir().unwrap();
        fs::write(tree.path().join("file-to-directory"), b"base").unwrap();
        fs::create_dir(tree.path().join("deleted-directory")).unwrap();
        fs::write(tree.path().join("deleted-directory/file"), b"deleted").unwrap();
        fs::create_dir(tree.path().join("directory-to-file")).unwrap();
        fs::write(tree.path().join("directory-to-file/child"), b"base").unwrap();
        let base = SnapshotIndex::build(tree.path(), &BTreeMap::new()).unwrap();

        fs::remove_file(tree.path().join("file-to-directory")).unwrap();
        fs::create_dir(tree.path().join("file-to-directory")).unwrap();
        fs::write(tree.path().join("file-to-directory/child"), b"new").unwrap();
        fs::remove_dir_all(tree.path().join("deleted-directory")).unwrap();
        fs::remove_dir_all(tree.path().join("directory-to-file")).unwrap();
        fs::write(tree.path().join("directory-to-file"), b"replacement").unwrap();

        fs::create_dir(upper.path().join("file-to-directory")).unwrap();
        fs::write(upper.path().join("file-to-directory/child"), b"new").unwrap();
        fs::write(upper.path().join("directory-to-file"), b"replacement").unwrap();

        let updated = base
            .apply_branch(
                tree.path(),
                &BTreeMap::new(),
                upper.path(),
                &[PathBuf::from("deleted-directory")],
                &BTreeSet::new(),
            )
            .unwrap();
        let rebuilt = SnapshotIndex::build(tree.path(), &BTreeMap::new()).unwrap();

        assert_eq!(updated.entries, rebuilt.entries);
        assert_eq!(updated.root_hash().unwrap(), rebuilt.root_hash().unwrap());
    }

    #[test]
    fn load_rejects_a_corrupt_directory_merkle_node() {
        let tree = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        fs::write(tree.path().join("file"), b"content").unwrap();
        let index = SnapshotIndex::build(tree.path(), &BTreeMap::new()).unwrap();
        let path = storage.path().join("index");
        index.write(&path).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();

        assert!(matches!(
            SnapshotIndex::load(&path),
            Err(SnapshotError::InvalidDescriptor(_))
        ));
    }
}
