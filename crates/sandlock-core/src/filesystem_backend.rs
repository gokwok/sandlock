//! Static filesystem-boundary selection and normalized mount planning.
//!
//! A filesystem backend is only one part of Sandlock's security boundary.
//! Seccomp, the user-notification supervisor, COW branches, process lifecycle,
//! and resource accounting remain Sandlock-owned regardless of this choice.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{ConfinementError, SandboxError};
use crate::protection::{Protection, ProtectionStatus};
use crate::sandbox::Sandbox;

/// Kernel mechanism used to construct the sandbox's static filesystem view.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemBackend {
    /// Apply the existing Landlock path-beneath rules.
    #[default]
    Landlock,
    /// Construct an empty mount namespace with Bubblewrap and explicit binds.
    Bubblewrap,
    /// Prefer Landlock when every strict protection is available, otherwise
    /// try Bubblewrap. The resolved backend is observable at runtime.
    Auto,
}

impl std::str::FromStr for FilesystemBackend {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "landlock" => Ok(Self::Landlock),
            "bubblewrap" => Ok(Self::Bubblewrap),
            "auto" => Ok(Self::Auto),
            _ => Err(format!(
                "invalid filesystem backend '{value}'; expected landlock, bubblewrap, or auto"
            )),
        }
    }
}

impl std::fmt::Display for FilesystemBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Landlock => "landlock",
            Self::Bubblewrap => "bubblewrap",
            Self::Auto => "auto",
        })
    }
}

/// Runtime-selected filesystem backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedFilesystemBackend {
    Landlock { abi: u32 },
    Bubblewrap { version: String },
}

impl ResolvedFilesystemBackend {
    pub fn implementation_id(&self) -> String {
        match self {
            Self::Landlock { abi } => format!("landlock-v{abi}"),
            Self::Bubblewrap { version } => format!("bubblewrap-fs-v2:{version}"),
        }
    }
}

/// Observable backend selection used by downstream cache keys and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemBackendReport {
    pub requested: FilesystemBackend,
    pub resolved: ResolvedFilesystemBackend,
    pub executable: Option<PathBuf>,
    pub implementation_id: String,
}

/// Provider responsible for one active semantic protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionProvider {
    Landlock,
    MountNamespace,
}

/// Provider-aware protection resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionReport {
    pub protection: Protection,
    pub status: ProtectionStatus,
    pub provider: Option<ProtectionProvider>,
}

pub(crate) fn resolve_backend(
    sandbox: &Sandbox,
) -> Result<ResolvedFilesystemBackend, ConfinementError> {
    let landlock_abi = crate::landlock::abi_version().ok();
    match sandbox.filesystem_backend {
        FilesystemBackend::Landlock => landlock_abi
            .map(|abi| ResolvedFilesystemBackend::Landlock { abi })
            .ok_or_else(|| {
                ConfinementError::LandlockUnavailable(
                    "filesystem backend is explicitly Landlock".to_owned(),
                )
            }),
        FilesystemBackend::Bubblewrap => crate::bubblewrap::probe(sandbox)
            .map(|(_, version)| ResolvedFilesystemBackend::Bubblewrap { version })
            .map_err(|error| {
                ConfinementError::FilesystemBackendUnavailable(format!("Bubblewrap: {error}"))
            }),
        FilesystemBackend::Auto => {
            if let Some(abi) = landlock_abi {
                let all_strict_available = Protection::all().all(|protection| {
                    ProtectionStatus::resolve(protection, abi, &sandbox.protection_policy)
                        != ProtectionStatus::Unavailable
                });
                if all_strict_available {
                    return Ok(ResolvedFilesystemBackend::Landlock { abi });
                }
            }
            crate::bubblewrap::probe(sandbox)
                .map(|(_, version)| ResolvedFilesystemBackend::Bubblewrap { version })
                .map_err(|error| {
                    ConfinementError::FilesystemBackendUnavailable(format!("Bubblewrap: {error}"))
                })
        }
    }
}

pub(crate) fn protection_reports(
    sandbox: &Sandbox,
    backend: &ResolvedFilesystemBackend,
) -> Vec<ProtectionReport> {
    Protection::all()
        .map(|protection| match backend {
            ResolvedFilesystemBackend::Landlock { abi } => {
                let status =
                    ProtectionStatus::resolve(protection, *abi, &sandbox.protection_policy);
                ProtectionReport {
                    protection,
                    status,
                    provider: (status == ProtectionStatus::Active)
                        .then_some(ProtectionProvider::Landlock),
                }
            }
            ResolvedFilesystemBackend::Bubblewrap { .. } => {
                use crate::protection::ProtectionState;
                let state = sandbox.protection_policy.state(protection);
                let supplied = matches!(protection, Protection::FsRefer | Protection::FsTruncate);
                let status = match (state, supplied) {
                    (ProtectionState::Disabled, _) => ProtectionStatus::Disabled,
                    (ProtectionState::Strict | ProtectionState::Degradable, true) => {
                        ProtectionStatus::Active
                    }
                    (ProtectionState::Degradable, false) => ProtectionStatus::Degraded,
                    (ProtectionState::Strict, false) => ProtectionStatus::Unavailable,
                };
                ProtectionReport {
                    protection,
                    status,
                    provider: (status == ProtectionStatus::Active)
                        .then_some(ProtectionProvider::MountNamespace),
                }
            }
        })
        .collect()
}

pub(crate) fn validate_protections(
    sandbox: &Sandbox,
    backend: &ResolvedFilesystemBackend,
) -> Result<(), ConfinementError> {
    if let Some(report) = protection_reports(sandbox, backend)
        .into_iter()
        .find(|report| report.status == ProtectionStatus::Unavailable)
    {
        return Err(ConfinementError::ProtectionUnavailable {
            protection: report.protection,
            required_abi: report.protection.min_abi(),
            host_abi: match backend {
                ResolvedFilesystemBackend::Landlock { abi } => *abi,
                ResolvedFilesystemBackend::Bubblewrap { .. } => 0,
            },
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountAccess {
    ReadOnly,
    ReadWrite,
    DeviceReadOnly,
    DeviceReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryPurpose {
    PolicyGrant,
    ExplicitMount,
    CowLower,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemEntry {
    pub(crate) guest_path: PathBuf,
    pub(crate) host_source: PathBuf,
    pub(crate) access: MountAccess,
    pub(crate) purpose: EntryPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CowView {
    pub(crate) guest_root: PathBuf,
    pub(crate) lower_root: PathBuf,
}

/// Backend-neutral normalized filesystem view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesystemPlan {
    pub(crate) entries: Vec<FilesystemEntry>,
    pub(crate) denied: Vec<PathBuf>,
    pub(crate) proc_mounted: bool,
    pub(crate) cow: Option<CowView>,
}

fn validate_guest_path(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(SandboxError::Invalid(format!(
            "filesystem guest path must be absolute: {}",
            path.display()
        )));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SandboxError::Invalid(format!(
            "filesystem guest path must not contain '..': {}",
            path.display()
        )));
    }
    Ok(())
}

fn source_under_chroot(chroot: Option<&Path>, guest: &Path) -> PathBuf {
    match chroot {
        Some(root) => root.join(guest.strip_prefix("/").unwrap_or(guest)),
        None => guest.to_path_buf(),
    }
}

fn is_device(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|metadata| {
            let kind = metadata.file_type();
            kind.is_char_device() || kind.is_block_device()
        })
        .unwrap_or(false)
}

impl FilesystemPlan {
    pub(crate) fn from_sandbox(sandbox: &Sandbox) -> Result<Self, SandboxError> {
        let mut entries = BTreeMap::<PathBuf, FilesystemEntry>::new();
        let chroot = sandbox.chroot.as_deref();
        let mut proc_mounted = false;

        let mut insert = |guest_path: PathBuf,
                          host_source: PathBuf,
                          access: MountAccess,
                          purpose: EntryPurpose|
         -> Result<(), SandboxError> {
            validate_guest_path(&guest_path)?;
            if guest_path == Path::new("/proc") {
                proc_mounted = true;
                return Ok(());
            }
            entries.insert(
                guest_path.clone(),
                FilesystemEntry {
                    guest_path,
                    host_source,
                    access,
                    purpose,
                },
            );
            Ok(())
        };

        for guest in &sandbox.fs_readable {
            let source = source_under_chroot(chroot, guest);
            let access = if is_device(&source) {
                MountAccess::DeviceReadOnly
            } else {
                MountAccess::ReadOnly
            };
            insert(guest.clone(), source, access, EntryPurpose::PolicyGrant)?;
        }
        for guest in &sandbox.fs_writable {
            let source = source_under_chroot(chroot, guest);
            let access = if is_device(&source) {
                MountAccess::DeviceReadWrite
            } else {
                MountAccess::ReadWrite
            };
            insert(guest.clone(), source, access, EntryPurpose::PolicyGrant)?;
        }
        for (guest, host) in &sandbox.fs_mount {
            let read_only = sandbox.fs_mount_ro.iter().any(|path| path == guest);
            let access = match (is_device(host), read_only) {
                (true, true) => MountAccess::DeviceReadOnly,
                (true, false) => MountAccess::DeviceReadWrite,
                (false, true) => MountAccess::ReadOnly,
                (false, false) => MountAccess::ReadWrite,
            };
            insert(
                guest.clone(),
                host.clone(),
                access,
                EntryPurpose::ExplicitMount,
            )?;
        }

        let cow = sandbox.workdir.as_ref().map(|lower_root| CowView {
            guest_root: sandbox
                .workdir_virtual
                .clone()
                .unwrap_or_else(|| lower_root.clone()),
            lower_root: lower_root.clone(),
        });
        if let Some(cow) = &cow {
            insert(
                cow.guest_root.clone(),
                cow.lower_root.clone(),
                MountAccess::ReadOnly,
                EntryPurpose::CowLower,
            )?;
        }

        let mut entries = entries.into_values().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.guest_path
                .components()
                .count()
                .cmp(&right.guest_path.components().count())
                .then_with(|| left.guest_path.cmp(&right.guest_path))
        });

        for denied in &sandbox.fs_denied {
            validate_guest_path(denied)?;
        }

        Ok(Self {
            entries,
            denied: sandbox.fs_denied.clone(),
            proc_mounted,
            cow,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Sandbox;

    #[test]
    fn default_backend_preserves_landlock() {
        assert_eq!(FilesystemBackend::default(), FilesystemBackend::Landlock);
        assert_eq!(
            Sandbox::builder().build().unwrap().filesystem_backend,
            FilesystemBackend::Landlock
        );
        assert!("unconfined".parse::<FilesystemBackend>().is_err());
    }

    #[test]
    fn bubblewrap_does_not_silently_relax_strict_protections() {
        let sandbox = Sandbox::builder()
            .filesystem_backend(FilesystemBackend::Bubblewrap)
            .build()
            .unwrap();
        let backend = ResolvedFilesystemBackend::Bubblewrap {
            version: "test".into(),
        };
        assert!(validate_protections(&sandbox, &backend).is_err());
        let mut builder = Sandbox::builder().filesystem_backend(FilesystemBackend::Bubblewrap);
        for protection in [
            Protection::NetTcp,
            Protection::FsIoctlDev,
            Protection::SignalScope,
            Protection::AbstractUnixSocketScope,
        ] {
            builder = builder.allow_degraded(protection);
        }
        assert!(validate_protections(&builder.build().unwrap(), &backend).is_ok());
    }

    #[test]
    fn in_place_confinement_rejects_other_backends() {
        for backend in [FilesystemBackend::Bubblewrap, FilesystemBackend::Auto] {
            let sandbox = Sandbox::builder()
                .filesystem_backend(backend)
                .build()
                .unwrap();
            let error = crate::sandbox::Confinement::try_from(&sandbox).unwrap_err();
            assert!(error.to_string().contains("filesystem_backend"));
        }
    }

    #[test]
    fn bubblewrap_requires_a_supervisor() {
        assert!(Sandbox::builder()
            .filesystem_backend(FilesystemBackend::Bubblewrap)
            .no_supervisor(true)
            .build()
            .is_err());
    }

    #[test]
    fn serialized_policy_keeps_backend_but_not_launcher_paths() {
        let sandbox = Sandbox::builder()
            .filesystem_backend(FilesystemBackend::Bubblewrap)
            .bubblewrap_path("/deployment/bwrap")
            .bubblewrap_bootstrap_path("/deployment/bootstrap")
            .workdir("/host/lower")
            .workdir_virtual("/workspace")
            .build()
            .unwrap();
        let encoded = serde_json::to_string(&sandbox).unwrap();
        assert!(!encoded.contains("/deployment/"));
        let restored: Sandbox = serde_json::from_str(&encoded).unwrap();
        assert_eq!(restored.filesystem_backend, FilesystemBackend::Bubblewrap);
        assert_eq!(
            restored.workdir_virtual.as_deref(),
            Some(Path::new("/workspace"))
        );
        assert!(restored.bubblewrap_path.is_none());
        assert!(restored.bubblewrap_bootstrap_path.is_none());
        let profile = crate::profile::sandbox_to_profile(&sandbox, &[]);
        assert_eq!(
            profile.config.filesystem_backend,
            FilesystemBackend::Bubblewrap
        );
        assert_eq!(profile.config.workdir_virtual, restored.workdir_virtual);
    }

    #[test]
    fn empty_policy_has_no_host_mounts() {
        let sandbox = Sandbox::builder().build().unwrap();
        let plan = FilesystemPlan::from_sandbox(&sandbox).unwrap();
        assert!(plan.entries.is_empty());
        assert!(!plan.proc_mounted);
    }

    #[test]
    fn cow_lower_is_always_read_only_and_uses_virtual_root() {
        let sandbox = Sandbox::builder()
            .fs_mount("/workspace", "/host/lower")
            .workdir("/host/lower")
            .workdir_virtual("/workspace")
            .build()
            .unwrap();
        let plan = FilesystemPlan::from_sandbox(&sandbox).unwrap();
        let entry = plan
            .entries
            .iter()
            .find(|entry| entry.guest_path == Path::new("/workspace"))
            .unwrap();
        assert_eq!(entry.host_source, Path::new("/host/lower"));
        assert_eq!(entry.access, MountAccess::ReadOnly);
        assert_eq!(entry.purpose, EntryPurpose::CowLower);
    }

    #[test]
    fn chroot_grants_resolve_sources_without_exposing_root() {
        let sandbox = Sandbox::builder()
            .chroot("/image")
            .fs_read("/usr")
            .build()
            .unwrap();
        let plan = FilesystemPlan::from_sandbox(&sandbox).unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].guest_path, Path::new("/usr"));
        assert_eq!(plan.entries[0].host_source, Path::new("/image/usr"));
    }
}
