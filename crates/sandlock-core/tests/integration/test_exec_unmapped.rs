//! Host-identity executables must not modify a surviving posix_spawn caller.

use sandlock_core::{sandbox::BranchAction, Sandbox};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
};

#[tokio::test]
async fn unmapped_exec_preserves_spawn_memory() {
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .unwrap();
    for cow in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        symlink(&helper, root.join("alias")).unwrap();
        fs::write(root.join("invalid"), b"not an executable\n").unwrap();
        fs::set_permissions(root.join("invalid"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::copy(&helper, root.join("denied")).unwrap();
        let mut builder = Sandbox::builder()
            .chroot("/")
            .fs_read(&helper)
            .fs_read("/proc")
            .fs_read("/dev")
            .fs_read(&root)
            .fs_deny(root.join("denied"));
        if cow {
            let lower = root.join("lower");
            fs::create_dir(&lower).unwrap();
            builder = builder
                .fs_mount("/virtual-work", &lower)
                .workdir(&lower)
                .on_exit(BranchAction::Abort);
        }
        let sandbox = builder.build().unwrap();
        for (path, errno) in [
            (helper.clone(), 0),
            (root.join("alias"), 0),
            (root.join("invalid"), libc::ENOEXEC),
            (root.join("denied"), libc::EACCES),
        ] {
            let result = sandbox
                .clone()
                .run(&[
                    helper.to_str().unwrap(),
                    "spawn-preserve",
                    path.to_str().unwrap(),
                    &errno.to_string(),
                ])
                .await
                .unwrap();
            assert!(
                result.success(),
                "cow={cow}, path={path:?}: {}",
                result.stderr_str().unwrap_or_default()
            );
            assert!(result
                .stdout_str()
                .unwrap()
                .contains("spawn memory preserved"));
        }
    }
}
