//! Real syscall regressions for ordinary paths, chroot and the merged COW view.

use sandlock_core::{sandbox::BranchAction, Sandbox};
use std::{fs, os::unix::fs::symlink, path::PathBuf};

async fn check_readlink(chroot: bool, cow: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::create_dir(root.join("directory")).unwrap();
    fs::write(root.join("regular"), b"content").unwrap();
    symlink("regular", root.join("link")).unwrap();
    symlink("missing-target", root.join("dangling")).unwrap();
    fs::create_dir(root.join("denied")).unwrap();
    symlink("do-not-expose", root.join("denied/link")).unwrap();
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .unwrap();
    let mut builder = Sandbox::builder()
        .fs_read(&helper)
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(&root)
        .cwd(&root);
    if chroot {
        builder = builder.chroot("/").fs_deny(root.join("denied"));
    }
    if cow {
        builder = builder.workdir(&root).on_exit(BranchAction::Abort);
    }
    let sandbox = builder.build().unwrap();
    for (name, errno) in [
        ("directory", libc::EINVAL),
        ("regular", libc::EINVAL),
        ("missing", libc::ENOENT),
        // Chroot's existing path resolver rejects an invalid parent walk at its
        // authorization boundary. This fix does not loosen that boundary.
        (
            "regular/child",
            if chroot { libc::EACCES } else { libc::ENOTDIR },
        ),
    ] {
        let path = root.join(name);
        let result = sandbox
            .clone()
            .run(&[
                helper.to_str().unwrap(),
                "readlink-errno",
                path.to_str().unwrap(),
                &errno.to_string(),
            ])
            .await
            .unwrap();
        assert!(
            result.success(),
            "chroot={chroot} cow={cow} {name}: {}",
            result.stderr_str().unwrap_or_default()
        );
    }
    for (name, target) in [("link", "regular"), ("dangling", "missing-target")] {
        let path = root.join(name);
        let result = sandbox
            .clone()
            .run(&[helper.to_str().unwrap(), "readlink", path.to_str().unwrap()])
            .await
            .unwrap();
        assert!(
            result.success(),
            "{}",
            result.stderr_str().unwrap_or_default()
        );
        assert_eq!(result.stdout_str().unwrap().trim(), target);
    }
    let result = sandbox
        .clone()
        .run(&[helper.to_str().unwrap(), "realpath", root.to_str().unwrap()])
        .await
        .unwrap();
    assert!(
        result.success(),
        "canonicalize chroot={chroot} cow={cow}: {}",
        result.stderr_str().unwrap_or_default()
    );
    assert_eq!(result.stdout_str().unwrap().trim(), root.to_str().unwrap());
    if chroot {
        let path = root.join("denied/link");
        let result = sandbox
            .clone()
            .run(&[
                helper.to_str().unwrap(),
                "readlink-errno",
                path.to_str().unwrap(),
                &libc::EACCES.to_string(),
            ])
            .await
            .unwrap();
        assert!(
            result.success(),
            "denied: {}",
            result.stderr_str().unwrap_or_default()
        );
    }
}

#[tokio::test]
async fn readlink_errno_chroot() {
    check_readlink(true, false).await;
}

#[tokio::test]
async fn readlink_errno_cow() {
    check_readlink(false, true).await;
}

#[tokio::test]
async fn readlink_errno_chroot_cow() {
    check_readlink(true, true).await;
}
