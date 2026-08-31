//! Optional read paths must not weaken static grants or hide native ENOENT.

use sandlock_core::{sandbox::BranchAction, Sandbox};
use std::{fs, os::unix::fs::symlink, path::PathBuf};

fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/rootfs-helper")
        .canonicalize()
        .unwrap()
}

async fn check(sandbox: &Sandbox, path: &std::path::Path, errno: i32, flags: i32) {
    let helper = helper();
    let result = sandbox
        .clone()
        .run(&[
            helper.to_str().unwrap(),
            "open-errno",
            path.to_str().unwrap(),
            &errno.to_string(),
            &flags.to_string(),
        ])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}: {}",
        path.display(),
        result.stderr_str().unwrap_or_default()
    );
}

#[tokio::test]
async fn missing_read_grant_keeps_static_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let missing = root.join("optional/policy.toml");
    let sibling = root.join("secret");
    fs::write(&sibling, b"private").unwrap();
    // No parent grant, no supervisor: Landlock alone must still deny siblings.
    let sandbox = Sandbox::builder()
        .fs_read(helper())
        .fs_read(&missing)
        .no_supervisor(true)
        .build()
        .unwrap();
    check(&sandbox, &missing, libc::ENOENT, libc::O_RDONLY).await;
    check(&sandbox, &sibling, libc::EACCES, libc::O_RDONLY).await;
    assert!(
        sandbox.fs_readable.contains(&missing),
        "do not erase the policy entry"
    );

    // The parked child already installed its rules. Creating the absent path
    // later must not give it a kernel grant that was never installed.
    let mut parked = sandbox;
    let helper = helper();
    parked
        .create(&[
            helper.to_str().unwrap(),
            "open-errno",
            missing.to_str().unwrap(),
            &libc::EACCES.to_string(),
            &libc::O_RDONLY.to_string(),
        ])
        .await
        .unwrap();
    fs::create_dir(root.join("optional")).unwrap();
    fs::write(&missing, b"late policy").unwrap();
    parked.start().unwrap();
    assert!(parked.wait().await.unwrap().success());
}

#[tokio::test]
async fn missing_read_grant_does_not_ignore_other_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    fs::write(root.join("regular"), b"content").unwrap();
    symlink("loop", root.join("loop")).unwrap();
    for path in [root.join("regular/child"), root.join("loop")] {
        let mut sandbox = Sandbox::builder()
            .fs_read(helper())
            .fs_read(path)
            .no_supervisor(true)
            .build()
            .unwrap();
        assert!(sandbox
            .run(&[helper().to_str().unwrap(), "echo", "must-not-run"])
            .await
            .is_err());
    }
    let mut sandbox = Sandbox::builder()
        .fs_read(helper())
        .fs_write(root.join("missing"))
        .no_supervisor(true)
        .build()
        .unwrap();
    assert!(sandbox
        .run(&[helper().to_str().unwrap(), "echo", "must-not-run"])
        .await
        .is_err());
}

async fn check_chroot_missing(mounted_cow: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let allowed = root.join("allowed");
    let missing = root.join("optional/policy.toml");
    fs::create_dir(&allowed).unwrap();
    fs::write(allowed.join("regular"), b"policy").unwrap();
    fs::write(root.join("secret"), b"private").unwrap();
    symlink("loop", allowed.join("loop")).unwrap();
    let mut builder = Sandbox::builder()
        .chroot("/")
        .fs_read(helper())
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(&allowed)
        .fs_read(&missing)
        .fs_deny(allowed.join("denied"));
    let base = if mounted_cow {
        let virtual_root = root.join("virtual");
        builder = builder
            .fs_mount_ro(&virtual_root, &allowed)
            .workdir(&allowed)
            .on_exit(BranchAction::Abort);
        virtual_root
    } else {
        allowed.clone()
    };
    let sandbox = builder.build().unwrap();
    check(&sandbox, &missing, libc::ENOENT, libc::O_RDONLY).await;
    check(
        &sandbox,
        &base.join("missing/parent/config"),
        libc::ENOENT,
        libc::O_RDONLY,
    )
    .await;
    check(
        &sandbox,
        &base.join("regular/child"),
        libc::ENOTDIR,
        libc::O_RDONLY,
    )
    .await;
    check(
        &sandbox,
        &allowed.join("denied/child"),
        libc::EACCES,
        libc::O_RDONLY,
    )
    .await;
    check(
        &sandbox,
        &root.join("ungranted/child"),
        libc::EACCES,
        libc::O_RDONLY,
    )
    .await;
    check(&sandbox, &root.join("secret"), libc::EACCES, libc::O_RDONLY).await;
    check(
        &sandbox,
        &base.join("regular"),
        libc::EACCES,
        libc::O_WRONLY,
    )
    .await;
    let result = sandbox
        .clone()
        .run(&[
            helper().to_str().unwrap(),
            "cat",
            base.join("regular").to_str().unwrap(),
        ])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}",
        result.stderr_str().unwrap_or_default()
    );
    assert_eq!(result.stdout_str().unwrap(), "policy");
    if !mounted_cow {
        check(
            &sandbox,
            &base.join("loop/child"),
            libc::ELOOP,
            libc::O_RDONLY,
        )
        .await;
    }
}

#[tokio::test]
async fn missing_open_chroot() {
    check_chroot_missing(false).await;
}

#[tokio::test]
async fn missing_open_chroot_mounted_cow() {
    check_chroot_missing(true).await;
}
