use sandlock_core::{BranchError, BranchState, ChangeKind, Sandbox};
use std::fs;
use std::path::PathBuf;

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sandlock-test-pending-{}-{}",
        name,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sandbox(workdir: &PathBuf) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(workdir)
        .workdir(workdir)
        .build()
        .unwrap()
}

#[tokio::test]
async fn pending_branch_commit_is_explicit() {
    let workdir = temp_dir("commit");
    fs::write(workdir.join("existing.txt"), "original").unwrap();

    let mut sandbox = sandbox(&workdir);
    let cmd = format!(
        "printf changed > {0}/existing.txt; printf added > {0}/added.txt",
        workdir.display()
    );
    let pending = sandbox.run_pending(&["sh", "-c", &cmd]).await;

    match pending {
        Ok(pending) => {
            assert!(pending.run_result.success());
            assert_eq!(
                fs::read_to_string(workdir.join("existing.txt")).unwrap(),
                "original"
            );
            assert!(!workdir.join("added.txt").exists());

            let (_, mut branch) = pending.into_parts();
            assert_eq!(branch.state(), BranchState::Pending);
            let changes = branch.changes().unwrap();
            assert!(
                changes
                    .iter()
                    .any(|c| c.kind == ChangeKind::Modified
                        && c.path == PathBuf::from("existing.txt"))
            );
            assert!(changes
                .iter()
                .any(|c| c.kind == ChangeKind::Added && c.path == PathBuf::from("added.txt")));

            branch.commit().unwrap();
            assert_eq!(branch.state(), BranchState::Committed);
            assert_eq!(
                fs::read_to_string(workdir.join("existing.txt")).unwrap(),
                "changed"
            );
            assert_eq!(
                fs::read_to_string(workdir.join("added.txt")).unwrap(),
                "added"
            );
            assert!(matches!(branch.abort(), Err(BranchError::AlreadyResolved)));
        }
        Err(e) => eprintln!("Pending branch test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

#[tokio::test]
async fn pending_branch_drop_aborts() {
    let workdir = temp_dir("drop");
    fs::write(workdir.join("existing.txt"), "original").unwrap();

    let mut sandbox = sandbox(&workdir);
    let cmd = format!("printf changed > {}/existing.txt", workdir.display());
    let pending = sandbox.run_pending(&["sh", "-c", &cmd]).await;

    match pending {
        Ok(pending) => {
            assert!(pending.run_result.success());
            let upper = pending.branch.upper_dir().to_path_buf();
            drop(pending);

            assert_eq!(
                fs::read_to_string(workdir.join("existing.txt")).unwrap(),
                "original"
            );
            assert!(!upper.exists());
        }
        Err(e) => eprintln!("Pending branch test skipped: {}", e),
    }

    let _ = fs::remove_dir_all(&workdir);
}

#[tokio::test]
async fn fs_branch_reuses_changes_and_detects_write_conflicts() {
    let workdir = temp_dir("reuse");
    let mut sandbox = sandbox(&workdir);
    let mut branch_a = sandbox.create_fs_branch().unwrap();
    let mut branch_b = sandbox.create_fs_branch().unwrap();
    let mut conflicting = sandbox.create_fs_branch().unwrap();

    let a_path = workdir.join("a.txt");
    let b_path = workdir.join("b.txt");
    let write_a = format!("printf first > {}", a_path.display());
    if let Err(e) = sandbox.run_in_branch(&mut branch_a, &["sh", "-c", &write_a]).await {
        eprintln!("FsBranch test skipped: {}", e);
        let _ = fs::remove_dir_all(&workdir);
        return;
    }

    let extend_a = format!(
        "test \"$(cat {})\" = first && printf -- -second >> {}",
        a_path.display(),
        a_path.display(),
    );
    assert!(sandbox
        .run_in_branch(&mut branch_a, &["sh", "-c", &extend_a])
        .await
        .unwrap()
        .success());

    let write_b = format!("printf independent > {}", b_path.display());
    sandbox
        .run_in_branch(&mut branch_b, &["sh", "-c", &write_b])
        .await
        .unwrap();
    let overwrite_a = format!("printf conflicting > {}", a_path.display());
    sandbox
        .run_in_branch(&mut conflicting, &["sh", "-c", &overwrite_a])
        .await
        .unwrap();

    branch_a.commit().unwrap();
    branch_b.commit().unwrap();
    assert_eq!(fs::read_to_string(&a_path).unwrap(), "first-second");
    assert_eq!(fs::read_to_string(&b_path).unwrap(), "independent");

    assert_eq!(conflicting.conflicts().unwrap(), vec![PathBuf::from("a.txt")]);
    assert!(matches!(
        conflicting.commit(),
        Err(BranchError::Conflict(_))
    ));
    conflicting.abort().unwrap();

    let _ = fs::remove_dir_all(&workdir);
}

#[tokio::test]
async fn attached_branch_returns_after_the_process_stops() {
    let workdir = temp_dir("attached");
    let mut sandbox = sandbox(&workdir);
    let mut branch = sandbox.create_fs_branch().unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();

    let path = workdir.join("attached.txt");
    let command = format!("printf attached > {}", path.display());
    let result = sandbox.run(&["sh", "-c", &command]).await;
    if let Err(error) = result {
        eprintln!("Attached FsBranch test skipped: {error}");
        let _ = fs::remove_dir_all(&workdir);
        return;
    }

    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    assert!(!path.exists());
    assert!(branch
        .changes()
        .unwrap()
        .iter()
        .any(|change| change.path == PathBuf::from("attached.txt")));
    branch.commit().unwrap();
    assert_eq!(fs::read_to_string(path).unwrap(), "attached");

    let _ = fs::remove_dir_all(&workdir);
}
