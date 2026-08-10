use sandlock_core::{
    read_preserved, BranchError, BranchState, ChangeKind, PreserveReason, Sandbox,
};
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
    if let Err(e) = sandbox
        .run_in_branch(&mut branch_a, &["sh", "-c", &write_a])
        .await
    {
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

    assert_eq!(
        conflicting.conflicts().unwrap(),
        vec![PathBuf::from("a.txt")]
    );
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
    assert_eq!(branch.state(), BranchState::Attached);

    let path = workdir.join("attached.txt");
    let command = format!("printf attached > {}", path.display());
    let result = sandbox.run(&["sh", "-c", &command]).await;
    if let Err(error) = result {
        eprintln!("Attached FsBranch test skipped: {error}");
        let _ = fs::remove_dir_all(&workdir);
        return;
    }

    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    assert_eq!(branch.state(), BranchState::Pending);
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

#[tokio::test]
async fn attached_branch_waits_for_background_descendants_before_returning() {
    let workdir = temp_dir("attached-descendant");
    let mut sandbox = sandbox(&workdir);
    let mut branch = sandbox.create_fs_branch().unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();

    let path = workdir.join("daemon.txt");
    let command = format!(
        "if setsid true 2>/dev/null; then exit 99; fi; printf first > {0}; (exec </dev/null >/dev/null 2>&1; while :; do printf x >> {0}; sleep 0.01; done) &",
        path.display()
    );
    let result = match sandbox.run(&["sh", "-c", &command]).await {
        Ok(result) => result,
        Err(error) => {
            eprintln!("Attached FsBranch descendant test skipped: {error}");
            let _ = fs::remove_dir_all(&workdir);
            return;
        }
    };
    assert_eq!(result.exit_status, sandlock_core::ExitStatus::Code(0));

    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    assert!(!sandbox
        .extra_deny_syscalls
        .iter()
        .any(|name| name == "setsid" || name == "setpgid"));
    let staged = branch.upper_dir().join("daemon.txt");
    let size = fs::metadata(&staged).unwrap().len();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(fs::metadata(&staged).unwrap().len(), size);
    branch.abort().unwrap();
    let _ = fs::remove_dir_all(&workdir);
}

#[test]
fn dropping_sandbox_leaves_an_attached_recovery_warning() {
    let workdir = temp_dir("attached-drop");
    let mut sandbox = sandbox(&workdir);
    let mut branch = sandbox.create_fs_branch().unwrap();
    let branch_dir = branch.upper_dir().parent().unwrap().to_path_buf();
    sandbox.attach_fs_branch(&mut branch).unwrap();
    assert_eq!(
        read_preserved(&branch_dir).unwrap().reason,
        PreserveReason::Attached
    );

    drop(sandbox);

    let preserved = read_preserved(&branch_dir).unwrap();
    assert_eq!(preserved.reason, PreserveReason::Attached);
    let _ = fs::remove_dir_all(&branch_dir);
    let _ = fs::remove_dir_all(&workdir);
}
