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
