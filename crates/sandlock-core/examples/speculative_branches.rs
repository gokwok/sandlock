//! Run two speculative actions against one workdir, then publish only the
//! branch selected after both actions finish.
//!
//! Run on Linux:
//!
//! ```sh
//! cargo run -p sandlock-core --example speculative_branches
//! ```

use sandlock_core::{PendingBranch, Sandbox};
use std::fs;
use std::path::Path;

fn show_workspace(workdir: &Path, phase: &str) {
    let read = |name: &str| {
        fs::read_to_string(workdir.join(name))
            .ok()
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| "<missing>".to_owned())
    };

    println!("\n{phase}");
    println!("  selected.txt = {}", read("selected.txt"));
    println!("  base.txt     = {}", read("base.txt"));
    println!("  only-a.txt   = {}", read("only-a.txt"));
    println!("  only-b.txt   = {}", read("only-b.txt"));
}

fn show_changes(label: &str, branch: &PendingBranch) -> Result<(), Box<dyn std::error::Error>> {
    let mut changes = branch
        .changes()?
        .into_iter()
        .map(|change| change.to_string())
        .collect::<Vec<_>>();
    changes.sort();

    println!("\n{label} staged changes:");
    for change in changes {
        println!("  {change}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workdir = tempfile::tempdir()?;
    fs::write(workdir.path().join("selected.txt"), "original\n")?;
    fs::write(workdir.path().join("base.txt"), "still present\n")?;

    let template = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_write(workdir.path())
        .workdir(workdir.path())
        .cwd(workdir.path())
        .build()?;

    show_workspace(workdir.path(), "Initial real workdir:");

    let mut candidate_a = template.clone().with_name("candidate-a");
    let mut candidate_b = template.with_name("candidate-b");

    // These actions execute concurrently. Both read the same lower workdir,
    // while each writes into its own private COW upper directory.
    let action_a = candidate_a.run_pending(&[
        "sh",
        "-c",
        "printf 'candidate-a\n' > selected.txt; printf 'from-a\n' > only-a.txt",
    ]);
    let action_b = candidate_b.run_pending(&[
        "sh",
        "-c",
        "printf 'candidate-b\n' > selected.txt; printf 'from-b\n' > only-b.txt; rm base.txt",
    ]);

    let (pending_a, pending_b) = tokio::try_join!(action_a, action_b)?;
    assert!(pending_a.run_result.success());
    assert!(pending_b.run_result.success());

    // Neither completed action has changed the real workdir yet.
    show_workspace(
        workdir.path(),
        "After both speculative actions (before decision):",
    );
    show_changes("candidate-a", &pending_a.branch)?;
    show_changes("candidate-b", &pending_b.branch)?;

    let (_, mut branch_a) = pending_a.into_parts();
    let (_, mut branch_b) = pending_b.into_parts();

    println!("\nDecision: select candidate-b");
    branch_b.commit()?;
    branch_a.abort()?;

    show_workspace(workdir.path(), "After commit(B) + abort(A):");

    assert_eq!(
        fs::read_to_string(workdir.path().join("selected.txt"))?,
        "candidate-b\n"
    );
    assert!(!workdir.path().join("base.txt").exists());
    assert!(!workdir.path().join("only-a.txt").exists());
    assert_eq!(
        fs::read_to_string(workdir.path().join("only-b.txt"))?,
        "from-b\n"
    );

    Ok(())
}
