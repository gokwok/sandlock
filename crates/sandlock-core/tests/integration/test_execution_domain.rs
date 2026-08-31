use sandlock_core::execution_domain::ExecutionDomain;
use sandlock_core::{Sandbox, StdioMode};
use std::{fs, path::Path, time::Duration};

fn sandbox(path: &Path) -> Sandbox {
    let mut sandbox = Sandbox::builder()
        .control_socket(false)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev/null")
        .fs_write("/dev/null")
        .fs_write(path)
        .build()
        .unwrap();
    sandbox.enable_session_domain().unwrap();
    sandbox
}

async fn launch(sandbox: &mut Sandbox, path: &Path, script: &str) {
    let process = sandbox
        .popen_checked(
            &["python3", "-c", script, path.to_str().unwrap()],
            StdioMode::Null,
            StdioMode::Null,
            StdioMode::Inherit,
        )
        .await
        .unwrap();
    drop(process);
}

async fn wait_file(path: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

const WRITER: &str = r#"
import os, sys, time, pathlib
root = pathlib.Path(sys.argv[1])
child = os.fork()
if child == 0:
    os.setpgid(0, 0)
    (root / 'identity').write_text(f'{os.getpid()} {os.getpgrp()} {os.getsid(0)}')
    with (root / 'writes').open('ab', buffering=0) as f:
        while True:
            f.write(b'x')
            time.sleep(.005)
else:
    while not (root / 'exit').exists(): time.sleep(.01)
    os._exit(23)
"#;

#[tokio::test]
async fn managed_session_freezes_and_reaps_new_process_groups() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    launch(&mut sb, dir.path(), WRITER).await;
    wait_file(&dir.path().join("writes")).await;
    let identity = fs::read_to_string(dir.path().join("identity")).unwrap();
    let ids: Vec<i32> = identity
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_eq!(
        ids[2],
        sb.execution_domain().unwrap().descriptor().session_id
    );
    let domain = sb.execution_domain().unwrap();
    let guard = sb.pause_and_wait(Duration::from_secs(5)).await.unwrap();
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    domain.signal(libc::SIGCONT).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
    guard.resume().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(fs::metadata(dir.path().join("writes")).unwrap().len() > size);
    sb.kill().unwrap();
    tokio::time::timeout(Duration::from_secs(10), sb.wait())
        .await
        .unwrap()
        .unwrap();
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
    sb.execution_domain()
        .unwrap()
        .signal(libc::SIGKILL)
        .unwrap();
}

#[tokio::test]
async fn managed_session_wait_cleans_descendants_after_leader_exit() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    launch(&mut sb, dir.path(), WRITER).await;
    wait_file(&dir.path().join("writes")).await;
    let descriptor = sb.execution_domain().unwrap().descriptor();
    fs::write(dir.path().join("exit"), "exit").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), sb.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.code(), Some(23));
    assert!(
        ExecutionDomain::open(descriptor).is_err(),
        "reaped anchor cannot be reopened"
    );
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
}

#[tokio::test]
async fn managed_session_keeps_setsid_denied_and_native_group_signals_working() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    let result = sb
        .run(&[
            "python3",
            "-c",
            r#"
import os, signal
pid = os.fork()
if pid == 0:
    os.setpgid(0, 0)
    try: os.setsid()
    except PermissionError: pass
    else: os._exit(10)
    os.killpg(os.getpgrp(), signal.SIGTERM)
    os._exit(11)
_, status = os.waitpid(pid, 0)
assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGTERM
"#,
        ])
        .await
        .unwrap();
    assert!(result.success(), "{:?}", result.stderr);
}

#[tokio::test]
async fn managed_session_freeze_survives_concurrent_thread_and_process_creation() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    launch(
        &mut sb,
        dir.path(),
        r#"
import os, sys, pathlib, threading, time
root = pathlib.Path(sys.argv[1])
def spawn():
    while True:
        pid = os.fork()
        if pid == 0:
            os.setpgid(0, 0)
            (root / 'child').write_text('write')
            os._exit(0)
        os.waitpid(pid, 0)
threading.Thread(target=spawn, daemon=True).start()
(root / 'ready').touch()
while True:
    t = threading.Thread(target=lambda: time.sleep(.001))
    t.start(); t.join()
"#,
    )
    .await;
    wait_file(&dir.path().join("ready")).await;
    for _ in 0..5 {
        let guard = sb.pause_and_wait(Duration::from_secs(5)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        guard.resume().unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sb.kill().unwrap();
    tokio::time::timeout(Duration::from_secs(10), sb.wait())
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn managed_session_is_explicit_and_not_a_serialized_live_handle() {
    let dir = tempfile::tempdir().unwrap();
    let sb = sandbox(dir.path());
    let json = serde_json::to_string(&sb).unwrap();
    assert!(!json.contains("session_domain"));
    assert!(sb.clone().execution_domain().is_none());
    let mut no_supervisor = Sandbox::builder().no_supervisor(true).build().unwrap();
    assert!(no_supervisor.enable_session_domain().is_err());
}

#[tokio::test]
async fn managed_session_kills_while_frozen_without_releasing_writers() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    launch(&mut sb, dir.path(), WRITER).await;
    wait_file(&dir.path().join("writes")).await;
    let guard = sb.pause_and_wait(Duration::from_secs(5)).await.unwrap();
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    guard.kill().unwrap();
    tokio::time::timeout(Duration::from_secs(10), sb.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
}

#[tokio::test]
async fn managed_session_rejects_wrong_anchor_and_drop_cleans_all_groups() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    launch(&mut sb, dir.path(), WRITER).await;
    wait_file(&dir.path().join("writes")).await;
    let mut descriptor = sb.execution_domain().unwrap().descriptor();
    descriptor.anchor_start_time += 1;
    assert!(ExecutionDomain::open(descriptor).is_err());
    drop(sb);
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
}

#[tokio::test]
async fn managed_session_cpu_throttle_cannot_resume_a_manual_freeze() {
    let dir = tempfile::tempdir().unwrap();
    let mut sb = sandbox(dir.path());
    sb.max_cpu = Some(50);
    launch(&mut sb, dir.path(), WRITER).await;
    wait_file(&dir.path().join("writes")).await;
    let guard = sb.pause_and_wait(Duration::from_secs(5)).await.unwrap();
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
    guard.resume().unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(fs::metadata(dir.path().join("writes")).unwrap().len() > size);
    sb.kill().unwrap();
    sb.wait().await.unwrap();
}

#[tokio::test]
async fn managed_session_vfork_wait_fails_freeze_closed_and_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("vfork.c");
    let binary = dir.path().join("vfork");
    fs::write(
        &source,
        r#"
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    if (chdir(argv[1])) return 10;
    pid_t child = vfork();
    if (!child) {
        close(open("ready", O_CREAT|O_WRONLY, 0600));
        while (access("release", F_OK)) usleep(1000);
        _exit(0);
    }
    if (child < 0 || waitpid(child, 0, 0) < 0) return 11;
    close(open("recovered", O_CREAT|O_WRONLY, 0600));
    return 0;
}
"#,
    )
    .unwrap();
    assert!(std::process::Command::new("cc")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap()
        .success());
    let mut sb = sandbox(dir.path());
    let process = sb
        .popen_checked(
            &[binary.to_str().unwrap(), dir.path().to_str().unwrap()],
            StdioMode::Null,
            StdioMode::Null,
            StdioMode::Inherit,
        )
        .await
        .unwrap();
    drop(process);
    wait_file(&dir.path().join("ready")).await;
    assert!(sb.pause_and_wait(Duration::from_millis(200)).await.is_err());
    fs::write(dir.path().join("release"), "go").unwrap();
    wait_file(&dir.path().join("recovered")).await;
    assert!(tokio::time::timeout(Duration::from_secs(5), sb.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
}

#[tokio::test]
async fn managed_session_bubblewrap_keeps_all_payload_groups_managed() {
    use sandlock_core::{FilesystemBackend, Protection};
    let dir = tempfile::tempdir().unwrap();
    let mut builder = Sandbox::builder()
        .filesystem_backend(FilesystemBackend::Bubblewrap)
        .bubblewrap_path("/usr/bin/bwrap")
        .bubblewrap_bootstrap_path(env!("CARGO_BIN_EXE_sandlock-bootstrap"))
        .control_socket(false)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev/null")
        .fs_write("/dev/null")
        .fs_write(dir.path());
    for protection in [
        Protection::NetTcp,
        Protection::FsIoctlDev,
        Protection::SignalScope,
        Protection::AbstractUnixSocketScope,
    ] {
        builder = builder.allow_degraded(protection);
    }
    let mut sb = builder.build().unwrap();
    sb.enable_session_domain().unwrap();
    launch(&mut sb, dir.path(), WRITER).await;
    wait_file(&dir.path().join("writes")).await;
    let guard = sb.pause_and_wait(Duration::from_secs(5)).await.unwrap();
    let size = fs::metadata(dir.path().join("writes")).unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(size, fs::metadata(dir.path().join("writes")).unwrap().len());
    guard.kill().unwrap();
    tokio::time::timeout(Duration::from_secs(5), sb.wait())
        .await
        .unwrap()
        .unwrap();
}
