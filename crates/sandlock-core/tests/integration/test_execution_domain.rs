use sandlock_core::execution_domain::ExecutionDomain;
use sandlock_core::{FilesystemBackend, Protection, Sandbox, StdioMode};
use std::{fs, path::Path, time::Duration};

fn sandbox(path: &Path) -> Sandbox {
    let mut sandbox = sandbox_builder(path).build().unwrap();
    sandbox.enable_session_domain().unwrap();
    sandbox
}

fn sandbox_builder(path: &Path) -> sandlock_core::SandboxBuilder {
    let mut builder = Sandbox::builder()
        .filesystem_backend(FilesystemBackend::Auto)
        .bubblewrap_path(test_helper())
        .bubblewrap_bootstrap_path(test_bootstrap())
        .control_socket(false)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev/urandom")
        .fs_read("/dev/null")
        .fs_write("/dev/null")
        .fs_write(path);
    for protection in [
        Protection::NetTcp,
        Protection::FsIoctlDev,
        Protection::SignalScope,
        Protection::AbstractUnixSocketScope,
    ] {
        builder = builder.allow_degraded(protection);
    }
    builder
}

#[tokio::test]
async fn managed_session_cow_snapshots_keep_lower_immutable() {
    use sandlock_core::{FsSnapshot, ResolvedFilesystemBackend};
    for backend in [FilesystemBackend::Auto, FilesystemBackend::Bubblewrap] {
        let source = tempfile::tempdir().unwrap();
        let snapshots = tempfile::tempdir().unwrap();
        let branches = tempfile::tempdir().unwrap();
        let checkpoints = tempfile::tempdir().unwrap();
        let control = tempfile::tempdir().unwrap();
        fs::write(source.path().join("base"), b"lower").unwrap();
        let mut base = FsSnapshot::capture(source.path(), snapshots.path()).unwrap();
        let mut sb = sandbox_builder(control.path())
            .filesystem_backend(backend)
            .chroot("/")
            .fs_mount("/workspace", base.root_dir())
            .fs_deny(base.root_dir())
            .fs_deny(branches.path())
            .workdir(base.root_dir())
            .workdir_virtual("/workspace")
            .cwd("/workspace")
            .fs_storage(branches.path())
            .build()
            .unwrap();
        if matches!(
            sb.resolved_filesystem_backend().unwrap(),
            ResolvedFilesystemBackend::Landlock { .. }
        ) {
            sb.workdir_virtual = None;
            sb.cwd = Some(base.root_dir().to_path_buf());
        }
        sb.enable_session_domain().unwrap();
        let mut branch = sb.create_fs_branch_from_snapshot(&base).unwrap();
        let upper = branch.upper_dir().join("base");
        sb.attach_fs_branch(&mut branch).unwrap();
        launch(
            &mut sb,
            control.path(),
            r#"
import os, sys, time, pathlib
control = pathlib.Path(sys.argv[1])
children = []
for i in range(40):
    pid = os.fork()
    if pid == 0:
        os.setpgid(0, 0)
        with open('/dev/urandom', 'rb', buffering=0) as entropy:
            assert len(entropy.read(16)) == 16
        pathlib.Path(f'/workspace/child-{i}').write_text(str(i))
        os._exit(0)
    children.append(pid)
for pid in children:
    assert os.waitpid(pid, 0)[1] == 0
with open('/workspace/base', 'ab', buffering=0) as writer:
    writer.write(b'x')
    (control / 'ready').write_text('ready')
    while True:
        writer.write(b'x')
        time.sleep(.005)
"#,
        )
        .await;
        wait_file(&control.path().join("ready")).await;
        for _ in 0..3 {
            let domain = sb.execution_domain().unwrap();
            let guard = sb.pause_and_wait(Duration::from_secs(5)).await.unwrap();
            let expected = fs::read(&upper).unwrap();
            domain.signal(libc::SIGCONT).unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(fs::read(&upper).unwrap(), expected);
            let mut checkpoint = guard
                .checkpoint_attached_fs_branch(checkpoints.path())
                .await
                .unwrap();
            guard.resume().unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                fs::read(checkpoint.root_dir().join("base")).unwrap(),
                expected
            );
            assert_eq!(
                fs::read(checkpoint.root_dir().join("child-39")).unwrap(),
                b"39"
            );
            assert_eq!(fs::read(base.root_dir().join("base")).unwrap(), b"lower");
            assert_eq!(fs::read(source.path().join("base")).unwrap(), b"lower");
            assert!(!source.path().join("child-0").exists());
            checkpoint.destroy().unwrap();
        }
        sb.kill().unwrap();
        sb.wait().await.unwrap();
        let mut branch = sb.take_attached_fs_branch().await.unwrap();
        branch.abort().unwrap();
        base.destroy().unwrap();
    }
}

#[tokio::test]
async fn managed_session_bootstrap_error_preserves_errno() {
    use sandlock_core::error::SandboxRuntimeError;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let bootstrap = dir.path().join("fail-bootstrap");
    fs::write(
        &bootstrap,
        r#"#!/usr/bin/python3
import os, struct, sys
fd = int(sys.argv[sys.argv.index('--exec-status-fd') + 1])
stage = b'compatibility probe denied'
os.write(fd, b'SLXF' + struct.pack('<iH', 1, len(stage)) + stage)
os._exit(126)
"#,
    )
    .unwrap();
    fs::set_permissions(&bootstrap, fs::Permissions::from_mode(0o700)).unwrap();
    let mut sb = sandbox_builder(dir.path())
        .filesystem_backend(FilesystemBackend::Bubblewrap)
        .bubblewrap_bootstrap_path(&bootstrap)
        .build()
        .unwrap();
    sb.enable_session_domain().unwrap();
    let error = sb.create(&["/usr/bin/true"]).await.unwrap_err();
    assert!(
        matches!(error, sandlock_core::SandlockError::Runtime(
        SandboxRuntimeError::ExecLaunch { errno: Some(libc::EPERM), ref stage, .. }
    ) if stage == "compatibility probe denied"),
        "{error}"
    );
}

fn test_helper() -> std::path::PathBuf {
    std::env::var_os("SANDLOCK_TEST_BWRAP")
        .map(Into::into)
        .unwrap_or_else(|| "/usr/bin/bwrap".into())
}

fn test_bootstrap() -> std::path::PathBuf {
    std::env::var_os("SANDLOCK_TEST_BOOTSTRAP")
        .map(Into::into)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_sandlock-bootstrap").into())
}

#[test]
fn managed_session_older_kernel_capabilities() {
    use std::os::unix::process::CommandExt;

    // Exercise each missing prerequisite on a modern kernel as well as the
    // real old-kernel run. This inherited test-only filter never removes a
    // production filter; it makes the two newer operations return EINVAL.
    for (missing_wait, missing_thread) in [(true, false), (false, true), (true, true)] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([
            "test_execution_domain::",
            "--skip",
            "managed_session_older_kernel_capabilities",
            "--test-threads=1",
            "--nocapture",
        ]);
        // SAFETY: pre_exec only invokes raw prctl/syscall with stack-owned BPF
        // data. It allocates nothing and does not touch locks after fork.
        unsafe {
            command.pre_exec(move || {
                let stmt = |code, k| libc::sock_filter {
                    code,
                    jt: 0,
                    jf: 0,
                    k,
                };
                let jump = |k, jf| libc::sock_filter {
                    code: 0x15,
                    jt: 0,
                    jf,
                    k,
                };
                let mask = |k| libc::sock_filter {
                    code: 0x45,
                    jt: 0,
                    jf: 1,
                    k,
                };
                let filter = [
                    stmt(0x20, 0),
                    jump(libc::SYS_seccomp as u32, 3),
                    stmt(0x20, 24),
                    mask(if missing_wait { 1 << 5 } else { 0 }),
                    stmt(0x06, 0x0005_0000 | libc::EINVAL as u32),
                    stmt(0x20, 0),
                    jump(libc::SYS_pidfd_open as u32, 3),
                    stmt(0x20, 24),
                    mask(if missing_thread {
                        libc::O_EXCL as u32
                    } else {
                        0
                    }),
                    stmt(0x06, 0x0005_0000 | libc::EINVAL as u32),
                    stmt(0x06, 0x7fff_0000),
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr() as *mut libc::sock_filter,
                };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                    || libc::syscall(libc::SYS_seccomp, 1, 0, &program) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "missing_wait={missing_wait} missing_thread={missing_thread}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
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
        .bubblewrap_path(test_helper())
        .bubblewrap_bootstrap_path(test_bootstrap())
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
