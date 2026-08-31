use sandlock_core::{FilesystemBackend, Protection, ProtectionProvider, ProtectionStatus, Sandbox};

fn test_helper() -> std::path::PathBuf {
    std::env::var_os("SANDLOCK_TEST_BWRAP")
        .map(Into::into).unwrap_or_else(|| "/usr/bin/bwrap".into())
}

fn bubblewrap_builder() -> sandlock_core::SandboxBuilder {
    let mut builder = Sandbox::builder()
        .filesystem_backend(FilesystemBackend::Bubblewrap)
        .bubblewrap_path(test_helper())
        .bubblewrap_bootstrap_path(std::env::var_os("SANDLOCK_TEST_BOOTSTRAP")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_sandlock-bootstrap").into()))
        .control_socket(false)
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read("/etc/ld.so.cache")
        .fs_read("/dev/null")
        .fs_write("/dev/null");
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

#[test]
fn bubblewrap_reports_provider_aware_identity() {
    let sandbox = bubblewrap_builder().build().unwrap();
    let report = sandbox.filesystem_backend_report().unwrap();
    assert!(report
        .implementation_id
        .starts_with("bubblewrap-fs-v2:bwrap-"));
    assert_eq!(
        report.executable.as_deref(),
        Some(test_helper().as_path())
    );
    let protections = sandbox.active_protection_reports().unwrap();
    for protection in [Protection::FsRefer, Protection::FsTruncate] {
        let report = protections
            .iter()
            .find(|report| report.protection == protection)
            .unwrap();
        assert_eq!(report.status, ProtectionStatus::Active);
        assert_eq!(report.provider, Some(ProtectionProvider::MountNamespace));
    }
    for protection in [
        Protection::NetTcp,
        Protection::FsIoctlDev,
        Protection::SignalScope,
        Protection::AbstractUnixSocketScope,
    ] {
        let report = protections
            .iter()
            .find(|report| report.protection == protection)
            .unwrap();
        assert_eq!(report.status, ProtectionStatus::Degraded);
        assert_eq!(report.provider, None);
    }
}

#[tokio::test]
async fn bubblewrap_runs_with_an_empty_root_and_explicit_grants() {
    let result = bubblewrap_builder()
        .build()
        .unwrap()
        .run(&["sh", "-c", "printf bubblewrap-ok"])
        .await
        .unwrap();
    assert!(
        result.success(),
        "stderr: {}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    assert_eq!(result.stdout.as_deref(), Some(b"bubblewrap-ok".as_slice()));
}

#[tokio::test]
async fn bubblewrap_read_only_random_device_preserves_mount_and_fd_restrictions() {
    let result = bubblewrap_builder()
        .fs_read("/dev/urandom")
        .fs_read("/proc")
        .env_var("DEVICE_TEST_VALUE", "delivered-after-bootstrap")
        .build().unwrap()
        .run(&["python3", "-c", r#"
import errno, os, fcntl
assert os.environ['DEVICE_TEST_VALUE'] == 'delivered-after-bootstrap'
for line in open('/proc/self/status'):
    if line.startswith(('CapEff:', 'CapPrm:', 'CapInh:', 'CapAmb:', 'CapBnd:')):
        assert int(line.split()[1], 16) == 0, line
for path in ('/dev/urandom', '/dev/../dev/urandom'):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    assert os.fstatvfs(fd).f_flag & os.ST_RDONLY
    assert os.fstatvfs(fd).f_flag & os.ST_NODEV
    assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    assert len(os.read(fd, 32)) == 32
    for action in (
        lambda: os.write(fd, b'x'),
        lambda: os.open(path, os.O_WRONLY),
        lambda: os.open('/proc/self/fd/%d' % fd, os.O_RDWR),
        lambda: os.fchmod(fd, 0o600),
    ):
        try:
            action()
        except OSError as error:
            assert error.errno in (errno.EBADF, errno.EACCES, errno.EPERM, errno.EROFS), error
        else:
            raise AssertionError('read-only device mutation was allowed')
    os.close(fd)
directory = os.open('/dev', os.O_RDONLY | os.O_DIRECTORY)
fd = os.open('urandom', os.O_RDONLY, dir_fd=directory)
assert len(os.read(fd, 16)) == 16
os.close(fd)
os.close(directory)
for _ in range(40):
    pid = os.fork()
    if pid == 0:
        with open('/dev/urandom', 'rb', buffering=0) as stream:
            assert len(stream.read(16)) == 16
        os._exit(0)
    assert os.waitpid(pid, 0)[1] == 0
print('read-only-device-ok')
"#]).await.unwrap();
    assert!(result.success(), "{}", result.stderr_str().unwrap_or_default());
    assert_eq!(result.stdout_str(), Some("read-only-device-ok"));
}

#[tokio::test]
async fn bubblewrap_read_only_devices_respect_denials_and_random_seed() {
    let denied = bubblewrap_builder()
        .fs_read("/dev/urandom")
        .fs_read("/proc")
        .policy_fn(|event, ctx| {
            if event.syscall == "execve" { ctx.deny_path("/dev/urandom"); }
            sandlock_core::policy_fn::Verdict::Allow
        })
        .build().unwrap()
        .run(&["sh", "-c", "if head -c 16 /dev/../dev/urandom; then exit 1; fi; printf denied"])
        .await.unwrap();
    assert!(denied.success(), "{}", denied.stderr_str().unwrap_or_default());
    assert_eq!(denied.stdout_str(), Some("denied"));
    let mut seeded = bubblewrap_builder().fs_read("/dev/urandom").random_seed(42).build().unwrap();
    let command = ["sh", "-c", "od -A n -N 16 -t x1 /dev/urandom"];
    let first = seeded.clone().run(&command).await.unwrap();
    let second = seeded.run(&command).await.unwrap();
    assert!(first.success() && second.success());
    assert!(!first.stdout.as_deref().unwrap().is_empty());
    assert_eq!(first.stdout, second.stdout);
}

#[tokio::test]
async fn bubblewrap_loader_environment_only_reaches_confined_workload() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("constructor.c");
    let library = dir.path().join("constructor.so");
    std::fs::write(&source, r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((constructor)) static void check_confinement(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) _exit(91);
    char line[256];
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line, "Cap", 3) && strtoull(strchr(line, ':') + 1, NULL, 16)) _exit(92);
    }
    fclose(status);
    setenv("CONFINED_PRELOAD_RAN", "yes", 1);
}
"#).unwrap();
    assert!(std::process::Command::new("cc").args(["-shared", "-fPIC"])
        .arg(&source).arg("-o").arg(&library).status().unwrap().success());
    let result = bubblewrap_builder()
        .fs_read(&library).fs_read("/proc").fs_read("/dev/urandom")
        .env_var("LD_PRELOAD", library.to_string_lossy())
        .build().unwrap()
        .run(&["sh", "-c", "test \"$CONFINED_PRELOAD_RAN\" = yes"])
        .await.unwrap();
    assert!(result.success(), "{}", result.stderr_str().unwrap_or_default());
}

#[tokio::test]
async fn bubblewrap_missing_read_grant_does_not_mount_its_parent() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("optional/config");
    let secret = temporary.path().join("secret");
    std::fs::write(&secret, b"private").unwrap();
    let result = bubblewrap_builder()
        .fs_read(&missing)
        .build().unwrap()
        .run(&["python3", "-c", r#"
import errno, sys
try:
    open(sys.argv[1])
except OSError as error:
    assert error.errno == errno.ENOENT, error
else:
    raise AssertionError('missing path opened')
try:
    open(sys.argv[2])
except OSError as error:
    assert error.errno in (errno.ENOENT, errno.EACCES), error
else:
    raise AssertionError('sibling became readable')
"#, missing.to_str().unwrap(), secret.to_str().unwrap()])
        .await.unwrap();
    assert!(result.success(), "{}", result.stderr_str().unwrap_or_default());
}

#[tokio::test]
async fn bubblewrap_connects_to_an_explicitly_writable_named_unix_socket() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("control.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let script = r#"
import os
import socket
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(os.environ['CONTROL_SOCKET'])
client.close()
"#;
    let result = bubblewrap_builder()
        .fs_write(&socket)
        .env_var("CONTROL_SOCKET", socket.to_string_lossy())
        .build()
        .unwrap()
        .run(&["python3", "-c", script])
        .await
        .unwrap();
    assert!(
        result.success(),
        "stderr: {}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
}

#[tokio::test]
async fn bubblewrap_create_parks_the_payload_until_start() {
    let workspace = tempfile::tempdir().unwrap();
    let marker = workspace.path().join("ran");
    let command = format!("touch {}", marker.display());
    let mut sandbox = bubblewrap_builder()
        .fs_write(workspace.path())
        .build()
        .unwrap();
    sandbox.create(&["sh", "-c", &command]).await.unwrap();
    assert!(!marker.exists(), "payload ran before Sandbox::start");
    assert_eq!(sandbox.pid(), sandbox.payload_pid());
    assert_eq!(sandbox.pid(), sandbox.process_group());
    sandbox.start().unwrap();
    let result = sandbox.wait().await.unwrap();
    assert!(result.success());
    assert!(marker.exists());
}

#[tokio::test]
async fn bubblewrap_pause_resume_and_kill_target_the_payload_group() {
    let workspace = tempfile::tempdir().unwrap();
    let marker = workspace.path().join("resumed");
    let command = format!("sleep 0.15; touch {}", marker.display());
    let mut sandbox = bubblewrap_builder()
        .fs_write(workspace.path())
        .build()
        .unwrap();
    sandbox.create(&["sh", "-c", &command]).await.unwrap();
    sandbox.start().unwrap();
    sandbox.pause().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    assert!(!marker.exists());
    sandbox.resume().unwrap();
    assert!(sandbox.wait().await.unwrap().success());
    assert!(marker.exists());

    let mut sandbox = bubblewrap_builder().build().unwrap();
    sandbox
        .create(&["sh", "-c", "sleep 60 & wait"])
        .await
        .unwrap();
    sandbox.start().unwrap();
    let payload = sandbox.pid().unwrap();
    sandbox.kill().unwrap();
    let _ = sandbox.wait().await.unwrap();
    assert_eq!(unsafe { libc::kill(payload, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn bubblewrap_concurrent_launches_do_not_deadlock_after_fork() {
    let mut launches = tokio::task::JoinSet::new();
    for candidate in 0..8 {
        launches.spawn(async move {
            let expected = format!("candidate-{candidate}");
            let result = bubblewrap_builder()
                .clean_env(true)
                .env_var("EXPECTED", &expected)
                .build()
                .unwrap()
                .run(&["sh", "-c", "test \"$EXPECTED\" = \"$1\"", "sh", &expected])
                .await
                .unwrap();
            assert!(
                result.success(),
                "stderr: {}",
                String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
            );
        });
    }
    while let Some(result) = launches.join_next().await {
        result.unwrap();
    }
}

#[tokio::test]
async fn bubblewrap_cow_virtual_root_survives_frequent_fork_without_touching_lower() {
    let lower = tempfile::tempdir().unwrap();
    let storage = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    std::fs::write(lower.path().join("base.txt"), b"lower").unwrap();
    let script = r#"
import os
os.mkdir('/config/auth.json.lock')
children = []
for i in range(40):
    pid = os.fork()
    if pid == 0:
        with open(f'/workspace/child-{i}.txt', 'w') as handle:
            handle.write(str(i))
        os._exit(0)
    children.append(pid)
for pid in children:
    os.waitpid(pid, 0)
with open('/workspace/base.txt', 'w') as handle:
    handle.write('upper')
tool_fd = os.open('/workspace/generated-tool', os.O_CREAT | os.O_WRONLY, 0o755)
with open('/usr/bin/true', 'rb') as source:
    os.write(tool_fd, source.read())
os.close(tool_fd)
tool_pid = os.fork()
if tool_pid == 0:
    os.execve('/workspace/generated-tool', ['/workspace/generated-tool'], os.environ)
_, tool_status = os.waitpid(tool_pid, 0)
if tool_status != 0:
    raise SystemExit('generated executable failed')
with open('/proc/self/mountinfo', 'r') as handle:
    print(handle.read())
"#;
    let mut sandbox = bubblewrap_builder()
        .chroot("/")
        .fs_mount("/workspace", lower.path())
        .fs_mount("/config", config.path())
        .fs_deny(lower.path())
        .fs_deny(storage.path())
        .fs_read("/proc")
        .workdir(lower.path())
        .workdir_virtual("/workspace")
        .fs_storage(storage.path())
        .build()
        .unwrap();
    let mut pending = sandbox
        .run_pending(&["python3", "-c", script])
        .await
        .unwrap();
    assert!(
        pending.run_result.success(),
        "stderr: {}",
        String::from_utf8_lossy(pending.run_result.stderr.as_deref().unwrap_or_default())
    );
    assert_eq!(
        std::fs::read(lower.path().join("base.txt")).unwrap(),
        b"lower"
    );
    assert!(!lower.path().join("child-0.txt").exists());
    assert!(config.path().join("auth.json.lock").is_dir());
    assert!(pending.branch.changes().unwrap().len() >= 42);
    let mountinfo =
        String::from_utf8_lossy(pending.run_result.stdout.as_deref().unwrap_or_default());
    assert!(!mountinfo.contains(&lower.path().display().to_string()));
    assert!(!mountinfo.contains(&storage.path().display().to_string()));
    assert!(!mountinfo.contains("/proc/self/fd/"));
    pending.branch.commit().unwrap();
    assert_eq!(
        std::fs::read(lower.path().join("base.txt")).unwrap(),
        b"upper"
    );
    assert_eq!(
        std::fs::read(lower.path().join("child-39.txt")).unwrap(),
        b"39"
    );
    assert!(lower.path().join("generated-tool").exists());
}

#[tokio::test]
async fn bubblewrap_enforces_ro_rw_and_unmounted_boundaries() {
    let read_only = tempfile::tempdir().unwrap();
    let writable = tempfile::tempdir().unwrap();
    let invisible = tempfile::tempdir().unwrap();
    std::fs::write(read_only.path().join("data"), b"original").unwrap();
    std::fs::write(read_only.path().join("secret"), b"hidden").unwrap();
    std::fs::write(invisible.path().join("secret"), b"secret").unwrap();
    let invisible_guest = invisible.path().display().to_string();
    let script = format!(
        "set -eu; test \"$(cat /ro/data)\" = original; \
         ! sh -c 'echo changed > /ro/data' 2>/dev/null; \
         ! truncate -s 0 /ro/data 2>/dev/null; \
         ! chmod 777 /ro/data 2>/dev/null; \
         ! rm /ro/data 2>/dev/null; \
         ! cat /ro/secret >/dev/null 2>&1; \
         printf writable > /rw/new; \
         test ! -e '{invisible_guest}/secret'"
    );
    let result = bubblewrap_builder()
        .fs_mount_ro("/ro", read_only.path())
        .fs_deny("/ro/secret")
        .fs_mount("/rw", writable.path())
        .build()
        .unwrap()
        .run(&["sh", "-c", &script])
        .await
        .unwrap();
    assert!(
        result.success(),
        "stderr: {}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    assert_eq!(
        std::fs::read(read_only.path().join("data")).unwrap(),
        b"original"
    );
    assert_eq!(
        std::fs::read(writable.path().join("new")).unwrap(),
        b"writable"
    );
}
