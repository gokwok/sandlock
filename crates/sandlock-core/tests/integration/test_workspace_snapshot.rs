use sandlock_core::error::SandboxRuntimeError;
use sandlock_core::{BranchError, FsBranch, FsSnapshot, RunResult, Sandbox, SnapshotError};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

fn snapshot_sandbox(workdir: &Path, branch_storage: &Path, writable: Option<&Path>) -> Sandbox {
    let mut builder = Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(workdir)
        .workdir(workdir)
        .cwd(workdir)
        .fs_storage(branch_storage);
    if let Some(path) = writable {
        builder = builder.fs_write(path);
    }
    builder.build().unwrap()
}

fn throttled_snapshot_sandbox(workdir: &Path, branch_storage: &Path, writable: &Path) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .fs_read(workdir)
        .fs_write(writable)
        .workdir(workdir)
        .cwd(workdir)
        .fs_storage(branch_storage)
        .max_cpu(10)
        .build()
        .unwrap()
}

fn logical_snapshot_sandbox(
    logical_workspace: &Path,
    lower: &Path,
    branch_storage: &Path,
) -> Sandbox {
    Sandbox::builder()
        .fs_read("/usr")
        .fs_read("/lib")
        .fs_read_if_exists("/lib64")
        .fs_read("/bin")
        .fs_read("/etc")
        .fs_read("/proc")
        .fs_read("/dev")
        .chroot("/")
        .fs_mount(logical_workspace, lower)
        .fs_deny(lower)
        .fs_deny(branch_storage)
        .workdir(lower)
        .cwd(logical_workspace)
        .fs_storage(branch_storage)
        .build()
        .unwrap()
}

fn assert_backend_paths_hidden(result: &RunResult, paths: &[&Path]) {
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(result.stdout.as_deref().unwrap_or_default()),
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    for path in paths {
        assert!(!output.contains(path.to_string_lossy().as_ref()), "{output}");
    }
}

#[tokio::test]
async fn logical_mount_snapshot_branch_exposes_merged_view_after_reopen() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    fs::write(source.path().join("lower.txt"), b"lower").unwrap();
    fs::write(source.path().join("deleted.txt"), b"hidden after delete").unwrap();
    let mut snapshot = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let logical = source.path().to_string_lossy();

    let mut sandbox = logical_snapshot_sandbox(
        source.path(), snapshot.root_dir(), branch_storage.path(),
    );
    let mut branch = sandbox.create_fs_branch_from_snapshot(&snapshot).unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();
    let write = format!(
        "set -eu; \
         test \"$PWD\" = '{0}'; \
         printf 'content\\n' > '{0}/added.txt'; \
         read VALUE < '{0}/added.txt'; test \"$VALUE\" = content; \
         test -r '{0}/added.txt'; \
         mkdir '{0}/upper-dir'; \
         printf nested > '{0}/upper-dir/nested.txt'; \
         test \"$(cat '{0}/upper-dir/nested.txt')\" = nested; \
         cd '{0}/upper-dir'; \
         test \"$PWD\" = '{0}/upper-dir'; \
         test \"$(ls)\" = nested.txt; \
         cd '{0}'; \
         ln -s added.txt upper-link; \
         test \"$(cat upper-link)\" = content; \
         printf '#!/bin/sh\\nprintf executable' > upper-executable; \
         chmod 755 upper-executable; \
         test \"$(./upper-executable)\" = executable; \
         rm deleted.txt; \
         test ! -e deleted.txt; \
         if DELETED=$(cat deleted.txt 2>&1); then exit 1; fi; \
         case \"$DELETED\" in *'hidden after delete'*) exit 1;; esac; \
         case \"$(ls -1)\" in *added.txt*) :;; *) exit 1;; esac",
        logical,
    );
    let result = sandbox.run(&["sh", "-c", &write]).await.unwrap();
    assert!(result.success(), "{}", String::from_utf8_lossy(
        result.stderr.as_deref().unwrap_or_default()
    ));
    assert_backend_paths_hidden(&result, &[snapshot.root_dir(), branch_storage.path()]);

    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    let preserved = branch.persist().unwrap();
    drop(sandbox);

    let mut reopened = FsBranch::reopen(preserved).unwrap();
    let mut resumed = logical_snapshot_sandbox(
        source.path(), snapshot.root_dir(), branch_storage.path(),
    );
    resumed.attach_fs_branch(&mut reopened).unwrap();
    let read = format!(
        "set -eu; \
         test \"$PWD\" = '{0}'; \
         test \"$(cat '{0}/added.txt')\" = content; \
         test \"$(cat '{0}/upper-dir/nested.txt')\" = nested; \
         test \"$(readlink '{0}/upper-link')\" = added.txt; \
         test \"$('{0}/upper-executable')\" = executable; \
         test ! -e '{0}/deleted.txt'; \
         if DELETED=$(cat '{0}/deleted.txt' 2>&1); then exit 1; fi; \
         case \"$DELETED\" in *'hidden after delete'*) exit 1;; esac; \
         case \"$(ls -1 '{0}')\" in *upper-dir*) :;; *) exit 1;; esac",
        logical,
    );
    let result = resumed.run(&["sh", "-c", &read]).await.unwrap();
    assert!(result.success(), "{}", String::from_utf8_lossy(
        result.stderr.as_deref().unwrap_or_default()
    ));
    assert_backend_paths_hidden(&result, &[snapshot.root_dir(), branch_storage.path()]);
    let mut reopened = resumed.take_attached_fs_branch().await.unwrap();
    reopened.abort().unwrap();
    snapshot.destroy().unwrap();
}

#[tokio::test]
async fn snapshot_branch_checkpoint_can_seed_an_independent_child() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    let sibling_storage = tempfile::tempdir().unwrap();
    let checkpoint_storage = tempfile::tempdir().unwrap();
    let child_storage = tempfile::tempdir().unwrap();
    fs::write(source.path().join("existing.txt"), b"original").unwrap();
    fs::write(source.path().join("deleted.txt"), b"delete me").unwrap();
    fs::create_dir(source.path().join("nested-parent")).unwrap();
    let mut base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();

    fs::write(source.path().join("existing.txt"), b"source changed").unwrap();
    let mut sandbox = snapshot_sandbox(base.root_dir(), branch_storage.path(), None);
    let mut branch = sandbox.create_fs_branch_from_snapshot(&base).unwrap();
    let command = format!(
        "test \"$(cat {0}/existing.txt)\" = original && \
         printf checkpointed > {0}/existing.txt && \
         printf added > {0}/added.txt && \
         umask 077 && mkdir {0}/private-dir && \
         printf private > {0}/private-file && \
         umask 027 && mkdir {0}/group-dir && \
         mkdir -m 700 {0}/nested-parent/no-access && \
         mkdir {0}/nested-parent/no-access/subdir && \
         printf hidden > {0}/nested-parent/no-access/file && \
         printf deeper > {0}/nested-parent/no-access/subdir/file && \
         chmod 000 {0}/nested-parent/no-access && \
         ln -s nested-parent/no-access {0}/restricted-alias && \
         ln -s nested-parent/no-access/subdir {0}/restricted-deep-alias && \
         python3 -c 'import os; a=\"{0}/upper-a\"; b=\"{0}/upper-b\"; os.mkdir(a); os.mkdir(b); os.chdir(a); fd=os.open(b,os.O_RDONLY|os.O_DIRECTORY); os.fchdir(fd); open(\"via-fchdir\",\"w\").write(\"ok\"); regular=os.open(\"via-fchdir\",os.O_RDONLY);\ntry: os.fchdir(regular); raise AssertionError(\"regular fchdir succeeded\")\nexcept NotADirectoryError: pass\nopen(\"after-failed-fchdir\",\"w\").write(\"ok\")' && \
         umask 377 && mkdir {0}/nested-parent/read-only && \
         rm {0}/deleted.txt",
        base.root_dir().display()
    );
    let result = sandbox
        .run_in_branch(&mut branch, &["sh", "-c", &command])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    assert_eq!(base.read_range("existing.txt", 0, 64).unwrap(), b"original");
    assert!(base.stat("deleted.txt").is_ok());

    let mut sibling_sandbox = snapshot_sandbox(base.root_dir(), sibling_storage.path(), None);
    let mut sibling = sibling_sandbox
        .create_fs_branch_from_snapshot(&base)
        .unwrap();
    let sibling_command = format!(
        "test \"$(cat {0}/existing.txt)\" = original && \
         test ! -e {0}/added.txt && printf sibling > {0}/sibling.txt",
        base.root_dir().display()
    );
    assert!(sibling_sandbox
        .run_in_branch(&mut sibling, &["sh", "-c", &sibling_command])
        .await
        .unwrap()
        .success());
    assert!(base.stat("sibling.txt").is_err());
    assert!(matches!(
        base.destroy(),
        Err(SnapshotError::InUse { count: 2 })
    ));
    assert!(matches!(branch.commit(), Err(BranchError::Denied)));

    let mut checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
    assert_eq!(
        checkpoint.read_range("existing.txt", 0, 64).unwrap(),
        b"checkpointed"
    );
    assert_eq!(checkpoint.read_range("added.txt", 0, 64).unwrap(), b"added");
    assert!(checkpoint.stat("deleted.txt").is_err());
    assert_eq!(checkpoint.stat("private-dir").unwrap().mode, 0o700);
    assert_eq!(checkpoint.stat("private-file").unwrap().mode, 0o600);
    assert_eq!(checkpoint.stat("group-dir").unwrap().mode, 0o750);
    assert_eq!(
        checkpoint.stat("nested-parent/no-access").unwrap().mode,
        0o000
    );
    assert_eq!(
        checkpoint.stat("nested-parent/read-only").unwrap().mode,
        0o400
    );
    assert_eq!(
        checkpoint.read_range("upper-b/via-fchdir", 0, 64).unwrap(),
        b"ok"
    );
    assert_eq!(
        checkpoint
            .read_range("upper-b/after-failed-fchdir", 0, 64)
            .unwrap(),
        b"ok"
    );
    assert!(checkpoint.stat("upper-a/via-fchdir").is_err());
    assert!(checkpoint.stat("upper-a/after-failed-fchdir").is_err());
    assert!(base.stat("nested-parent/no-access").is_err());
    assert!(base.stat("nested-parent/read-only").is_err());

    let materialized = checkpoint_storage.path().join("materialized-checkpoint");
    checkpoint.materialize(&materialized).unwrap();
    assert_eq!(
        checkpoint
            .read_range("nested-parent/no-access/file", 0, 64)
            .unwrap(),
        b"hidden"
    );
    assert_eq!(
        fs::symlink_metadata(materialized.join("nested-parent/no-access"))
            .unwrap()
            .mode()
            & 0o7777,
        0o000
    );
    let checkpoint_diff = base.diff(&checkpoint, 128).unwrap();
    assert!(checkpoint_diff.changed_paths >= 6);

    let later = format!("printf later > {}/existing.txt", base.root_dir().display());
    assert!(sandbox
        .run_in_branch(&mut branch, &["sh", "-c", &later])
        .await
        .unwrap()
        .success());
    assert_eq!(
        checkpoint.read_range("existing.txt", 0, 64).unwrap(),
        b"checkpointed"
    );

    let mut child_sandbox = snapshot_sandbox(checkpoint.root_dir(), child_storage.path(), None);
    let mut child = child_sandbox
        .create_fs_branch_from_snapshot(&checkpoint)
        .unwrap();
    let verify = format!(
        "test \"$(cat {0}/existing.txt)\" = checkpointed && \
         test \"$(cat {0}/added.txt)\" = added && \
         test \"$(stat -c %a {0}/nested-parent/no-access)\" = 0 && \
         ! cat {0}/nested-parent/no-access/file >/dev/null 2>&1 && \
         ! cat {0}/restricted-alias/file >/dev/null 2>&1 && \
         ! cat {0}/restricted-deep-alias/file >/dev/null 2>&1 && \
         python3 -c 'import ctypes,os,stat; p=b\"{0}/nested-parent/no-access\"; fd=os.open(p,os.O_PATH); assert stat.S_IMODE(os.fstat(fd).st_mode)==0;\ntry: os.fchdir(fd); raise AssertionError(\"fchdir bypass\")\nexcept PermissionError: pass;\nclass H(ctypes.Structure): _fields_=[(\"flags\",ctypes.c_ulonglong),(\"mode\",ctypes.c_ulonglong),(\"resolve\",ctypes.c_ulonglong)]\nh=H(os.O_RDONLY,0,0); raw=ctypes.CDLL(None,use_errno=True).syscall(437,-100,b\"{0}/restricted-alias/file\",ctypes.byref(h),24); assert raw == -1 and ctypes.get_errno() in (13,1)' && \
         test ! -e {0}/deleted.txt && printf child > {0}/child.txt",
        checkpoint.root_dir().display()
    );
    let result = child_sandbox
        .run_in_branch(&mut child, &["sh", "-c", &verify])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    assert!(checkpoint.stat("child.txt").is_err());
    let grandchild_storage = tempfile::tempdir().unwrap();
    let grandchild_checkpoint = child.checkpoint(grandchild_storage.path()).unwrap();
    assert_eq!(
        grandchild_checkpoint
            .read_range("nested-parent/no-access/file", 0, 64)
            .unwrap(),
        b"hidden"
    );

    child.abort().unwrap();
    drop(grandchild_checkpoint);
    checkpoint.destroy().unwrap();
    sibling.abort().unwrap();
    branch.abort().unwrap();
    base.destroy().unwrap();
}

#[tokio::test]
async fn snapshot_fd_metadata_stays_bound_to_the_open_inode() {
    let source = tempfile::tempdir().unwrap();
    let base_storage = tempfile::tempdir().unwrap();
    let staging_storage = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("locked")).unwrap();
    fs::write(source.path().join("locked/file"), b"hidden").unwrap();
    let mut base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
    let mut staging_sandbox = snapshot_sandbox(base.root_dir(), staging_storage.path(), None);
    let mut staging_branch = staging_sandbox
        .create_fs_branch_from_snapshot(&base)
        .unwrap();
    let chmod = format!("chmod 000 {}/locked", base.root_dir().display());
    assert!(staging_sandbox
        .run_in_branch(&mut staging_branch, &["sh", "-c", &chmod])
        .await
        .unwrap()
        .success());
    let mut snapshot = staging_branch.checkpoint(snapshot_storage.path()).unwrap();
    staging_branch.abort().unwrap();
    base.destroy().unwrap();
    let mut sandbox = snapshot_sandbox(snapshot.root_dir(), branch_storage.path(), None);
    let mut branch = sandbox.create_fs_branch_from_snapshot(&snapshot).unwrap();
    let command = format!(
        "python3 -c 'import ctypes,os,platform,stat,sys; p=b\"{0}/locked\"; fd=os.open(p,os.O_PATH); assert stat.S_IMODE(os.fstat(fd).st_mode)==0; os.chmod(p,0o755); assert stat.S_IMODE(os.stat(p).st_mode)==0o755; assert stat.S_IMODE(os.fstat(fd).st_mode)==0; filefd=os.open(p+b\"/file\",os.O_RDONLY); machine=platform.machine(); libc=ctypes.CDLL(None,use_errno=True);\ntry: os.fchmod(filefd,0o777); raise AssertionError(\"lower fchmod succeeded\")\nexcept PermissionError: pass\ntry: os.utime(filefd,None); raise AssertionError(\"lower futimens succeeded\")\nexcept PermissionError: pass\nfor alias in (b\"/dev/fd/%d\"%filefd,b\"/proc/thread-self/fd/%d\"%filefd):\n try: os.chmod(alias,0o777); raise AssertionError(\"magic fd chmod succeeded\")\n except PermissionError: pass\nnr_fchmodat2=452; raw=libc.syscall(nr_fchmodat2,filefd,b\"\",0o777,0x1000); assert raw==-1 and ctypes.get_errno()==1; assert stat.S_IMODE(os.fstat(filefd).st_mode)==0o644; os.close(filefd)\ntry: os.open(b\"file\",os.O_RDONLY,dir_fd=fd); raise AssertionError(\"old lower dirfd bypassed mode\")\nexcept PermissionError: pass\ntry: os.fchdir(fd); raise AssertionError(\"old lower fd bypassed mode\")\nexcept PermissionError: pass\nstx=ctypes.create_string_buffer(256); nr_stx={{\"x86_64\":332,\"aarch64\":291}}[machine]; raw=libc.syscall(nr_stx,fd,b\"\",0x1000,0x2,stx); assert raw==0 and int.from_bytes(stx.raw[28:30],sys.byteorder)&0o7777==0; stx_null=ctypes.create_string_buffer(256); raw=libc.syscall(nr_stx,fd,ctypes.c_void_p(),0x1000,0x2,stx_null); assert raw==0 and int.from_bytes(stx_null.raw[28:30],sys.byteorder)&0o7777==0; sb=ctypes.create_string_buffer(256); nr_fstatat={{\"x86_64\":262,\"aarch64\":79}}[machine]; raw=libc.syscall(nr_fstatat,fd,b\"\",sb,0x1000); mode_off={{\"x86_64\":24,\"aarch64\":16}}[machine]; assert raw==0 and int.from_bytes(sb.raw[mode_off:mode_off+4],sys.byteorder)&0o7777==0'",
        snapshot.root_dir().display()
    );
    assert_eq!(snapshot.stat("locked/file").unwrap().mode, 0o644);
    let result = sandbox
        .run_in_branch(&mut branch, &["sh", "-c", &command])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    branch.abort().unwrap();
    snapshot.destroy().unwrap();
}

#[tokio::test]
async fn upper_open_failure_never_falls_through_to_lower_content() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    fs::write(source.path().join("protected.txt"), b"lower content").unwrap();
    let mut snapshot = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let mut sandbox = snapshot_sandbox(snapshot.root_dir(), branch_storage.path(), None);
    let mut branch = sandbox.create_fs_branch_from_snapshot(&snapshot).unwrap();
    let command = format!(
        "chmod 000 {0}/protected.txt && ! cat {0}/protected.txt >/dev/null 2>&1",
        snapshot.root_dir().display()
    );
    let result = sandbox
        .run_in_branch(&mut branch, &["sh", "-c", &command])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    branch.abort().unwrap();
    snapshot.destroy().unwrap();
}

#[tokio::test]
async fn lower_symlink_uses_the_merged_upper_target() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    let checkpoint_storage = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("target")).unwrap();
    fs::write(source.path().join("target/file"), b"lower content").unwrap();
    fs::write(source.path().join("target/remove"), b"remove me").unwrap();
    fs::write(source.path().join("file"), b"wrong root").unwrap();
    fs::create_dir(source.path().join("base")).unwrap();
    fs::write(source.path().join("base/child"), b"in-root").unwrap();
    std::os::unix::fs::symlink("/child", source.path().join("base/link")).unwrap();
    fs::create_dir(source.path().join("sub")).unwrap();
    std::os::unix::fs::symlink("target", source.path().join("alias")).unwrap();
    let mut snapshot = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let mut sandbox = snapshot_sandbox(snapshot.root_dir(), branch_storage.path(), None);
    let mut branch = sandbox.create_fs_branch_from_snapshot(&snapshot).unwrap();
    let command = format!(
        "python3 -c 'import ctypes,errno,os,platform,stat,threading; root=b\"{0}\"; alias=root+b\"/alias\"; target=root+b\"/target\";
try: os.open(alias,os.O_RDONLY|os.O_NOFOLLOW); raise AssertionError(\"nofollow followed\")
except OSError as e: assert e.errno==errno.ELOOP
libc=ctypes.CDLL(None,use_errno=True); nr={{\"x86_64\":437,\"aarch64\":437}}[platform.machine()]; dfd=os.open(target,os.O_PATH|os.O_DIRECTORY)
class H(ctypes.Structure): _fields_=[(\"flags\",ctypes.c_ulonglong),(\"mode\",ctypes.c_ulonglong),(\"resolve\",ctypes.c_ulonglong)]
h=H(os.O_RDONLY,0,8); raw=libc.syscall(nr,dfd,b\"../file\",ctypes.byref(h),24); assert raw==-1 and ctypes.get_errno()==errno.EXDEV
h.resolve=16; raw=libc.syscall(nr,dfd,b\"../file\",ctypes.byref(h),24); assert raw>=0 and os.read(raw,64)==b\"lower content\"; os.close(raw); os.close(dfd)
basefd=os.open(root+b\"/base\",os.O_PATH|os.O_DIRECTORY); h=H(os.O_RDONLY,0,16); raw=libc.syscall(nr,basefd,b\"link\",ctypes.byref(h),24); assert raw>=0 and os.read(raw,64)==b\"in-root\"; os.close(raw); os.close(basefd)
h=H(os.O_RDONLY,0,0); raw=libc.syscall(nr,-100,root+b\"/target/file\",ctypes.byref(h),16); assert raw==-1 and ctypes.get_errno()==errno.EINVAL
extended=(ctypes.c_ulonglong*4)(os.O_RDONLY,0,0,1); raw=libc.syscall(nr,-100,root+b\"/target/file\",extended,32); assert raw==-1 and ctypes.get_errno()==errno.E2BIG
barrier=threading.Barrier(12); won=[]
def create():
 barrier.wait()
 try:
  f=os.open(root+b\"/exclusive\",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o641); os.close(f); won.append(1)
 except FileExistsError: pass
threads=[threading.Thread(target=create) for _ in range(12)]; [t.start() for t in threads]; [t.join() for t in threads]; assert len(won)==1; assert stat.S_IMODE(os.stat(root+b\"/exclusive\").st_mode)==0o641' && \
         ! mkdir {0}/target && ! ln -s anything {0}/target/file && \
         ! touch {0}/missing/file && ! mkdir {0}/missing/child && test ! -e {0}/missing && \
         ln -s ../target {0}/sub/link && test \"$(cat {0}/sub/link/file)\" = 'lower content' && \
         printf source > {0}/noreplace-src && \
         python3 -c 'import ctypes,errno,os,platform; libc=ctypes.CDLL(None,use_errno=True); nr={{\"x86_64\":316,\"aarch64\":276}}[platform.machine()]; raw=libc.syscall(nr,-100,b\"{0}/noreplace-src\",-100,b\"{0}/target/file\",1); assert raw==-1 and ctypes.get_errno()==errno.EEXIST' && \
         test \"$(cat {0}/noreplace-src)\" = source && \
         rm {0}/alias/remove && test ! -e {0}/alias/remove && \
         printf upper > {0}/alias/new && test \"$(cat {0}/target/new)\" = upper && \
         mkdir {0}/alias/new-dir && test -d {0}/target/new-dir && \
         chmod 000 {0}/alias && \
         test \"$(stat -c %a {0}/target)\" = 0 && \
         test \"$(stat -L -c %a {0}/alias)\" = 0 && \
         ! cat {0}/alias/file >/dev/null 2>&1 && \
         python3 -c 'import ctypes,os; h=(ctypes.c_ulonglong*3)(os.O_RDONLY,0,4); libc=ctypes.CDLL(None,use_errno=True); raw=libc.syscall(437,-100,b\"{0}/alias/file\",h,24); assert raw == -1 and ctypes.get_errno() == 40'",
        snapshot.root_dir().display()
    );
    let result = sandbox
        .run_in_branch(&mut branch, &["sh", "-c", &command])
        .await
        .unwrap();
    assert!(
        result.success(),
        "{}",
        String::from_utf8_lossy(result.stderr.as_deref().unwrap_or_default())
    );
    let mut checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
    assert!(checkpoint.stat("target/remove").is_err());
    assert_eq!(checkpoint.read_range("target/new", 0, 64).unwrap(), b"upper");
    assert_eq!(checkpoint.stat("target").unwrap().mode, 0);
    assert!(checkpoint.stat("target/new-dir").is_ok());
    branch.abort().unwrap();
    checkpoint.destroy().unwrap();
    snapshot.destroy().unwrap();
}

#[test]
fn snapshot_branch_rejects_a_direct_lower_write_grant() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    fs::write(source.path().join("file"), b"base").unwrap();
    let snapshot = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let sandbox = Sandbox::builder()
        .fs_read(snapshot.root_dir())
        .fs_write(snapshot.root_dir())
        .workdir(snapshot.root_dir())
        .fs_storage(branch_storage.path())
        .build()
        .unwrap();

    assert!(matches!(
        sandbox.create_fs_branch_from_snapshot(&snapshot),
        Err(sandlock_core::SandlockError::Runtime(
            SandboxRuntimeError::Branch(BranchError::Denied)
        ))
    ));
}

#[tokio::test]
async fn attached_checkpoint_captures_a_stopped_writer_boundary() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    let checkpoint_storage = tempfile::tempdir().unwrap();
    let signal = tempfile::tempdir().unwrap();
    fs::write(source.path().join("live.txt"), b"base").unwrap();
    let mut base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let mut sandbox = snapshot_sandbox(base.root_dir(), branch_storage.path(), Some(signal.path()));
    let mut branch = sandbox.create_fs_branch_from_snapshot(&base).unwrap();
    let staged_path = branch.upper_dir().join("live.txt");
    sandbox.attach_fs_branch(&mut branch).unwrap();

    let command = format!(
        "printf one > {0}/live.txt; touch {1}/ready; \
         while test ! -e {1}/continue; do sleep 0.01; done; \
         printf two > {0}/live.txt; while :; do sleep 1; done",
        base.root_dir().display(),
        signal.path().display(),
    );
    sandbox.spawn(&["sh", "-c", &command]).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !signal.path().join("ready").exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "writer never became ready"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let guard = sandbox
        .pause_and_wait(Duration::from_secs(5))
        .await
        .unwrap();
    let mut checkpoint = guard
        .checkpoint_attached_fs_branch(checkpoint_storage.path())
        .await
        .unwrap();
    guard.resume().unwrap();
    fs::write(signal.path().join("continue"), b"").unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if fs::read(&staged_path).is_ok_and(|bytes| bytes == b"two") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "writer did not resume"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    sandbox.kill().unwrap();
    sandbox.wait().await.unwrap();
    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();

    assert_eq!(checkpoint.read_range("live.txt", 0, 64).unwrap(), b"one");
    assert_eq!(base.read_range("live.txt", 0, 64).unwrap(), b"base");
    branch.abort().unwrap();
    checkpoint.destroy().unwrap();
    base.destroy().unwrap();
}

#[tokio::test]
async fn paused_attached_branch_applies_a_validated_snapshot_delta_before_resume() {
    let source = tempfile::tempdir().unwrap();
    let base_storage = tempfile::tempdir().unwrap();
    let target_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    let validation_storage = tempfile::tempdir().unwrap();
    let checkpoint_storage = tempfile::tempdir().unwrap();
    let signal = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), b"base").unwrap();
    fs::write(source.path().join("deleted"), b"gone").unwrap();
    let mut base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
    fs::write(source.path().join("value"), b"target").unwrap();
    fs::remove_file(source.path().join("deleted")).unwrap();
    fs::write(source.path().join("added"), b"new").unwrap();
    let mut target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
    let delta = base
        .delta_to(
            &target,
            sandlock_core::SnapshotDeltaLimits::default(),
            &sandlock_core::SnapshotDeltaPolicy {
                allow_symlinks: false,
                protected_paths: Vec::new(),
            },
        )
        .unwrap();
    let mut sandbox = snapshot_sandbox(base.root_dir(), branch_storage.path(), Some(signal.path()));
    let mut branch = sandbox.create_fs_branch_from_snapshot(&base).unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();
    let command = format!(
        "touch {1}/ready; while test ! -e {1}/continue; do sleep 0.01; done; \
         test \"$(cat {0}/value)\" = target; \
         test \"$(cat {0}/added)\" = new; \
         test ! -e {0}/deleted; \
         touch {1}/observed; while :; do sleep 1; done",
        base.root_dir().display(),
        signal.path().display(),
    );
    sandbox.spawn(&["sh", "-c", &command]).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !signal.path().join("ready").exists() {
        assert!(tokio::time::Instant::now() < deadline, "writer never became ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let guard = sandbox
        .pause_and_wait(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        guard
            .apply_attached_fs_delta(
                &delta,
                &[],
                sandlock_core::SnapshotCompareLimits::default(),
                validation_storage.path(),
            )
            .await
            .unwrap(),
        delta.summary()
    );
    guard.resume().unwrap();
    fs::write(signal.path().join("continue"), b"").unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !signal.path().join("observed").exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "resumed process did not observe the committed delta"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    sandbox.kill().unwrap();
    sandbox.wait().await.unwrap();
    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    let mut checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
    assert_eq!(checkpoint.read_range("value", 0, 16).unwrap(), b"target");
    assert_eq!(checkpoint.read_range("added", 0, 16).unwrap(), b"new");
    assert!(checkpoint.stat("deleted").is_err());
    branch.abort().unwrap();
    checkpoint.destroy().unwrap();
    target.destroy().unwrap();
    base.destroy().unwrap();
}

#[tokio::test]
async fn paused_attached_delta_rejects_a_stale_declared_dependency_without_writing() {
    let source = tempfile::tempdir().unwrap();
    let base_storage = tempfile::tempdir().unwrap();
    let target_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    let validation_storage = tempfile::tempdir().unwrap();
    let checkpoint_storage = tempfile::tempdir().unwrap();
    let signal = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), b"base").unwrap();
    fs::write(source.path().join("dependency"), b"base").unwrap();
    let mut base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
    fs::write(source.path().join("value"), b"target").unwrap();
    let mut target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
    let delta = base
        .delta_to(
            &target,
            sandlock_core::SnapshotDeltaLimits::default(),
            &sandlock_core::SnapshotDeltaPolicy::default(),
        )
        .unwrap();
    let mut sandbox = snapshot_sandbox(base.root_dir(), branch_storage.path(), Some(signal.path()));
    let mut branch = sandbox.create_fs_branch_from_snapshot(&base).unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();
    let command = format!(
        "printf stale > {0}/dependency; touch {1}/ready; while :; do sleep 1; done",
        base.root_dir().display(),
        signal.path().display(),
    );
    sandbox.spawn(&["sh", "-c", &command]).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !signal.path().join("ready").exists() {
        assert!(tokio::time::Instant::now() < deadline, "writer never became ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let guard = sandbox
        .pause_and_wait(Duration::from_secs(5))
        .await
        .unwrap();
    let error = guard
        .apply_attached_fs_delta(
            &delta,
            &[sandlock_core::SnapshotRequirement {
                path: "dependency".into(),
                scope: sandlock_core::SnapshotCompareScope::Content,
            }],
            sandlock_core::SnapshotCompareLimits::default(),
            validation_storage.path(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        sandlock_core::SandlockError::Runtime(SandboxRuntimeError::Branch(
            BranchError::Snapshot(SnapshotError::DeltaConflict { .. })
        ))
    ));
    guard.resume().unwrap();

    sandbox.kill().unwrap();
    sandbox.wait().await.unwrap();
    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    let mut checkpoint = branch.checkpoint(checkpoint_storage.path()).unwrap();
    assert_eq!(checkpoint.read_range("value", 0, 16).unwrap(), b"base");
    assert_eq!(checkpoint.read_range("dependency", 0, 16).unwrap(), b"stale");
    branch.abort().unwrap();
    checkpoint.destroy().unwrap();
    target.destroy().unwrap();
    base.destroy().unwrap();
}

#[test]
fn live_directory_delta_combines_dependency_proof_and_path_cas() {
    let source = tempfile::tempdir().unwrap();
    let base_storage = tempfile::tempdir().unwrap();
    let target_storage = tempfile::tempdir().unwrap();
    let destination = tempfile::tempdir().unwrap();
    fs::write(source.path().join("dependency"), b"base").unwrap();
    fs::write(source.path().join("output"), b"base").unwrap();
    let mut base = FsSnapshot::capture(source.path(), base_storage.path()).unwrap();
    fs::write(source.path().join("output"), b"target").unwrap();
    let mut target = FsSnapshot::capture(source.path(), target_storage.path()).unwrap();
    base.materialize(destination.path().join("workspace")).unwrap();
    let workspace = destination.path().join("workspace");
    let requirements = [sandlock_core::SnapshotRequirement {
        path: "dependency".into(),
        scope: sandlock_core::SnapshotCompareScope::Content,
    }];
    assert!(base
        .compare_directory_requirements(
            &workspace,
            &requirements,
            sandlock_core::SnapshotCompareLimits::default(),
        )
        .unwrap()
        .matched);
    let delta = base
        .delta_to(
            &target,
            sandlock_core::SnapshotDeltaLimits::default(),
            &sandlock_core::SnapshotDeltaPolicy::default(),
        )
        .unwrap();
    delta
        .apply_to_directory_with_requirements(
            &workspace,
            sandlock_core::SnapshotDeltaApplyMode::Initial,
            &requirements,
            sandlock_core::SnapshotCompareLimits::default(),
            Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(fs::read(workspace.join("output")).unwrap(), b"target");
    target.destroy().unwrap();
    base.destroy().unwrap();
}

#[tokio::test]
async fn paused_attached_guard_can_kill_without_resuming_user_code() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    fs::write(source.path().join("value"), b"base").unwrap();
    let mut base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let mut sandbox = snapshot_sandbox(base.root_dir(), branch_storage.path(), None);
    let mut branch = sandbox.create_fs_branch_from_snapshot(&base).unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();
    sandbox.spawn(&["sh", "-c", "while :; do sleep 1; done"]).await.unwrap();

    let guard = sandbox
        .pause_and_wait(Duration::from_secs(5))
        .await
        .unwrap();
    guard.kill().unwrap();
    sandbox.wait().await.unwrap();
    let mut branch = sandbox.take_attached_fs_branch().await.unwrap();
    branch.abort().unwrap();
    base.destroy().unwrap();
}

#[tokio::test]
async fn attached_checkpoint_stays_quiescent_with_cpu_throttling() {
    let source = tempfile::tempdir().unwrap();
    let snapshot_storage = tempfile::tempdir().unwrap();
    let branch_storage = tempfile::tempdir().unwrap();
    let checkpoint_storage = tempfile::tempdir().unwrap();
    let signal_dir = tempfile::tempdir().unwrap();
    let signal = signal_dir.path().join("ready");
    fs::write(source.path().join("value"), b"base").unwrap();
    let base = FsSnapshot::capture(source.path(), snapshot_storage.path()).unwrap();
    let mut sandbox =
        throttled_snapshot_sandbox(base.root_dir(), branch_storage.path(), signal_dir.path());
    let mut branch = sandbox.create_fs_branch_from_snapshot(&base).unwrap();
    sandbox.attach_fs_branch(&mut branch).unwrap();
    let command = format!(
        "printf one > {0}/value; touch {1}; while :; do printf two > {0}/value; done",
        base.root_dir().display(),
        signal.display()
    );
    sandbox.spawn(&["sh", "-c", &command]).await.unwrap();
    for _ in 0..200 {
        if signal.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(signal.exists());

    let guard = sandbox
        .pause_and_wait(Duration::from_secs(5))
        .await
        .unwrap();
    let checkpoint = guard
        .checkpoint_attached_fs_branch(checkpoint_storage.path())
        .await
        .unwrap();
    let captured = checkpoint.read_range("value", 0, 16).unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(checkpoint.read_range("value", 0, 16).unwrap(), captured);
    drop(guard);

    sandbox.kill().unwrap();
    sandbox.wait().await.unwrap();
    let mut detached = sandbox.take_attached_fs_branch().await.unwrap();
    detached.abort().unwrap();
}
