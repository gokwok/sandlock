//! Recover malformed notification register data on affected vendor kernels.
//!
//! The installed filter rejects every non-native audit architecture. A
//! notification with another architecture therefore cannot be dispatched as
//! an unknown syscall and continued. Use the kernel's blocked-task register
//! view instead, or refuse the syscall if that view is unavailable.

use std::io::{self, Read};
use std::os::fd::RawFd;

use crate::sys::structs::{SeccompData, SeccompNotif};

#[derive(Default)]
pub(crate) struct MetadataReader {
    use_proc: bool,
}

impl MetadataReader {
    pub(crate) async fn validate(
        &mut self,
        fd: RawFd,
        mut notif: SeccompNotif,
    ) -> io::Result<SeccompNotif> {
        if !self.use_proc && (notif.data.arch != crate::arch::AUDIT_ARCH || notif.data.nr < 0) {
            self.use_proc = true;
            eprintln!(
                "sandlock: malformed kernel notification metadata; using verified task registers"
            );
        }
        if self.use_proc {
            // RECV can wake us before the notifying task actually sleeps.
            // Bound the wait for its kernel register view; never continue a
            // syscall whose arguments cannot be recovered safely.
            for attempt in 0..10 {
                match read_task_registers(fd, &notif) {
                    Ok(data) => {
                        notif.data = data;
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && attempt < 9 => {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(notif)
    }
}

fn read_task_registers(fd: RawFd, notif: &SeccompNotif) -> io::Result<SeccompData> {
    super::notif::id_valid(fd, notif.id)?;
    // Opening pins this proc entry. A reused numeric TID cannot supply data
    // for the old notification: ID_VALID must still succeed after the read.
    // Read kernel register state, never addresses supplied by the workload.
    let file = std::fs::File::open(format!("/proc/{}/syscall", notif.pid))?;
    let mut text = String::new();
    file.take(512).read_to_string(&mut text)?;
    super::notif::id_valid(fd, notif.id)?;
    parse_registers(&text)
}

fn parse_registers(text: &str) -> io::Result<SeccompData> {
    if text.trim() == "running" {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "notifying task has not parked yet",
        ));
    }
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid blocked-task syscall registers",
        )
    };
    let mut fields = text.split_whitespace();
    let nr = fields
        .next()
        .ok_or_else(invalid)?
        .parse::<i32>()
        .map_err(|_| invalid())?;
    if nr < 0 {
        return Err(invalid());
    }
    let mut hex = || {
        let word = fields
            .next()
            .and_then(|word| word.strip_prefix("0x"))
            .ok_or_else(invalid)?;
        u64::from_str_radix(word, 16).map_err(|_| invalid())
    };
    let mut args = [0; 6];
    for arg in &mut args {
        *arg = hex()?;
    }
    let _stack_pointer = hex()?;
    let instruction_pointer = hex()?;
    if fields.next().is_some() {
        return Err(invalid());
    }
    Ok(SeccompData {
        nr,
        arch: crate::arch::AUDIT_ARCH,
        instruction_pointer,
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_notification_uses_live_kernel_registers() {
        const WORKER: &str = "SANDLOCK_METADATA_TEST_WORKER";
        if std::env::var_os(WORKER).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["seccomp::notif_metadata::tests::malformed_notification_uses_live_kernel_registers", "--exact", "--nocapture"])
                .env(WORKER, "1")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        use std::os::fd::AsRawFd;
        // SAFETY: the isolated test worker exits directly after this probe.
        // Its child performs only raw syscalls and _exit after fork. The
        // alarm and parent-death signal bound both processes on failure.
        unsafe {
            libc::alarm(5);
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
        let filter =
            super::super::bpf::assemble_filter(&[libc::SYS_getpid as u32], &[], &[]).unwrap();
        let listener = super::super::bpf::install_filter(&filter).unwrap();
        // SAFETY: see the isolated probe invariant above.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // SAFETY: only raw syscalls with scalar arguments, then _exit.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                let result =
                    libc::syscall(libc::SYS_getpid, 11u64, 22u64, 33u64, 44u64, 55u64, 66u64);
                libc::_exit(if result == 42 { 0 } else { 1 });
            }
        }
        // SAFETY: repr(C) POD initialized to the zero fields RECV requires.
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        // SAFETY: listener and output pointer remain valid for this ioctl.
        assert_eq!(
            unsafe {
                libc::ioctl(
                    listener.as_raw_fd(),
                    crate::sys::structs::SECCOMP_IOCTL_NOTIF_RECV as _,
                    &mut notif,
                )
            },
            0
        );
        notif.data.arch = 0;
        notif.data.nr = -1;
        notif.data.args = [0; 6];
        let mut reader = MetadataReader::default();
        let restored = reader.validate(listener.as_raw_fd(), notif).await.unwrap();
        assert_eq!(restored.data.nr as i64, libc::SYS_getpid);
        assert_eq!(restored.data.args, [11, 22, 33, 44, 55, 66]);
        let response = crate::sys::structs::SeccompNotifResp {
            id: notif.id,
            val: 42,
            error: 0,
            flags: 0,
        };
        // SAFETY: response is a valid initialized ioctl input for this listener.
        assert_eq!(
            unsafe {
                libc::ioctl(
                    listener.as_raw_fd(),
                    crate::sys::structs::SECCOMP_IOCTL_NOTIF_SEND as _,
                    &response,
                )
            },
            0
        );
        assert!(reader.validate(listener.as_raw_fd(), notif).await.is_err());
        let mut status = 0;
        // SAFETY: wait for our own fork child, then exit the isolated worker
        // without returning to a harness carrying the getpid filter.
        unsafe {
            libc::waitpid(child, &mut status, 0);
            libc::_exit(if status == 0 { 0 } else { 1 });
        }
    }

    #[test]
    fn blocked_registers_preserve_all_argument_bits() {
        let data =
            parse_registers("56 0xffffffffffffff9c 0x1234 0x80041 0x1a4 0x0 0xffff 0x80 0x90\n")
                .unwrap();
        assert_eq!(data.nr, 56);
        assert_eq!(
            data.args,
            [(-100i64) as u64, 0x1234, 0x80041, 0x1a4, 0, 0xffff]
        );
        assert_eq!(data.instruction_pointer, 0x90);
    }

    #[test]
    fn incomplete_or_running_registers_are_rejected() {
        for text in [
            "running",
            "-1 0x80 0x90",
            "56 0x1",
            "56 1 2 3 4 5 6 7 8",
            "56 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8 extra",
        ] {
            assert!(parse_registers(text).is_err(), "{text}");
        }
    }
}
