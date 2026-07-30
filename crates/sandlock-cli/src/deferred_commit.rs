use anyhow::{anyhow, Result};
use sandlock_core::{ExitStatus, RunResult};
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{FromRawFd, RawFd};

pub(crate) enum Decision {
    Commit,
    Abort,
}

/// CLI-owned endpoints for the deferred-commit control protocol.
///
/// Both descriptors are duplicated with `FD_CLOEXEC`. The sandbox child also
/// closes every unrelated descriptor above stderr before exec, so the action
/// cannot forge its ready event or resolve its own branch.
pub(crate) struct Control {
    decision: File,
    status: File,
}

impl Control {
    pub(crate) fn open(decision_fd: RawFd, status_fd: RawFd) -> Result<Self> {
        if decision_fd < 3 {
            return Err(anyhow!("--decision-fd must be 3 or greater"));
        }
        if status_fd < 3 {
            return Err(anyhow!(
                "--status-fd must be 3 or greater with --defer-commit"
            ));
        }
        if decision_fd == status_fd {
            return Err(anyhow!("--decision-fd and --status-fd must be different"));
        }

        Ok(Self {
            decision: duplicate_fd(decision_fd, "--decision-fd")?,
            status: duplicate_fd(status_fd, "--status-fd")?,
        })
    }

    /// Publish the pending event, then block until the controller chooses the
    /// branch outcome. Dropping the caller's PendingBranch on any error aborts
    /// the staged filesystem changes.
    pub(crate) fn announce_and_wait(mut self, result: &RunResult) -> Result<Decision> {
        write_status(&mut self.status, result, Some("pending"))
            .map_err(|e| anyhow!("failed to write deferred status: {e}"))?;
        drop(self.status);

        let mut line = String::new();
        let bytes = BufReader::new(self.decision)
            .read_line(&mut line)
            .map_err(|e| anyhow!("failed to read --decision-fd: {e}"))?;
        if bytes == 0 {
            return Err(anyhow!(
                "--decision-fd reached EOF before commit/abort; branch aborted"
            ));
        }

        match line.trim() {
            "commit" => Ok(Decision::Commit),
            "abort" => Ok(Decision::Abort),
            other => Err(anyhow!(
                "invalid decision {other:?}; expected `commit` or `abort`; branch aborted"
            )),
        }
    }
}

/// Preserve the original `--status-fd` one-line JSON contract for a normal
/// run. Callers intentionally treat this as best effort.
pub(crate) fn write_run_status(fd: RawFd, result: &RunResult) -> Result<()> {
    let mut status = duplicate_fd(fd, "--status-fd")?;
    write_status(&mut status, result, None)
}

#[derive(Serialize)]
struct Status<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
}

fn write_status(file: &mut File, result: &RunResult, state: Option<&str>) -> Result<()> {
    let (exit_code, signal) = exit_parts(result);
    serde_json::to_writer(
        &mut *file,
        &Status {
            state,
            exit_code,
            signal,
        },
    )?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn exit_parts(result: &RunResult) -> (i32, Option<i32>) {
    match result.exit_status {
        ExitStatus::Code(code) => (code, None),
        ExitStatus::Signal(signal) => (-1, Some(signal)),
        ExitStatus::Killed | ExitStatus::Timeout => (-1, None),
    }
}

fn duplicate_fd(fd: RawFd, flag: &str) -> Result<File> {
    if fd < 0 {
        return Err(anyhow!("{flag} must be a non-negative file descriptor"));
    }

    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(anyhow!(
            "failed to duplicate {flag} {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    #[test]
    fn status_json_keeps_existing_shape_without_state() {
        let result = RunResult {
            exit_status: ExitStatus::Code(7),
            stdout: None,
            stderr: None,
        };
        let mut output = tempfile::tempfile().unwrap();

        write_status(&mut output, &result, None).unwrap();
        output.rewind().unwrap();

        let value: serde_json::Value = serde_json::from_reader(output).unwrap();
        assert_eq!(value, serde_json::json!({"exit_code": 7}));
    }

    #[test]
    fn deferred_status_marks_branch_pending() {
        let result = RunResult {
            exit_status: ExitStatus::Signal(9),
            stdout: None,
            stderr: None,
        };
        let mut output = tempfile::tempfile().unwrap();

        write_status(&mut output, &result, Some("pending")).unwrap();
        output.rewind().unwrap();

        let value: serde_json::Value = serde_json::from_reader(output).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "state": "pending",
                "exit_code": -1,
                "signal": 9
            })
        );
    }
}
