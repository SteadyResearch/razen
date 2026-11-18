//! Host-only native argv capture. No shell, worker threads, or detached readers.
use std::ffi::OsStr;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};

#[derive(Clone, Copy, Debug)]
pub struct CommandLimits {
    pub stdin_bytes: usize,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub struct CommandStatusOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

fn unavailable() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Native command I/O or process operation failed",
    )
}

fn channel() -> ProofResult<(UnixStream, Stdio)> {
    let (host, child) = UnixStream::pair().map_err(|_| unavailable())?;
    host.set_nonblocking(true).map_err(|_| unavailable())?;
    Ok((host, Stdio::from(OwnedFd::from(child))))
}

pub(crate) struct OwnedProcess {
    child: Child,
    group: Pid,
    reaped: bool,
}

impl OwnedProcess {
    pub(crate) fn spawn(mut command: Command) -> ProofResult<Self> {
        let child = command
            .process_group(0)
            .spawn()
            .map_err(|_| unavailable())?;
        // Command owns its configured child-side Stdio even after spawn.
        // Drop it before observing EOF on any of the host-side streams.
        drop(command);
        let group = Pid::from_raw(child.id() as i32).ok_or_else(unavailable)?;
        Ok(Self {
            child,
            group,
            reaped: false,
        })
    }

    pub(crate) fn exited(&self) -> ProofResult<bool> {
        waitid(
            WaitId::Pid(self.group),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
        )
        .map(|status| status.is_some())
        .map_err(|_| unavailable())
    }

    pub(crate) fn finish(
        &mut self,
        terminate_group: bool,
    ) -> ProofResult<std::process::ExitStatus> {
        // The leader has not been reaped, so its PID cannot be reused for an
        // unrelated group between observation, signalling, and wait.
        if terminate_group {
            match kill_process_group(self.group, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(_) => {
                    let _ = self.child.kill();
                    self.child.wait().map_err(|_| {
                        ProofError::new(
                            ErrorCode::ProviderUnavailable,
                            "Native command cleanup reaping failed",
                        )
                    })?;
                    self.reaped = true;
                    return Err(ProofError::new(
                        ErrorCode::ProviderUnavailable,
                        "Native command process group termination failed",
                    ));
                }
            }
        }
        let status = self.child.wait().map_err(|_| {
            ProofError::new(
                ErrorCode::ProviderUnavailable,
                "Native command could not be reaped",
            )
        })?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish(true);
        }
    }
}

fn read_chunk(stream: &mut UnixStream, bytes: &mut Vec<u8>, cap: usize) -> ProofResult<bool> {
    let mut buffer = [0; 8192];
    match stream.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if count > cap.saturating_sub(bytes.len()) {
                return Err(ProofError::new(
                    ErrorCode::OutputInvalid,
                    "Native command output exceeded its byte limit",
                ));
            }
            bytes.extend_from_slice(&buffer[..count]);
            Ok(false)
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            Ok(false)
        }
        Err(_) => Err(ProofError::new(
            ErrorCode::ProviderUnavailable,
            "Native command stream read failed",
        )),
    }
}

pub fn capture(
    program: &Path,
    args: &[&OsStr],
    stdin: Option<&[u8]>,
    limits: CommandLimits,
) -> ProofResult<CommandOutput> {
    let output = capture_status(program, args, stdin, limits)?;
    if output.exit_code != 0 {
        return Err(ProofError::new(
            ErrorCode::ProviderUnavailable,
            "Native command exited unsuccessfully",
        ));
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

pub fn capture_status(
    program: &Path,
    args: &[&OsStr],
    stdin: Option<&[u8]>,
    limits: CommandLimits,
) -> ProofResult<CommandStatusOutput> {
    const MAX_BYTES: usize = 16 * 1024 * 1024;
    let input = stdin.unwrap_or_default();
    if !program.is_absolute()
        || limits.timeout.is_zero()
        || limits.timeout > Duration::from_secs(60)
        || input.len() > limits.stdin_bytes
        || limits.stdin_bytes > MAX_BYTES
        || limits.stdout_bytes > MAX_BYTES
        || limits.stderr_bytes > MAX_BYTES
    {
        return Err(ProofError::new(
            ErrorCode::InvalidInput,
            "Native command requires finite byte limits, deadline, and absolute executable",
        ));
    }
    let deadline = Instant::now()
        .checked_add(limits.timeout)
        .ok_or_else(unavailable)?;
    let (writer, child_stdin) = channel()?;
    let mut writer = Some(writer);
    let (mut reader, child_stdout) = channel()?;
    let (mut errors, child_stderr) = channel()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(child_stdin)
        .stdout(child_stdout)
        .stderr(child_stderr);
    let mut owned = OwnedProcess::spawn(command)?;
    let mut output = CommandOutput {
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let mut sent = 0;
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    loop {
        if Instant::now() >= deadline {
            return Err(ProofError::new(
                ErrorCode::Timeout,
                "Native command deadline exceeded",
            ));
        }
        if let Some(stream) = writer.as_mut() {
            if sent < input.len() {
                let end = input.len().min(sent + 8192);
                match stream.write(&input[sent..end]) {
                    Ok(0) => return Err(unavailable()),
                    Ok(count) => sent += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        return Err(ProofError::new(
                            ErrorCode::ProviderUnavailable,
                            "Native command stdin write failed",
                        ));
                    }
                }
            }
            if sent == input.len() {
                // Closing the owned endpoint delivers EOF even if the peer has
                // already exited; shutdown can instead fail with ENOTCONN.
                drop(writer.take());
            }
        }
        if !stdout_closed {
            stdout_closed = read_chunk(&mut reader, &mut output.stdout, limits.stdout_bytes)?;
        }
        if !stderr_closed {
            stderr_closed = read_chunk(&mut errors, &mut output.stderr, limits.stderr_bytes)?;
        }
        if stdout_closed && stderr_closed && owned.exited()? {
            // Exit and both EOFs are observed. Reap, do not signal an
            // already-completed native command.
            let status = owned.finish(false)?;
            let exit_code = status.code().ok_or_else(|| {
                ProofError::new(
                    ErrorCode::ProviderUnavailable,
                    "Native command terminated without a normal exit status",
                )
            })?;
            if writer.is_some() {
                return Err(ProofError::new(
                    ErrorCode::ProviderUnavailable,
                    "Native command exited before consuming its input",
                ));
            }
            return Ok(CommandStatusOutput {
                stdout: output.stdout,
                stderr: output.stderr,
                exit_code,
            });
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_nonzero_exit_retains_real_bounded_stdout_stderr_and_strict_capture_still_fails() {
        let limits = CommandLimits {
            stdin_bytes: 0,
            stdout_bytes: 16,
            stderr_bytes: 1024,
            timeout: Duration::from_secs(2),
        };
        let args = [OsStr::new("%d"), OsStr::new("public-not-a-number")];
        let observed = capture_status(Path::new("/usr/bin/printf"), &args, None, limits).unwrap();
        assert_eq!(observed.exit_code, 1);
        assert_eq!(observed.stdout, b"0");
        assert!(
            observed
                .stderr
                .windows(b"public-not-a-number".len())
                .any(|bytes| bytes == b"public-not-a-number")
        );
        let error = capture(Path::new("/usr/bin/printf"), &args, None, limits).unwrap_err();
        assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    }
}
