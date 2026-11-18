use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const PROCESS_DEADLINE: Duration = Duration::from_secs(10);

/// The guard holds the actual Child; no PID searches or process-group killing.
pub struct OwnedChild {
    pub(crate) child: Child,
    reaped: bool,
}

impl OwnedChild {
    pub fn spawn(command: &mut Command) -> Self {
        Self {
            child: command.spawn().expect("spawn owned test child"),
            reaped: false,
        }
    }

    pub fn sleep() -> Self {
        Self::spawn(
            Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        )
    }

    pub fn assert_running(&mut self) {
        assert!(
            self.child
                .try_wait()
                .expect("inspect owned child")
                .is_none(),
            "owned child exited unexpectedly"
        );
    }

    pub fn kill_and_wait(&mut self) -> ExitStatus {
        assert!(!self.reaped, "cannot kill an already reaped child");
        self.child.kill().expect("SIGKILL owned test child");
        self.wait_for_exit()
    }

    pub fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + PROCESS_DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().expect("inspect owned child exit") {
                self.reaped = true;
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "owned child did not exit in time"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let result = match self.child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => self
                .child
                .kill()
                .and_then(|()| self.child.wait().map(|_| ())),
            Err(error) => Err(error),
        };
        if !thread::panicking() {
            result.expect("terminate and reap only the owned test child");
        }
    }
}
