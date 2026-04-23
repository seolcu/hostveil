use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_ADAPTER_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub struct CommandOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub enum CommandError {
    Io(io::Error),
    TimedOut(Duration),
}

impl CommandError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::NotFound)
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Io(error) => error.to_string(),
            Self::TimedOut(timeout) => crate::i18n::tr_adapter_command_timed_out(timeout.as_secs()),
        }
    }
}

pub fn run_with_default_timeout(command: Command) -> Result<CommandOutput, CommandError> {
    run_with_timeout(command, DEFAULT_ADAPTER_TIMEOUT)
}

pub fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<CommandOutput, CommandError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_timeout_process_group(&mut command);

    let mut child = command.spawn().map_err(CommandError::Io)?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdout_handle = thread::spawn(move || read_pipe(stdout));
    let stderr_handle = thread::spawn(move || read_pipe(stderr));
    let start = Instant::now();

    loop {
        match child.try_wait().map_err(CommandError::Io)? {
            Some(status) => {
                let stdout = stdout_handle.join().unwrap_or_default();
                let stderr = stderr_handle.join().unwrap_or_default();
                return Ok(CommandOutput {
                    status,
                    stdout,
                    stderr,
                });
            }
            None if start.elapsed() >= timeout => {
                terminate_child(&mut child);
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(CommandError::TimedOut(timeout));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[cfg(unix)]
fn configure_timeout_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_timeout_process_group(_command: &mut Command) {}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        kill_process_group(child.id());
    }

    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn kill_process_group(child_id: u32) {
    const SIGKILL: i32 = 9;

    let Ok(pgid) = i32::try_from(child_id) else {
        return;
    };

    unsafe {
        let _ = kill(-pgid, SIGKILL);
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

fn read_pipe<R: Read>(pipe: Option<R>) -> Vec<u8> {
    let Some(mut pipe) = pipe else {
        return Vec::new();
    };

    let mut output = Vec::new();
    let _ = pipe.read_to_end(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::{CommandError, run_with_timeout};

    #[test]
    fn command_timeout_kills_and_returns_detail() {
        rust_i18n::set_locale("en");

        let started = Instant::now();
        let error = run_with_timeout(
            {
                let mut command = Command::new("sh");
                command.args(["-c", "sleep 2"]);
                command
            },
            Duration::from_millis(50),
        )
        .expect_err("sleep command should time out");

        assert!(matches!(error, CommandError::TimedOut(_)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(error.detail().contains("timed out after"));
    }
}
