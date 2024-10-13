use nix::{
    fcntl::{open, OFlag},
    libc::{STDERR_FILENO, STDOUT_FILENO},
    sys::{ptrace, stat::Mode, wait::WaitStatus},
    unistd::{close, dup2, execve, fork, ForkResult, Pid},
};
use std::ffi::CString;

use crate::diag::Result;

pub trait Tracer {
    /// Traces the execution of a binary with the given process ID.
    ///
    /// # Arguments
    ///
    /// * `child` - The process ID of the binary to be traced.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if there is a failure while inspecting the binary.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the tracing is successful.
    fn trace(&self, child: Pid) -> Result<()>;
}

fn tracee(args: &[CString], env: &[CString]) -> Result<()> {
    let null = open("/dev/null", OFlag::O_WRONLY, Mode::empty())?;
    dup2(null, STDERR_FILENO)?;
    dup2(null, STDOUT_FILENO)?;
    close(null)?;

    ptrace::traceme()?;
    execve(&args[0], args, env)?;

    Ok(())
}

/// Runs the binary inspection program using the specified tracer.
///
/// # Arguments
///
/// * `tracer` - The tracer implementation to use for binary inspection.
/// * `args` - The command-line arguments for the binary to be inspected.
/// * `env` - The environment variables for the binary to be inspected.
///
/// # Errors
///
/// Returns an `Err` if there is a failure during the binary inspection.
///
/// # Returns
///
/// Returns `Ok(())` if the binary inspection is successful.
pub fn run<T: Tracer>(tracer: &T, args: &[CString], env: &[CString]) -> Result<()> {
    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => tracer.trace(child),
        ForkResult::Child => tracee(args, env),
    }
}

#[must_use]
pub fn terminated(status: WaitStatus) -> bool {
    match status {
        WaitStatus::Signaled(_, signal, coredump) => {
            let coredump_str = if coredump { " (core dumped)" } else { "" };
            println!("+++ killed by {signal:?}{coredump_str} +++");
            true
        }
        WaitStatus::Exited(_, code) => {
            println!("+++ exited with {code} +++");
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminated_signaled() {
        let status = WaitStatus::Signaled(
            Pid::from_raw(1),
            nix::sys::signal::Signal::SIGKILL,
            false,
        );
        assert!(terminated(status));
    }

    #[test]
    fn test_terminated_other() {
        let status =
            WaitStatus::Stopped(Pid::from_raw(1), nix::sys::signal::Signal::SIGSTOP);
        assert!(!terminated(status));
    }
}
