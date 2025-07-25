use nix::{
    sys::{ptrace, wait::WaitStatus},
    unistd::{execve, fork, ForkResult, Pid},
};
use std::ffi::CString;

use crate::diag::Result;

/// A trait for implementing ptrace-based process tracers.
///
/// Types implementing `Tracer` provide the logic to inspect and control a traced
/// process using the `ptrace` API. The primary extension point is the `trace`
/// method, which is invoked with the PID of the child process to be traced. This
/// allows custom tracing logic, such as system call inspection, breakpoint
/// handling, or binary instrumentation.
pub trait Tracer {
    /// Trace the execution of the process identified by `pid`.
    ///
    /// Implementations should drive the ptrace-based inspection loop for the
    /// child `pid` and return the process's numeric exit/status code. This is
    /// the primary extension point used by the library to perform binary
    /// inspection.
    ///
    /// # Arguments
    ///
    /// * `pid` - PID of the traced child process.
    ///
    /// # Errors
    ///
    /// Returns `Err` when any ptrace/wait/IO operation fails while tracing.
    ///
    /// # Returns
    ///
    /// Returns `Ok(exit_code)` where `exit_code` is the traced process's
    /// numeric exit status (or a signal-derived value). On failure an `Err`
    /// value is returned.
    fn trace(&self, pid: Pid) -> Result<i32>;
}

fn tracee(args: &[CString], env: &[CString]) -> Result<i32> {
    ptrace::traceme()?;
    execve(&args[0], args, env)?;

    Ok(0)
}

/// Fork and execute the target program, running `tracer` against the
/// resulting child process.
///
/// This helper forks the current process. The child will exec the provided
/// `args`/`env` and the parent will invoke the supplied `tracer` with the
/// child's PID.
///
/// # Arguments
///
/// * `tracer` - The tracer implementation to use for binary inspection.
/// * `args` - Command-line arguments for the binary to be inspected (the
///   first element is the program path).
/// * `env` - Environment variables for the child process.
///
/// # Errors
///
/// Returns `Err` if the fork fails or if the tracer returns an error while
/// inspecting the child process.
///
/// # Returns
///
/// Returns `Ok(status)` where `status` is the numeric exit/status code
/// produced by the tracer (typically `0` for success). On failure an `Err`
/// is returned.
pub fn run<T: Tracer>(tracer: &T, args: &[CString], env: &[CString]) -> Result<i32> {
    match unsafe { fork() }? {
        ForkResult::Parent { child: pid, .. } => tracer.trace(pid),
        ForkResult::Child => tracee(args, env),
    }
}

#[must_use]
/// Inspect a `WaitStatus` and, if it denotes termination, print a
/// human-readable summary and return the numeric exit or signal code.
///
/// # Arguments
///
/// * `status` - A `WaitStatus` returned from `wait`/`waitpid`.
///
/// # Returns
///
/// Returns `Some(code)` when the status represents a process exit or
/// termination due to a signal. Returns `None` for non-terminating
/// statuses such as `Stopped`.
pub fn terminated(status: WaitStatus) -> Option<i32> {
    match status {
        WaitStatus::Signaled(_, signal, coredump) => {
            let coredump_str = if coredump { " (core dumped)" } else { "" };
            eprintln!("+++ killed by {signal:?}{coredump_str} +++");
            Some(signal as i32)
        }
        WaitStatus::Exited(_, code) => {
            eprintln!("+++ exited with {code} +++");
            Some(code)
        }
        _ => None,
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
        assert!(terminated(status).is_some());
    }

    #[test]
    fn test_terminated_other() {
        let status =
            WaitStatus::Stopped(Pid::from_raw(1), nix::sys::signal::Signal::SIGSTOP);
        assert!(terminated(status).is_none());
    }
}
