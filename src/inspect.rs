use nix::{
    fcntl::{open, OFlag},
    libc::{STDERR_FILENO, STDOUT_FILENO},
    sys::{ptrace, stat::Mode},
    unistd::{close, dup2, execve, fork, ForkResult, Pid},
};
use std::ffi::CString;

use crate::diag::Result;

pub trait Tracer {
    /// # Errors
    ///
    /// Should return `Err` upon failure while inspecting a binary.
    fn trace(child: Pid) -> Result<()>;
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

/// # Errors
///
/// Will return `Err` upon any failure in the program as it is the entry point for
/// binary inspection.
pub fn run<T: Tracer>(args: &[CString], env: &[CString]) -> Result<()> {
    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => T::trace(child),
        ForkResult::Child => tracee(args, env),
    }
}
