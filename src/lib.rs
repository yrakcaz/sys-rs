#![allow(clippy::multiple_crate_versions)]
#![feature(trait_alias)]

//! sys-rs — a small ptrace-based binary inspection and tracing toolkit.
//!
//! The crate provides a tracer framework and utilities to inspect running
//! processes: disassembly helpers, breakpoint management, syscall
//! formatting, REPL and progress helpers. The public modules are organized
//! to allow small, targeted tools (for example the `addr2line` and `strace`
//! binaries in `bin/`) to reuse the core tracing logic.
//!
//! See the `bin/` examples in the repository for small command-line front-ends.

pub mod asm;
pub mod breakpoint;
pub mod command;
pub mod coverage;
pub mod debug;
pub mod diag;
pub mod handler;
pub mod hwaccess;
pub mod input;
pub mod param;
pub mod print;
pub mod process;
pub mod profile;
pub mod progress;
pub mod repl;
pub mod syscall;
pub mod trace;

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::Pid;

    #[test]
    fn test_crate_smoke() {
        let _ = asm::Parser::new().expect("parser");
        let _ = command::Registry::default();
        let _ = progress::State::new(Pid::from_raw(1), None);
        let _ = breakpoint::Manager::new(Pid::from_raw(1));
    }
}
