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
//!
//! # Requirements
//!
//! Requires **nightly Rust** (`#![feature(trait_alias)]`) and targets
//! **Linux x86\_64** only.
//!
//! # Library stability
//!
//! The public API of this library crate is an internal implementation detail
//! of the bundled binaries and is **not subject to semver guarantees**.

/// Disassembly helpers using capstone.
pub mod asm;
/// Software breakpoint installation and management.
pub mod breakpoint;
/// Command registry, dispatch, and REPL tab-completion.
pub mod command;
/// Coverage data collection and source annotation.
pub mod coverage;
/// DWARF debug-info parsing (addr-to-source-line resolution).
pub mod debug;
/// Error and Result types used throughout the crate.
pub mod diag;
/// ptrace-based command handler functions for the debugger REPL.
pub mod handler;
/// Hardware register access via ptrace.
pub mod hwaccess;
/// CLI argument and environment-variable helpers.
pub mod input;
/// Command parameter types and parsed value representation.
pub mod param;
/// Instruction printing callbacks and layout selection.
pub mod print;
/// ELF binary metadata and address-space inspection.
pub mod process;
/// Instruction-level profiling tracer.
pub mod profile;
/// Tracer loop state, execution/mode enums, and progress callback.
pub mod progress;
/// Readline-based REPL runner.
pub mod repl;
/// Syscall metadata, argument formatting, and pretty-printing.
pub mod syscall;
/// Core Tracer trait and fork/exec/ptrace entry-point.
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
