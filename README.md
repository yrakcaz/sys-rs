[![CI](https://github.com/yrakcaz/sys-rs/actions/workflows/rust_ci.yml/badge.svg)](https://github.com/yrakcaz/sys-rs/actions/workflows/rust_ci.yml)
[![Crates.io](https://img.shields.io/crates/v/sys-rs)](https://crates.io/crates/sys-rs)
[![Documentation](https://img.shields.io/badge/docs-sys--rs-purple)](https://docs.rs/sys-rs)
[![MIT License](https://img.shields.io/github/license/yrakcaz/sys-rs?color=blue)](./LICENSE)

# sys-rs

A collection of Linux system tools reimplemented in Rust — tracing system calls,
inspecting code coverage, resolving debug symbols, and interactive debugging.
Built on `ptrace` and DWARF, targeting x86\_64 Linux with nightly Rust.

## Requirements

- **Rust nightly** — this crate uses `#![feature(trait_alias)]` and will not compile
  on stable
- **Linux x86\_64** — ptrace support is Linux-only; DWARF support is limited to
  x86\_64 and versions 2, 3, 4
- **System dependencies** — install before building:
  ```
  apt install libunwind-dev libclang-dev llvm-dev
  ```

## install

```
cargo install sys-rs
```

This installs all binaries (`strace-rs`, `gcov-rs`, `addr2line-rs`, `sscov-rs`,
`dbg-rs`) to `~/.cargo/bin`.

## build

* `cargo build` for debug mode
* `cargo build --release` for release mode

## strace-rs

This works the same way as Linux's `strace` command and can be used to trace
the system calls invoked by a process as well as the signals it received.

Usage: `strace-rs command [args]`

## sscov-rs

This is a Super Simple Coverage tool that displays all the addresses covered
by the instruction pointer during the execution of a binary, as well as the
associated disassembled instructions.

Usage: `sscov-rs command [args]`

## addr2line-rs

This tool displays all the lines of code corresponding to the addresses covered
by the instruction pointer during the execution of a binary.
The binary needs to be compiled with DWARF debug symbols.

Usage: `addr2line-rs command [args]`

## gcov-rs

This tool leverages addr2line to generate a .cov file per source file that maps
each line of the source file to its coverage count.
This works only if the binary passed as parameter has been compiled with DWARF debug
symbols. If not, gcov-rs will simply behave the same as sscov-rs.

Usage: `gcov-rs command [args]`

## dbg-rs

This is a simple debugger tool that lets you set breakpoints, step through code, and
inspect the state of a process while executing a binary. It provides essential
debugging features in both source and assembly modes.

Usage: `dbg-rs command [args]`

## Library API

The `sys_rs` library crate is an internal implementation detail of the binaries
above. It is published as part of this crate for contributor convenience but is
**not subject to semver guarantees** and is not designed for use as a dependency.
