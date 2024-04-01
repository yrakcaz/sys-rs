# sys-rs

I always wanted to re-write some of the GNU/Linux system tools, just for fun.  
I was also looking for a project I could work on to learn Rust.  
Let's kill two birds with one stone :)  

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
