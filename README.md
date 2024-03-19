# sys-rs

I always wanted to re-write some of the GNU/Linux system tools, just for fun.  
I was also looking for a project I could work on to learn Rust.  
Let's kill two birds with one stone :)  

## build

* `cargo build` for debug mode  
* `cargo build --release` for release mode  

## strace-rs

This works the same way as Linux's `strace` command and can be used to trace
the system calls invoked by a process.  

Usage: strace <command> <params...>  
