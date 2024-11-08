use libc::PTRACE_SYSCALL_INFO_EXIT;
use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::Pid,
};
use std::process::exit;

use sys_rs::{
    diag::Result,
    input::{args, env},
    syscall, trace,
};

struct Tracer;

impl trace::Tracer for Tracer {
    fn trace(&self, child: Pid) -> Result<i32> {
        let ret;
        let syscalls = syscall::Entries::new()?;

        let mut status = wait()?;
        ptrace::setoptions(
            child,
            ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACEEXEC
                | ptrace::Options::PTRACE_O_TRACEEXIT,
        )?;

        loop {
            match status {
                WaitStatus::PtraceSyscall(_) => {
                    if u8::try_from(ptrace::getevent(child)?)?
                        == PTRACE_SYSCALL_INFO_EXIT
                    {
                        eprintln!("{}", syscall::Repr::build(child, &syscalls)?);
                    }
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::PtraceEvent(_, _, event) => {
                    if event == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                        let syscall = syscall::Repr::build(child, &syscalls)?;
                        if syscall.is_exit() {
                            eprintln!("{syscall}");
                        }
                    }
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    eprintln!("{}", syscall::Repr::build(child, &syscalls)?);
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::Stopped(_, signal) => {
                    eprintln!("--- {signal:?} ---");
                    ptrace::cont(child, signal)?;
                }
                _ => {
                    if let Some(code) = trace::terminated(status) {
                        ret = code;
                        break;
                    }
                }
            }
            status = wait()?;
        }

        Ok(ret)
    }
}

fn main() -> Result<()> {
    exit(trace::run::<Tracer>(&Tracer, &args()?, &env()?)?)
}
