use libc::PTRACE_SYSCALL_INFO_EXIT;
use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::Pid,
};

use sys_rs::{
    diag::Result,
    input::{args, env},
    syscall, trace,
};

struct Tracer;

impl trace::Tracer for Tracer {
    fn trace(&self, child: Pid) -> Result<()> {
        let syscalls = syscall::info::Entries::new()?;

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
                        println!("{}", syscall::Repr::build(child, &syscalls)?);
                    }
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::PtraceEvent(_, _, event) => {
                    if event == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                        let syscall = syscall::Repr::build(child, &syscalls)?;
                        if syscall.is_exit() {
                            println!("{syscall}");
                        }
                    }
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    println!("{}", syscall::Repr::build(child, &syscalls)?);
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::Stopped(_, signal) => {
                    println!("--- {signal:?} ---");
                    ptrace::cont(child, signal)?;
                }
                _ if trace::terminated(status) => break,
                _ => {}
            }
            status = wait()?;
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    trace::run::<Tracer>(&Tracer, &args()?, &env()?)
}
