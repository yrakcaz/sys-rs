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
    inspect,
    syscall::{info::Entries as SyscallEntries, model::Repr as Syscall},
};

struct Tracer;

impl inspect::Tracer for Tracer {
    fn trace(child: Pid) -> Result<()> {
        let syscall_entries = SyscallEntries::new()?;

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
                        println!("{}", Syscall::build(child, &syscall_entries)?);
                    }
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::PtraceEvent(_, _, event) => {
                    if event == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
                        let syscall = Syscall::build(child, &syscall_entries)?;
                        if syscall.is_exit() {
                            println!("{syscall}");
                        }
                    }
                    ptrace::syscall(child, None)?;
                }
                WaitStatus::Stopped(_, signal) => {
                    if signal == Signal::SIGTRAP {
                        println!("{}", Syscall::build(child, &syscall_entries)?);
                        ptrace::syscall(child, None)?;
                    } else {
                        println!("--- {signal:?} ---");
                        ptrace::cont(child, signal)?;
                    }
                }
                WaitStatus::Signaled(_, signal, coredump) => {
                    let coredump_str = if coredump { " (core dumped)" } else { "" };
                    println!("+++ killed by {signal:?}{coredump_str} +++");
                    break;
                }
                WaitStatus::Exited(_, code) => {
                    println!("+++ exited with {code} +++");
                    break;
                }
                _ => {}
            }
            status = wait()?;
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    inspect::run::<Tracer>(&args()?, &env()?)
}
