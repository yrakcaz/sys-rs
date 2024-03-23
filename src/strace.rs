use libc::PTRACE_SYSCALL_INFO_EXIT;
use nix::{
    fcntl::{open, OFlag},
    libc::{STDERR_FILENO, STDOUT_FILENO},
    sys::{
        ptrace,
        signal::Signal,
        stat::Mode,
        wait::{wait, WaitStatus},
    },
    unistd::{close, dup2, execve, fork, ForkResult, Pid},
};
use std::ffi::CString;

mod diag;
use diag::Result;

mod input;
use input::{args, env};

mod syscall;
use syscall::{info::Entries as SyscallEntries, model::Repr as Syscall};

fn tracer(child: Pid) -> Result<()> {
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

fn tracee(args: &[CString], env: &[CString]) -> Result<()> {
    let null = open("/dev/null", OFlag::O_WRONLY, Mode::empty())?;
    dup2(null, STDERR_FILENO)?;
    dup2(null, STDOUT_FILENO)?;
    close(null)?;

    ptrace::traceme()?;
    execve(&args[0], args, env)?;

    Ok(())
}

fn do_fork(args: &[CString], env: &[CString]) -> Result<()> {
    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => tracer(child),
        ForkResult::Child => tracee(args, env),
    }
}

fn main() -> Result<()> {
    do_fork(&args()?, &env()?)
}
