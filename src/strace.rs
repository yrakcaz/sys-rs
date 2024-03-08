extern crate nix;

// FIXME is there a way to make all the nix use look cleaner?
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execve, fork, ForkResult};
use std::env;
use std::ffi::CString;

type SysResult<T> = Result<T, Errno>;

fn get_args() -> SysResult<Vec<CString>> {
    let args: Vec<CString> = env::args()
        .skip(1)
        .map(|arg| CString::new(arg).expect("Failed to convert argument to CString"))
        .collect();

    if args.is_empty() {
        eprintln!("Usage: strace <command> <params...>");
        return Err(Errno::EINVAL);
    }

    Ok(args)
}

fn get_env() -> SysResult<Vec<CString>> {
    let env: Vec<CString> = env::vars_os()
        .map(|(key, value)| {
            let mut env_str = key.into_string().expect("Invalid env var key");
            env_str.push('=');
            env_str.push_str(&value.into_string().expect("Invalid env var value"));
            CString::new(env_str).expect("Failed to convert env var to CString")
        }).collect();

    Ok(env)
}

enum SyscallState {
    Enter,
    Exit,
}

fn do_fork_exec(args: &Vec<CString>, env: &Vec<CString>) -> SysResult<()> {
    match unsafe{ fork() }? {
        ForkResult::Parent { child, .. } => {
            waitpid(child, None)?;
            let mut syscall_state = SyscallState::Enter;
            loop {
                ptrace::syscall(child, None)?;
                if let WaitStatus::Exited(_, _) = waitpid(child, None)? {
                    break;
                }

                let regs = ptrace::getregs(child)?;
                if let SyscallState::Enter = syscall_state {
                    println!("syscall={}", regs.orig_rax);
                    // FIXME we could also inspect args here
                    syscall_state = SyscallState::Exit;
                } else {
                    println!("retval={}", regs.rax);
                    syscall_state = SyscallState::Enter;
                }
            }
        }
        ForkResult::Child => {
            ptrace::traceme()?;
            execve(&args[0], &args, &env)?;
        }
    }

    Ok(())
}

fn do_strace() -> SysResult<()> {
    let args = get_args()?;
    let env = get_env()?;
    do_fork_exec(&args, &env)?;

    Ok(())
}

fn main() -> Result<(), &'static str> {
    if let Err(errno) = do_strace() {
        return Err(errno.desc());
    }

    Ok(())
}
