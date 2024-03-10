#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate maplit;

use std::{env, ffi::CString};

use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execve, fork, ForkResult, Pid},
};

mod error;
use error::{invalid_argument, SysResult};

mod syscall;
use syscall::SyscallData;

fn get_args() -> SysResult<Vec<CString>> {
    let args: Vec<CString> = env::args()
        .skip(1)
        .map(|arg| CString::new(arg).expect("Failed to convert argument to CString"))
        .collect();

    if args.is_empty() {
        eprintln!("Usage: strace <command> <params...>");
        invalid_argument()?;
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
        })
        .collect();

    Ok(env)
}

fn tracer(child: Pid) -> SysResult<()> {
    waitpid(child, None)?;
    let mut syscall_data = SyscallData::new(child);
    loop {
        ptrace::syscall(child, None)?;
        if let WaitStatus::Exited(_, _) = waitpid(child, None)? {
            break;
        }

        let regs = ptrace::getregs(child)?;
        syscall_data.push(regs)?;

        if !syscall_data.complete() {
            continue;
        }

        println!("{}", syscall_data);
        syscall_data = SyscallData::new(child);
    }

    Ok(())
}

fn tracee() -> SysResult<()> {
    let args = get_args()?;
    let env = get_env()?;

    ptrace::traceme()?;
    execve(&args[0], &args, &env)?;

    Ok(())
}

fn do_fork() -> SysResult<()> {
    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => {
            tracer(child)?;
        }
        ForkResult::Child => {
            tracee()?;
        }
    }

    Ok(())
}

fn main() -> Result<(), &'static str> {
    if let Err(errno) = do_fork() {
        Err(errno.desc())?;
    }

    Ok(())
}
