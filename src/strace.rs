use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execve, fork, ForkResult, Pid},
};
use std::{env, ffi::CString};

mod error;
use error::{invalid_argument, SysResult};

mod syscall;
use syscall::SyscallPrinter;

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
    let mut syscall_printer = SyscallPrinter::new(child);

    waitpid(child, None)?;
    loop {
        ptrace::syscall(child, None)?;
        if let WaitStatus::Exited(_, code) = waitpid(child, None)? {
            println!("program exited with code {}", code);
            break;
        }

        let regs = ptrace::getregs(child)?;
        syscall_printer.maybe_print(&regs)?;
    }

    Ok(())
}

fn tracee(args: &Vec<CString>) -> SysResult<()> {
    let env = get_env()?;

    ptrace::traceme()?;
    execve(&args[0], args, &env)?;

    Ok(())
}

fn do_fork() -> SysResult<()> {
    let args = get_args()?;

    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => {
            tracer(child)?;
        }
        ForkResult::Child => {
            tracee(&args)?;
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
