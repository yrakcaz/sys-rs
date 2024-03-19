use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execve, fork, ForkResult, Pid},
};
use std::{
    env,
    ffi::{CString, NulError},
};

mod error;
use error::{SysError, SysResult};

mod syscall;
use syscall::SyscallPrinter;

fn get_args() -> SysResult<Vec<CString>> {
    let args: Result<Vec<CString>, NulError> =
        env::args().skip(1).map(CString::new).collect();

    match args {
        Err(e) => Err(SysError::CString(e)),
        Ok(args) if args.is_empty() => {
            eprintln!("Usage: strace <command> <params...>");
            Err(SysError::InvalidArgument)
        }
        Ok(args) => Ok(args),
    }
}

fn get_env() -> SysResult<Vec<CString>> {
    env::vars_os()
        .map(|(key, val)| {
            let key_str = key.into_string().map_err(|_| SysError::EnvVar)?;
            let val_str = val.into_string().map_err(|_| SysError::EnvVar)?;
            let env_str = format!("{key_str}={val_str}");
            CString::new(env_str).map_err(SysError::CString)
        })
        .collect()
}

fn tracer(child: Pid) -> SysResult<()> {
    let mut syscall_printer = SyscallPrinter::new(child)?;

    waitpid(child, None)?;
    loop {
        ptrace::syscall(child, None)?;
        if let WaitStatus::Exited(_, code) = waitpid(child, None)? {
            println!("program exited with code {code}");
            break;
        }

        let regs = ptrace::getregs(child)?;
        syscall_printer.maybe_print(&regs)?;
    }

    Ok(())
}

fn tracee(args: &[CString], env: &[CString]) -> SysResult<()> {
    ptrace::traceme()?;
    execve(&args[0], args, env)?;

    Ok(())
}

fn do_fork(args: &[CString], env: &[CString]) -> SysResult<()> {
    match unsafe { fork() }? {
        ForkResult::Parent { child, .. } => tracer(child),
        ForkResult::Child => tracee(args, env),
    }
}

fn main() -> SysResult<()> {
    let args = get_args()?;
    let env = get_env()?;

    do_fork(&args, &env)
}
