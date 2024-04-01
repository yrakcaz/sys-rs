use nix::{
    errno::Errno,
    unistd::{access, AccessFlags},
};
use std::{env, ffi::CString, ffi::NulError, path::Path, result};

use crate::diag::{Error, Result};

fn is_executable(path: &Path) -> bool {
    access(path.to_str().unwrap_or(""), AccessFlags::X_OK).is_ok()
}

fn find_executable_in_path(file_name: &str) -> Option<String> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).find_map(|dir| {
            let full_path = dir.join(file_name);
            if is_executable(&full_path) {
                full_path.to_str().map(String::from)
            } else {
                None
            }
        })
    })
}

/// # Errors
///
/// Will return `Err` if no command is provided, if the command is not found, if it
/// is not executable, or if failing to convert arguments to `CString`.
pub fn args() -> Result<Vec<CString>> {
    let mut args_iter = env::args().skip(1);
    let this = env::args()
        .next()
        .ok_or_else(|| Error::from(Errno::EINVAL))?;
    let cmd = args_iter.next().map_or_else(
        || {
            eprintln!("Usage: {this} command [args]");
            Err(Error::from(Errno::EINVAL))
        },
        Ok,
    )?;

    let mut args: Vec<CString> = args_iter
        .map(CString::new)
        .collect::<result::Result<_, NulError>>()
        .map_err(Error::from)?;

    let executable_path = if is_executable(Path::new(&cmd)) {
        cmd
    } else {
        find_executable_in_path(&cmd).ok_or(Error::from(Errno::ENOENT))?
    };

    args.insert(0, CString::new(executable_path).map_err(Error::from)?);
    Ok(args)
}

/// # Errors
///
/// Will return `Err` if failing to convert environment variables to `CString`.
pub fn env() -> Result<Vec<CString>> {
    env::vars_os()
        .map(|(key, val)| {
            let e = "Error: OsString conversion failed";
            let key_str =
                key.into_string().map_err(|_| Error::from(e.to_string()))?;
            let val_str =
                val.into_string().map_err(|_| Error::from(e.to_string()))?;
            let env_str = format!("{key_str}={val_str}");
            CString::new(env_str).map_err(Error::from)
        })
        .collect()
}
