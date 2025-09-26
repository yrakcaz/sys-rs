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

/// Parses command line arguments and returns them as a vector of `CString`.
///
/// # Arguments
///
/// This function does not take parameters; it reads `env::args()` for the
/// current process command line.
///
/// # Errors
///
/// This function will return an `Err` if no command is provided, if the command is not found,
/// if it is not executable, or if there is an error converting arguments to `CString`.
///
/// # Returns
///
/// Returns a `Result` containing a vector of `CString` representing the command line arguments, or an `Err` if there was an error.
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
        find_executable_in_path(&cmd).ok_or_else(|| Error::from(Errno::ENOENT))?
    };

    args.insert(0, CString::new(executable_path).map_err(Error::from)?);
    Ok(args)
}

/// Retrieves environment variables and returns them as a vector of `CString`.
///
/// # Arguments
///
/// This function does not take parameters; it reads the current process environment.
///
/// # Errors
///
/// This function will return an `Err` if there is an error converting environment variables to `CString`.
///
/// # Returns
///
/// Returns a vector of `CString` representing the environment variables.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_executable() {
        assert!(is_executable(Path::new("/bin/ls")));
        assert!(!is_executable(Path::new("/bin/nonexistent")));
    }

    #[test]
    fn test_find_executable_in_path() {
        assert!(find_executable_in_path("ls").is_some());
        assert!(find_executable_in_path("nonexistent").is_none());
    }

    #[test]
    fn test_env() {
        env::set_var("TEST_ENV_VAR", "test_value");

        let result = env();
        assert!(result.is_ok());
        let cstrings = result.expect("Failed to get environment variables");
        let env_var = CString::new("TEST_ENV_VAR=test_value")
            .expect("Failed to create CString");
        assert!(cstrings.contains(&env_var));

        env::remove_var("TEST_ENV_VAR");
    }
}
