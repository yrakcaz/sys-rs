use core::ffi::c_void;
use nix::{errno::Errno, sys::ptrace, unistd::Pid};
use serde_derive::Deserialize;
use std::{collections::HashMap, fmt};

use crate::{
    diag::{Error, Result},
    hwaccess::Registers,
};

#[derive(Debug, Deserialize, PartialEq)]
/// Representation of a syscall argument or return value type.
///
/// This enum describes how a syscall argument or return value should be
/// interpreted when pretty-printing traced syscalls (signed integer, pointer,
/// string, or unsigned integer).
pub enum Type {
    /// Signed integer value (printed as i64).
    Int,
    /// Pointer value (printed as `NULL` or hex address).
    Ptr,
    /// NUL-terminated string located in the traced process memory.
    Str,
    /// Unsigned integer value.
    Uint,
}

#[derive(Deserialize)]
/// A single syscall argument description.
///
/// `Arg` holds the argument name and its `Type` (how it should be formatted).
/// Instances are deserialized from the `syscall.json` metadata used to
/// pretty-print syscall invocations.
pub struct Arg {
    name: String,
    arg_type: Type,
}

impl Arg {
    #[must_use]
    /// Return the argument name as defined in the syscall metadata.
    ///
    /// # Returns
    ///
    /// A reference to the argument name string.
    pub fn name(&self) -> &String {
        &self.name
    }

    #[must_use]
    /// Return the argument's `Type` which determines how the value is formatted.
    ///
    /// # Returns
    ///
    /// A reference to the `Type` for this argument.
    pub fn arg_type(&self) -> &Type {
        &self.arg_type
    }
}

#[derive(Deserialize)]
/// Metadata describing a single syscall entry.
///
/// Contains the syscall name, return type and an optional vector of
/// `Arg` descriptions for the syscall's parameters. Entries are populated
/// from `syscall.json` and used by `Repr::build` to format syscall output.
pub struct Entry {
    name: String,
    ret_type: Type,
    args: Option<Vec<Arg>>,
}

impl Entry {
    #[must_use]
    /// Return the syscall name (for example "write").
    ///
    /// # Returns
    ///
    /// A reference to the syscall name string.
    pub fn name(&self) -> &String {
        &self.name
    }

    #[must_use]
    /// Return the return `Type` for this syscall.
    ///
    /// # Returns
    ///
    /// A reference to the return `Type` describing how to format the return value.
    pub fn ret_type(&self) -> &Type {
        &self.ret_type
    }

    #[must_use]
    /// Return the optional argument descriptions for this syscall.
    ///
    /// # Returns
    ///
    /// `Some(Vec<Arg>)` when the syscall has parameters, otherwise `None`.
    pub fn args(&self) -> &Option<Vec<Arg>> {
        &self.args
    }
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            ret_type: Type::Int,
            args: None,
        }
    }
}

/// Lookup table for syscall entries indexed by syscall number.
///
/// `Entries` wraps an internal `HashMap<u64, Entry>` populated from the
/// embedded `syscall.json` metadata. Use `Entries::new()` to construct an
/// instance and `Entries::get(id)` to retrieve the corresponding `Entry`.
pub struct Entries {
    map: HashMap<u64, Entry>,
    default: Entry,
}

impl Entries {
    /// Creates a new instance of `Entries`.
    ///
    /// This function reads the contents of the `syscall.json` file and parses it into a `HashMap<u64, Entry>`.
    /// If the parsing fails, an `Err` is returned.
    ///
    /// # Errors
    ///
    /// This function will return an `Err` if it fails to parse the `syscall.json` file.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the newly created `Entries` instance if successful, or an `Err` if parsing fails.
    pub fn new() -> Result<Self> {
        let json = include_str!("data/syscall.json");
        let map = serde_json::from_str(json)?;
        Ok(Self {
            map,
            default: Entry::default(),
        })
    }

    #[must_use]
    /// Lookup the `Entry` for the provided syscall number.
    ///
    /// # Arguments
    ///
    /// * `id` - Syscall number to look up.
    ///
    /// # Returns
    ///
    /// A reference to the matching `Entry` or the default `Entry` when no
    /// entry exists for `id`.
    pub fn get(&self, id: u64) -> &Entry {
        self.map.get(&id).unwrap_or(&self.default)
    }
}

/// Formatted representation of a syscall invocation for printing.
///
/// `Repr` holds the syscall name, a comma-separated argument string and the
/// formatted return value. Construct one with `Repr::build` using the
/// traced process registers and the `Entries` metadata.
pub struct Repr<'a> {
    name: &'a str,
    args: String,
    ret_val: String,
}

fn trace_str(addr: u64, pid: Pid) -> Result<String> {
    let mut ret = String::new();
    let mut offset = 0;
    loop {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let c = char::from(ptrace::read(pid, (addr + offset) as *mut c_void)? as u8);
        if c == '\0' {
            break;
        }
        if c == '\n' {
            ret.push('\\');
            ret.push('n');
            offset += 1;
            continue;
        }
        ret.push(c);
        offset += 1;
    }

    Ok(format!("\"{ret}\""))
}

fn parse_value(type_repr: &Type, val: u64, pid: Pid) -> Result<String> {
    match type_repr {
        #[allow(clippy::cast_possible_wrap)]
        Type::Int => Ok(format!("{}", val as i64)),
        Type::Ptr => {
            let ptr_str = if val == 0x0 {
                "NULL".to_string()
            } else {
                format!("{val:#x}")
            };
            Ok(ptr_str)
        }
        Type::Str => Ok(if val == 0x0 {
            "?".to_string()
        } else {
            trace_str(val, pid)?
        }),
        Type::Uint => Ok(format!("{val}")),
    }
}

impl<'a> Repr<'a> {
    /// Builds a `Repr` struct from the given process ID (`pid`) and a reference to `Entries`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID for which to build the `Repr` struct.
    /// * `infos` - A reference to `Entries` containing the syscall information.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if `ptrace::getregs()` or `ptrace::read()` fails.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the constructed `Repr` struct on success.
    pub fn build(pid: Pid, infos: &'a Entries) -> Result<Self> {
        let regs = Registers::read(pid)?;
        let info = infos.get(regs.orig_rax());
        let name = info.name();

        let reg_vals = regs.function_params();
        let args = if let Some(args) = info.args() {
            let mut results = Vec::new();
            for (i, arg) in args.iter().enumerate() {
                let mut ret = arg.name().to_owned();
                ret.push('=');
                ret.push_str(&parse_value(arg.arg_type(), reg_vals[i], pid)?);
                results.push(ret);
            }
            Ok::<String, Error>(results.join(", "))
        } else {
            Ok(String::new())
        }?;

        #[allow(clippy::cast_possible_wrap)]
        let ret_val = if regs.rax() as i64 == -(Errno::ENOSYS as i64) {
            "?".to_string()
        } else {
            parse_value(info.ret_type(), regs.rax(), pid)?
        };

        Ok(Self {
            name,
            args,
            ret_val,
        })
    }

    #[must_use]
    /// Return true when this `Repr` represents an exit-style syscall.
    ///
    /// # Returns
    ///
    /// `true` when the syscall name contains the substring "exit".
    pub fn is_exit(&self) -> bool {
        self.name.contains("exit")
    }
}

impl fmt::Display for Repr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}) = {}", self.name, self.args, self.ret_val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_default() {
        let entry = Entry::default();
        assert_eq!(entry.name(), "unknown");
        assert_eq!(entry.ret_type(), &Type::Int);
        assert!(entry.args().is_none());
    }

    #[test]
    fn test_entries_new() {
        let entries = Entries::new();
        assert!(entries.is_ok());
    }

    #[test]
    fn test_entries_get() {
        let entries = Entries::new().expect("Failed to create Entries");
        let entry = entries.get(1);
        assert_eq!(entry.name(), "write");
    }

    #[test]
    fn test_arg_methods() {
        let arg = Arg {
            name: "arg1".to_string(),
            arg_type: Type::Int,
        };
        assert_eq!(arg.name(), "arg1");
        assert_eq!(arg.arg_type(), &Type::Int);
    }

    #[test]
    fn test_entry_methods() {
        let entry = Entry {
            name: "test".to_string(),
            ret_type: Type::Uint,
            args: Some(vec![Arg {
                name: "arg1".to_string(),
                arg_type: Type::Str,
            }]),
        };
        assert_eq!(entry.name(), "test");
        assert_eq!(entry.ret_type(), &Type::Uint);
        assert!(entry.args().is_some());
    }

    #[test]
    fn test_parse_value() {
        let pid = Pid::from_raw(1);
        assert_eq!(
            parse_value(&Type::Int, 42, pid).expect("Failed to parse Int value"),
            "42"
        );
        assert_eq!(
            parse_value(&Type::Uint, 42, pid).expect("Failed to parse Uint value"),
            "42"
        );
        assert_eq!(
            parse_value(&Type::Ptr, 0, pid).expect("Failed to parse Ptr value"),
            "NULL"
        );
        assert_eq!(
            parse_value(&Type::Ptr, 42, pid).expect("Failed to parse Ptr value"),
            "0x2a"
        );
        assert_eq!(
            parse_value(&Type::Str, 0, pid).expect("Failed to parse Str value"),
            "?"
        );
    }

    #[test]
    fn test_repr_is_exit() {
        let repr = Repr {
            name: "exit",
            args: String::new(),
            ret_val: String::new(),
        };
        assert!(repr.is_exit());

        let repr = Repr {
            name: "open",
            args: String::new(),
            ret_val: String::new(),
        };
        assert!(!repr.is_exit());
    }

    #[test]
    fn test_repr_display() {
        let repr = Repr {
            name: "open",
            args: "arg1=42".to_string(),
            ret_val: "0".to_string(),
        };
        assert_eq!(format!("{}", repr), "open(arg1=42) = 0");
    }

    #[test]
    fn test_entries_get_unknown() {
        let entries = Entries::new().expect("Failed to create Entries");
        let entry = entries.get(999_999);
        assert_eq!(entry.name(), "unknown");
    }
}
