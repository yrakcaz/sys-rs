use core::fmt;
use nix::errno::Errno;

use crate::{
    asm::Parser,
    diag::{Error, Result},
};

/// The expected parameter type for a command argument.
///
/// This enum is used by the command registry to describe what kind of value
/// a specific command parameter expects. It is primarily used to parse and
/// validate user input when dispatching commands.
pub enum Type {
    /// A numeric address in hexadecimal form (e.g. `0x400123`).
    Address,
    /// A formatting specifier: one of `d`, `x`, `i` or `s`.
    Format,
    /// A numeric identifier (used for breakpoint ids, etc.).
    Id,
    /// A numeric size value.
    Size,
    /// A plain string value.
    String,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Address => write!(f, "<address>"),
            Type::Format => write!(f, "[d|x|i|s]"),
            Type::Id => write!(f, "<id>"),
            Type::Size => write!(f, "<size>"),
            Type::String => write!(f, "<string>"),
        }
    }
}

#[derive(Clone)]
/// How to format bytes when examining memory.
///
/// - `Decimal` prints bytes as decimal numbers.
/// - `Hexadecimal` prints bytes in hexadecimal.
/// - `Instruction` interprets the buffer as machine code and disassembles it.
/// - `String` treats the buffer as UTF-8 and prints the string.
pub enum Format {
    /// Print each byte as decimal.
    Decimal,
    /// Print each byte as hexadecimal.
    Hexadecimal,
    /// Disassemble the buffer into instructions and print them.
    Instruction,
    /// Print the buffer as a UTF-8 string.
    String,
}

impl Format {
    /// Format and print `buf` according to this `Format`.
    ///
    /// # Arguments
    ///
    /// * `buf` - The byte buffer to format.
    /// * `addr` - Base address to use when disassembling instructions (only
    ///   used for `Format::Instruction`).
    ///
    /// # Errors
    ///
    /// Returns an error if instruction disassembly is requested and the
    /// underlying parser fails.
    pub fn bytes(&self, buf: &[u8], addr: u64) -> Result<()> {
        match self {
            Format::Decimal | Format::Hexadecimal => {
                for byte in buf {
                    match self {
                        Format::Decimal => print!("{byte} "),
                        Format::Hexadecimal => print!("{byte:x} "),
                        _ => unreachable!(),
                    }
                }
                println!();
            }
            Format::Instruction => {
                let parser = Parser::new()?;
                let instructions = parser.get_all_instructions_from(buf, addr)?;
                for instruction in instructions {
                    println!("{instruction}");
                }
            }
            Format::String => println!("{}", String::from_utf8_lossy(buf)),
        }

        Ok(())
    }
}

impl TryFrom<char> for Format {
    type Error = Error;

    fn try_from(c: char) -> Result<Self> {
        match c {
            'd' => Ok(Format::Decimal),
            'x' => Ok(Format::Hexadecimal),
            'i' => Ok(Format::Instruction),
            's' => Ok(Format::String),
            _ => Err(Error::from(Errno::EINVAL)),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Decimal => write!(f, "d"),
            Format::Hexadecimal => write!(f, "x"),
            Format::Instruction => write!(f, "i"),
            Format::String => write!(f, "s"),
        }
    }
}

/// A parsed command argument value.
///
/// Instances of `Value` represent concrete arguments that were parsed from
/// user input according to the expected `Type` for a command parameter.
pub enum Value<'a> {
    /// Parsed address value.
    Address(u64),
    /// A format specifier value.
    Format(Format),
    /// Numeric identifier.
    Id(u64),
    /// Numeric size.
    Size(u64),
    /// A borrowed string slice.
    String(&'a str),
}

impl<'a> Value<'a> {
    /// Parse a parameter string into a typed `Value` according to `param_type`.
    ///
    /// # Arguments
    ///
    /// * `param_type` - The expected `Type` describing how to parse `param`.
    /// * `param` - The raw string slice containing the parameter to parse.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the parameter cannot be parsed according to
    /// `param_type` (for example an invalid hex address or non-numeric id).
    pub fn new(param_type: &Type, param: &'a str) -> Result<Self> {
        match param_type {
            Type::Address => Self::address(param),
            Type::Format => Self::format(param),
            Type::Id => Self::id(param),
            Type::Size => Self::size(param),
            Type::String => Ok(Self::string(param)),
        }
    }

    fn address(param: &str) -> Result<Self> {
        param
            .strip_prefix("0x")
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .map(Value::Address)
            .ok_or_else(|| Error::from(Errno::EINVAL))
    }

    fn format(param: &str) -> Result<Self> {
        let format = Format::try_from(
            param.chars().next().ok_or(Error::from(Errno::EINVAL))?,
        )?;
        Ok(Value::Format(format))
    }

    fn id(param: &str) -> Result<Self> {
        param
            .parse::<u64>()
            .map(Value::Id)
            .map_err(|_| Error::from(Errno::EINVAL))
    }

    fn size(param: &str) -> Result<Self> {
        param
            .parse::<u64>()
            .map(Value::Size)
            .map_err(|_| Error::from(Errno::EINVAL))
    }

    fn string(param: &'a str) -> Self {
        Value::String(param)
    }
}

impl fmt::Display for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Address(addr) => write!(f, "{addr:#x}"),
            Value::Format(fmt) => write!(f, "{fmt}"),
            Value::Id(id) => write!(f, "{id}"),
            Value::Size(size) => write!(f, "{size}"),
            Value::String(s) => write!(f, "{s}"),
        }
    }
}

/// Helpers to extend a parsed `Value` path with additional string arguments.
///
/// This trait is used by the command dispatch code to build a `Vec<Value>`
/// representing the command path plus the user provided arguments. For
/// example, it allows turning `[]` into `[Value::String("help")]` or to
/// append further tokens.
pub trait Extend<'a> {
    /// Extend the current slice of parsed `Value`s with additional string
    /// arguments and return a new `Vec<Value>`.
    ///
    /// This is used by the command dispatch code to create a concrete
    /// argument vector that contains the existing parsed values followed by
    /// the provided `first` argument and any `rest` arguments. The returned
    /// vector contains cloned/copy variants of the original `Value`s.
    ///
    /// # Arguments
    ///
    /// * `self` - The slice of already-parsed `Value` arguments to extend.
    /// * `first` - The first additional argument to append (becomes a
    ///   `Value::String`).
    /// * `rest` - Remaining additional arguments to append (each becomes a
    ///   `Value::String`).
    ///
    /// # Returns
    ///
    /// A newly allocated `Vec<Value<'a>>` containing the original values (as
    /// copies) followed by `first` and the elements of `rest` converted to
    /// `Value::String`.
    fn extend(&self, first: &'a str, rest: &'a [&'a str]) -> Vec<Value<'a>>;
}

impl<'a> Extend<'a> for [Value<'a>] {
    fn extend(&self, first: &'a str, rest: &'a [&'a str]) -> Vec<Value<'a>> {
        let mut out = Vec::with_capacity(self.len() + 1 + rest.len());
        for v in self {
            out.push(match v {
                Value::Address(addr) => Value::Address(*addr),
                Value::Format(fmt) => Value::Format(fmt.clone()),
                Value::Id(id) => Value::Id(*id),
                Value::Size(size) => Value::Size(*size),
                Value::String(s) => Value::String(s),
            });
        }

        out.push(Value::String(first));
        for &s in rest {
            out.push(Value::String(s));
        }

        out
    }
}

/// Join a slice of `Value` into a single `String` using `sep` as separator.
///
/// This is a convenience used by handlers when composing user-visible
/// messages from an array of previously parsed `Value` arguments.
pub trait Join {
    /// Join the display representation of `self` using `sep`.
    ///
    /// # Arguments
    ///
    /// * `self` - The slice of `Value` items to join.
    /// * `sep` - Separator string inserted between each item's display
    ///   representation.
    ///
    /// # Returns
    ///
    /// A `String` containing each element's `Display` output separated by
    /// `sep`.
    fn join(&self, sep: &str) -> String;
}

impl Join for [Value<'_>] {
    fn join(&self, sep: &str) -> String {
        self.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(sep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_ok() {
        let v = Value::new(&Type::Address, "0x1000").expect("parse address");
        match v {
            Value::Address(a) => assert_eq!(a, 0x1000),
            _ => panic!("expected Address variant"),
        }
    }

    #[test]
    fn test_parse_id_err() {
        let r = Value::new(&Type::Id, "not-a-number");
        assert!(r.is_err());
    }

    #[test]
    fn test_extend_and_join() {
        let base: &[Value] = &[];
        let out = base.extend("help", &["me", "now"]);
        assert_eq!(out.len(), 3);
        assert_eq!(out.join(" "), "help me now");
    }

    #[test]
    fn test_format_try_from_ok() {
        let f = Format::try_from('d').expect("format parse");
        assert!(matches!(f, Format::Decimal));
    }
}
