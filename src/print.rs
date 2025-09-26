use crate::{asm::Instruction, diag::Result};

#[derive(PartialEq, Debug)]
/// Controls how instructions are printed.
///
/// `Layout::Assembly` prints raw disassembly. `Layout::Source` indicates
/// the caller prefers source-oriented output (e.g., showing source lines
/// when DWARF info is available).
pub enum Layout {
    /// Print assembly/disassembly.
    Assembly,
    /// Prefer source-level printing when available.
    Source,
}

impl From<bool> for Layout {
    fn from(src_available: bool) -> Self {
        if src_available {
            Self::Source
        } else {
            Self::Assembly
        }
    }
}

/// Type alias for a printing callback used by the tracer/profile code.
///
/// The callback is invoked when the tracer or profiler wants to render an
/// instruction. Implementations receive the current `Instruction` and the
/// active `Layout` and may return an optional string containing the text that
/// was printed.
///
/// # Arguments
///
/// * `instruction` - The instruction to print.
/// * `layout` - The active printing layout (assembly or source-oriented).
///
/// # Returns
///
/// `Ok(Some(String))` when a string was printed and should be recorded,
/// `Ok(None)` when nothing was printed, or `Err` for I/O or lookup errors.
pub trait PrintFn = FnMut(&Instruction, &Layout) -> Result<Option<String>>;

/// Default instruction printer which prints the `Instruction`'s `Display`
/// representation.
///
/// The default printer formats the instruction using its `Display`
/// implementation and writes it to stdout. The printed string is also
/// returned inside `Ok(Some(...))` so callers can record or redisplay it.
///
/// # Arguments
///
/// * `instruction` - The `Instruction` to print.
/// * `_` - The active `Layout` (unused by the default printer).
///
/// # Errors
///
/// Returns an `Err` if writing to stdout or other I/O performed by the
/// underlying platform fails.
///
/// # Returns
///
/// `Ok(Some(String))` containing the printed text on success.
pub fn default(instruction: &Instruction, _: &Layout) -> Result<Option<String>> {
    let ret = format!("{instruction}");
    println!("{ret}");
    Ok(Some(ret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_default_returns_string() {
        let parser = crate::asm::Parser::new().expect("parser new");
        let opcode: [u8; 5] = [0xe8, 0x05, 0x00, 0x00, 0x00];
        let inst = parser
            .get_instruction_from(&opcode, 0x1000)
            .expect("decoding");
        let res = default(&inst, &Layout::Assembly).expect("print default failed");
        assert!(res.is_some());
        let s = res.unwrap();
        assert!(s.contains("call") || s.contains("callq"));
    }
}
