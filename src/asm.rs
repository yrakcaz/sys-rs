use capstone::{prelude::*, Insn};
use nix::errno::Errno;
use std::fmt;

use crate::diag::{Error, Result};

/// A disassembled instruction with human-friendly fields.
///
/// This type stores the instruction address, mnemonic and operands as strings
/// so callers can format or inspect them without depending on capstone types.
pub struct Instruction {
    address: u64,
    mnemonic: String,
    operands: String,
}

impl Instruction {
    #[must_use]
    /// Create an `Instruction` from a capstone `Insn`.
    ///
    /// Converts a capstone `Insn` into the crate's lightweight `Instruction`
    /// representation by copying the instruction address, mnemonic and
    /// operand string. This allows callers to own and format instruction
    /// data without keeping capstone types around.
    ///
    /// # Arguments
    ///
    /// * `insn` - A reference to a capstone `Insn` to convert.
    ///
    /// # Returns
    ///
    /// An owned `Instruction` containing the address, mnemonic and operands
    /// extracted from `insn`.
    pub fn new(insn: &Insn) -> Self {
        Self {
            address: insn.address(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
        }
    }

    #[must_use]
    /// Return the instruction address.
    ///
    /// # Returns
    ///
    /// The virtual memory address where this instruction is located.
    pub fn address(&self) -> u64 {
        self.address
    }

    #[must_use]
    /// Return true when the mnemonic represents a call instruction.
    ///
    /// # Returns
    ///
    /// `true` when the instruction mnemonic contains the substring
    /// "call" (for example `callq`), otherwise `false`.
    pub fn is_call(&self) -> bool {
        self.mnemonic.contains("call")
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}: {}\t{}",
            self.address, self.mnemonic, self.operands
        )
    }
}

/// A light wrapper around capstone used to disassemble buffers.
pub struct Parser {
    capstone: Capstone,
}

impl Parser {
    /// Create a new instruction `Parser` for the host architecture (`x86_64`).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying capstone builder fails.
    pub fn new() -> Result<Self> {
        Ok(Self {
            capstone: Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Att)
                .detail(true)
                .build()?,
        })
    }

    /// Disassemble a single instruction from `opcode` at address `addr`.
    ///
    /// # Arguments
    ///
    /// * `opcode` - Bytes containing at least one instruction.
    /// * `addr` - Virtual address corresponding to the start of `opcode`.
    ///
    /// # Errors
    ///
    /// Returns an error when disassembly fails or no instruction could be
    /// decoded.
    pub fn get_instruction_from(
        &self,
        opcode: &[u8],
        addr: u64,
    ) -> Result<Instruction> {
        let instructions = self.capstone.disasm_count(opcode, addr, 1)?;
        Ok(Instruction::new(
            instructions
                .iter()
                .next()
                .ok_or_else(|| Error::from(Errno::ENOEXEC))?,
        ))
    }

    /// Disassemble all instructions present in `code`, returning a vector of
    /// `Instruction` instances.
    ///
    /// # Arguments
    ///
    /// * `code` - Buffer containing machine code.
    /// * `addr` - Base virtual address of `code`.
    ///
    /// # Errors
    ///
    /// Returns an error if the disassembly operation fails.
    pub fn get_all_instructions_from(
        &self,
        code: &[u8],
        addr: u64,
    ) -> Result<Vec<Instruction>> {
        let instructions = self.capstone.disasm_all(code, addr)?;
        Ok(instructions.iter().map(Instruction::new).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_get_instruction_from() {
        let parser = Parser::new().expect("Failed to create parser");

        let opcode: [u8; 5] = [0xe8, 0x05, 0x00, 0x00, 0x00];
        let addr: u64 = 0x1000;

        let instruction = parser
            .get_instruction_from(&opcode, addr)
            .expect("Failed to get instruction");

        assert_eq!(instruction.address(), addr);
        assert_eq!(instruction.is_call(), true);
        assert_eq!(instruction.mnemonic, "callq");
        assert_eq!(instruction.operands, "0x100a");
    }

    #[test]
    fn test_instruction_fmt() {
        let inst = Instruction {
            address: 0x1000,
            mnemonic: "mov".into(),
            operands: "rax, rbx".into(),
        };
        let s = format!("{}", inst);
        assert!(s.contains("0x1000"));
        assert!(s.contains("mov"));
        assert!(s.contains("rax, rbx"));
    }
}
