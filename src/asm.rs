use capstone::{prelude::*, Insn};
use nix::errno::Errno;
use std::fmt;

use crate::diag::{Error, Result};

pub struct Instruction {
    addr: u64,
    mnemonic: String,
    operands: String,
}

impl Instruction {
    #[must_use]
    pub fn new(insn: &Insn) -> Self {
        Self {
            addr: insn.address(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
        }
    }

    #[must_use]
    pub fn addr(&self) -> u64 {
        self.addr
    }

    #[must_use]
    pub fn is_call(&self) -> bool {
        self.mnemonic.contains("call")
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}: {}\t{}", self.addr, self.mnemonic, self.operands)
    }
}
pub struct Parser {
    capstone: Capstone,
}

impl Parser {
    /// Creates a new `Parser` instance.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if there is a failure to build Capstone.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Parser` instance if successful.
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

    /// Retrieves the disassembled instruction from the given opcode and address.
    ///
    /// # Arguments
    ///
    /// * `opcode` - The opcode bytes of the instruction.
    /// * `addr` - The address of the instruction.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if there is a failure to disassemble the instruction.
    ///
    /// # Returns
    ///
    /// The disassembled instruction as a `Result` containing an `Instruction` if successful.
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
}
