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
    /// # Errors
    ///
    /// Will return `Err` upon any failure to build Capstone.
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

    /// # Errors
    ///
    /// Will return `Err` upon any failure to disassemble instruction.
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
