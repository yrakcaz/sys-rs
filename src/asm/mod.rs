use capstone::prelude::*;
use nix::errno::Errno;

use crate::diag::{Error, Result};

pub mod instruction;

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
    ) -> Result<instruction::Wrapper> {
        let instructions = self.capstone.disasm_count(opcode, addr, 1)?;
        Ok(instruction::Wrapper::new(
            instructions
                .iter()
                .next()
                .ok_or_else(|| Error::from(Errno::ENOEXEC))?,
        ))
    }
}
