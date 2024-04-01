use capstone::Insn;
use std::fmt;

pub struct Wrapper {
    addr: u64,
    mnemonic: String,
    operands: String,
}

impl Wrapper {
    #[must_use]
    pub fn new(insn: &Insn) -> Self {
        Self {
            addr: insn.address(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            operands: insn.op_str().unwrap_or("").to_string(),
        }
    }

    #[must_use]
    pub fn is_call(&self) -> bool {
        self.mnemonic.contains("call")
    }
}

impl fmt::Display for Wrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}: {}\t{}", self.addr, self.mnemonic, self.operands)
    }
}
