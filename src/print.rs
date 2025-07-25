use crate::{asm::Instruction, diag::Result};

#[derive(PartialEq)]
pub enum Layout {
    Assembly,
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

pub trait PrintFn = FnMut(&Instruction, &Layout) -> Result<bool>;

pub fn default(instruction: &Instruction, _: &Layout) -> Result<bool> {
    eprintln!("{instruction}");
    Ok(true)
}
