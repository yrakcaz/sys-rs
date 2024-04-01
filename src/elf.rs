use goblin::elf::{Elf, SectionHeader};
use nix::errno::Errno;
use std::{fs::File, io::Read, path::Path};

use crate::diag::{Error, Result};

pub struct Reader {
    buffer: Vec<u8>,
    text_section: SectionHeader,
}

impl Reader {
    /// # Errors
    ///
    /// Will return `Err` upon any failure to read or parse ELF file.
    pub fn build(path: &str) -> Result<Self> {
        let path = Path::new(path);
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer)?;
        let text_section = elf
            .section_headers
            .iter()
            .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"))
            .ok_or(Error::from(Errno::ENODATA))?;

        Ok(Self {
            buffer,
            text_section: text_section.clone(),
        })
    }

    #[must_use]
    pub fn is_in_text_section(&self, rip: u64) -> bool {
        let text_start = self.text_section.sh_addr;
        let text_end = text_start + self.text_section.sh_size;
        rip >= text_start && rip <= text_end
    }

    #[must_use]
    pub fn get_bytes_from_text(&self, addr: u64) -> Option<&[u8]> {
        self.is_in_text_section(addr)
            .then(|| {
                let text_addr = self.text_section.sh_addr;
                let text_offset = self.text_section.sh_offset;
                let index = usize::try_from(addr - text_addr + text_offset).ok()?;
                self.buffer.get(index..index + 16)
            })
            .flatten()
    }
}
