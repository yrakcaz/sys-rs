use goblin::elf::{Elf, SectionHeader};
use nix::errno::Errno;
use std::{collections::HashMap, fs::File, io::Read, path::Path};

use crate::diag::{Error, Result};

const EI_DATA: usize = 5;
const MAX_OPCODE_SIZE: u64 = 16;

pub struct Reader {
    buffer: Vec<u8>,
    endianness: u8,
    section: HashMap<String, SectionHeader>,
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
        let endianness = elf.header.e_ident[EI_DATA];

        let section: HashMap<String, SectionHeader> = elf
            .section_headers
            .iter()
            .filter_map(|header| {
                elf.shdr_strtab
                    .get_at(header.sh_name)
                    .map(|name| (name.to_string(), header.clone()))
            })
            .collect();
        section.get(".text").ok_or(Error::from(Errno::ENODATA))?;

        Ok(Self {
            buffer,
            endianness,
            section,
        })
    }

    pub fn endianness(&self) -> u8 {
        self.endianness
    }

    pub fn is_addr_in_section(&self, addr: u64, name: &str) -> bool {
        self.section.get(name).map_or(false, |section| {
            let start = section.sh_addr;
            let end = start + section.sh_size;
            (start..end).contains(&addr)
        })
    }

    fn get_buffer_data(&self, offset: u64, len: u64) -> Result<Option<&[u8]>> {
        let offset = usize::try_from(offset)?;
        let len = usize::try_from(len)?;
        Ok(self.buffer.get(offset..offset + len))
    }

    pub fn get_section_data(&self, name: &str) -> Result<Option<&[u8]>> {
        self.section.get(name).map_or(Ok(None), |section| {
            self.get_buffer_data(section.sh_offset, section.sh_size)
        })
    }

    pub fn get_opcode_from_section(
        &self,
        addr: u64,
        name: &str,
    ) -> Result<Option<&[u8]>> {
        self.section.get(name).map_or(Ok(None), |section| {
            if self.is_addr_in_section(addr, name) {
                self.get_buffer_data(
                    addr - section.sh_addr + section.sh_offset,
                    MAX_OPCODE_SIZE,
                )
            } else {
                Ok(None)
            }
        })
    }
}
