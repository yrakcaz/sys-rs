use goblin::elf;
use nix::{errno::Errno, unistd::Pid};
use procfs::process::{MMPermissions, MMapPath, Process};
use std::{collections::HashMap, fs::File, io::Read, ops::Range, path::Path};

use crate::diag::{Error, Result};

const EI_DATA: usize = 5;
const MAX_OPCODE_SIZE: u64 = 16;

pub fn get_mem_range(pid : Pid, path : &str) -> Result<Range<u64>> {
  // FIXME can probs be cleaner + maybe somewhere else + do we really need a range?
  let process = Process::new(pid.into())?;
  let maps = process.maps()?;

  let mut ret = None;
  for map in maps {
     if map.perms.contains(MMPermissions::READ) &&
        map.perms.contains(MMPermissions::EXECUTE) {
        if let MMapPath::Path(buf) = &map.pathname {
           if buf.ends_with(path) {
              ret = Some(map.address.0..map.address.1);
              break;
           }
        }
     }
  }

  ret.ok_or_else(|| Error::from(Errno::ENODATA))
}

pub struct Elf {
    buffer: Vec<u8>,
    endianness: u8,
    entry: u64,
    etype: u16, // FIXME name
    section: HashMap<String, elf::SectionHeader>,
}

impl Elf {
    /// # Errors
    ///
    /// Will return `Err` upon any failure to read or parse ELF file.
    pub fn build(path: &str) -> Result<Self> {
        let path = Path::new(path);
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = elf::Elf::parse(&buffer)?;
        let endianness = elf.header.e_ident[EI_DATA];
        let entry = elf.header.e_entry;
        let etype = elf.header.e_type;

        let section: HashMap<String, elf::SectionHeader> = elf
            .section_headers
            .iter()
            .filter_map(|header| {
                elf.shdr_strtab
                    .get_at(header.sh_name)
                    .map(|name| (name.to_string(), header.clone()))
            })
            .collect();
        section
            .get(".text")
            .ok_or_else(|| Error::from(Errno::ENODATA))?;

        Ok(Self {
            buffer,
            endianness,
            entry,
            etype,
            section,
        })
    }

    #[must_use]
    pub fn endianness(&self) -> u8 {
        self.endianness
    }

    #[must_use]
    pub fn entry(&self, offset: u64) -> u64 {
        self.entry + offset
    }

    pub fn etype(&self) -> u16 {
        self.etype
    }

    #[must_use]
    pub fn is_addr_in_section(&self, addr: u64, name: &str, offset: u64) -> bool {
        self.section.get(name).map_or(false, |section| {
            let start = section.sh_addr + offset;
            let end = start + section.sh_size;
            //println!("{name}: 0x{:x} - 0x{:x} ++ 0x{addr:x}", start, end);
            (start..end).contains(&addr)
        })
    }

    fn get_buffer_data(&self, offset: u64, len: u64) -> Result<Option<&[u8]>> {
        let offset = usize::try_from(offset)?;
        let len = usize::try_from(len)?;
        Ok(self.buffer.get(offset..offset + len))
    }

    /// # Errors
    ///
    /// Will return `Err` upon failure to convert u64 to usize when getting buffer
    /// data.
    pub fn get_section_data(&self, name: &str) -> Result<Option<&[u8]>> {
        self.section.get(name).map_or(Ok(None), |section| {
            self.get_buffer_data(section.sh_offset, section.sh_size)
        })
    }

    /// # Errors
    ///
    /// Will return `Err` upon failure to convert u64 to usize when getting buffer
    /// data.
    pub fn get_opcode_from_section(
        &self,
        addr: u64,
        name: &str,
        offset: u64
    ) -> Result<Option<&[u8]>> {
        self.section.get(name).map_or(Ok(None), |section| {
            if self.is_addr_in_section(addr, name, offset) {
                self.get_buffer_data(
                    addr - offset - section.sh_addr + section.sh_offset,
                    MAX_OPCODE_SIZE,
                )
            } else {
                Ok(None)
            }
        })
    }
}
