use goblin::elf;
use nix::{errno::Errno, sys::wait::wait, unistd::Pid};
use procfs::process::{MMPermissions, MMapPath, Process};
use std::{collections::HashMap, fs::File, io::Read, path::Path};

use crate::diag::{Error, Result};

const EI_DATA: usize = 5;
const MAX_OPCODE_SIZE: u64 = 16;

pub struct Info {
    buffer: Vec<u8>,
    endianness: u8,
    entry: u64,
    offset: u64,
    vaddr: u64,
    sections: HashMap<String, elf::SectionHeader>,
}

impl Info {
    /// # Errors
    ///
    /// Will return `Err` upon any failure while collecting process data.
    pub fn build(path: &str, pid: Pid) -> Result<Self> {
        // First, wait for the process to start so we can collect its data.
        wait()?;

        let mut file = File::open(Path::new(path))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = elf::Elf::parse(&buffer)?;
        let endianness = elf.header.e_ident[EI_DATA];
        let entry = elf.header.e_entry;

        let pie = match elf.header.e_type {
            elf::header::ET_DYN => Ok(true),
            elf::header::ET_EXEC => Ok(false),
            _ => Err(Error::from(Errno::ENOEXEC)),
        }?;

        let offset = if pie {
            Self::get_mem_offset(path, pid)?
        } else {
            0
        };

        let vaddr = if pie {
            elf.program_headers
                .iter()
                .find(|ph| {
                    ph.p_type == elf::program_header::PT_LOAD && ph.is_executable()
                })
                .map(|ph| ph.p_vaddr)
                .ok_or_else(|| Error::from(Errno::ENODATA))?
        } else {
            0
        };

        let sections: HashMap<String, elf::SectionHeader> = elf
            .section_headers
            .iter()
            .filter_map(|header| {
                elf.shdr_strtab
                    .get_at(header.sh_name)
                    .map(|name| (name.to_string(), header.clone()))
            })
            .collect();
        sections
            .get(".text")
            .ok_or_else(|| Error::from(Errno::ENODATA))?;

        Ok(Self {
            buffer,
            endianness,
            entry,
            offset,
            vaddr,
            sections,
        })
    }

    fn get_mem_offset(path: &str, pid: Pid) -> Result<u64> {
        let absolute_path = std::fs::canonicalize(path)?;

        let process = Process::new(pid.into())?;
        let maps = process.maps()?;

        let mut offset = None;
        for map in maps {
            if map.perms.contains(MMPermissions::READ)
                && map.perms.contains(MMPermissions::EXECUTE)
            {
                if let MMapPath::Path(buf) = &map.pathname {
                    if buf == &absolute_path {
                        offset = Some(map.address.0);
                        break;
                    }
                }
            }
        }

        offset.ok_or_else(|| Error::from(Errno::ENODATA))
    }

    #[must_use]
    pub fn endianness(&self) -> u8 {
        self.endianness
    }

    #[must_use]
    pub fn entry(&self) -> u64 {
        self.entry + self.offset - self.vaddr
    }

    pub fn vaddr(&self) -> u64 {
        self.vaddr
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub fn is_addr_in_section(&self, addr: u64, name: &str) -> bool {
        self.sections.get(name).map_or(false, |section| {
            let start = section.sh_addr + self.offset;
            let end = start + section.sh_size;
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
        self.sections.get(name).map_or(Ok(None), |section| {
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
    ) -> Result<Option<&[u8]>> {
        let addr = addr + self.vaddr;
        self.sections.get(name).map_or(Ok(None), |section| {
            if self.is_addr_in_section(addr, name) {
                self.get_buffer_data(
                    addr - self.offset - section.sh_addr + section.sh_offset,
                    MAX_OPCODE_SIZE,
                )
            } else {
                Ok(None)
            }
        })
    }
}
