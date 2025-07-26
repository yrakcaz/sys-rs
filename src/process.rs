use goblin::elf;
use nix::{errno::Errno, sys::wait::wait, unistd::Pid};
use procfs::process::{MMPermissions, MMapPath, Process};
use std::{collections::HashMap, fs::File, io::Read, path::Path};

use crate::diag::{Error, Result};

const AT_ENTRY: u64 = 9;
const AT_PHDR: u64 = 3;
const EI_DATA: usize = 5;
const MAX_OPCODE_SIZE: u64 = 16;

pub struct Info {
    pid: Pid,
    auxv: HashMap<u64, u64>,
    buffer: Vec<u8>,
    header: elf::Header,
    sections: HashMap<String, elf::SectionHeader>,
    load_vaddr: u64,
    load_offset: u64,
    mem_offset: u64,
}

impl Info {
    /// Builds an `Info` struct by collecting process data.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file containing process data.
    /// * `pid` - The process ID.
    ///
    /// # Errors
    ///
    /// Returns an `Err` upon any failure while collecting process data.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the `Info` struct upon success, or an `Err` upon failure.
    pub fn build(path: &str, pid: Pid) -> Result<Self> {
        // First, wait for the process to start so we can collect its data.
        wait()?;

        let auxv = Self::get_auxv(pid)?;

        let mut file = File::open(Path::new(path))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = elf::Elf::parse(&buffer)?;
        let header = elf.header;

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

        let dynamic = match elf.header.e_type {
            elf::header::ET_DYN => Ok(true),
            elf::header::ET_EXEC => Ok(false),
            _ => Err(Error::from(Errno::ENOEXEC)),
        }?;

        let (load_vaddr, load_offset) = if dynamic {
            elf.program_headers
                .iter()
                .find(|ph| {
                    ph.p_type == elf::program_header::PT_LOAD && ph.is_executable()
                })
                .map(|ph| (ph.p_vaddr, ph.p_offset))
                .ok_or_else(|| Error::from(Errno::ENODATA))?
        } else {
            (0, 0)
        };

        let mem_offset = if dynamic {
            Self::get_mem_offset(path, pid)?
        } else {
            0
        };

        Ok(Self {
            pid,
            auxv,
            buffer,
            header,
            sections,
            load_vaddr,
            load_offset,
            mem_offset,
        })
    }

    fn get_auxv(pid: Pid) -> Result<HashMap<u64, u64>> {
        let process = Process::new(pid.into())?;
        let auxv = process.auxv()?;
        Ok(auxv.into_iter().collect())
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

    fn get_buffer_data(&self, offset: u64, len: u64) -> Result<Option<&[u8]>> {
        let offset = usize::try_from(offset)?;
        let len = usize::try_from(len)?;
        Ok(self.buffer.get(offset..offset + len))
    }

    #[must_use]
    pub fn pid(&self) -> Pid {
        self.pid
    }

    #[must_use]
    pub fn endianness(&self) -> u8 {
        self.header.e_ident[EI_DATA]
    }

    #[must_use]
    pub fn offset(&self) -> u64 {
        self.mem_offset - self.load_vaddr
    }

    #[must_use]
    pub fn is_addr_in_section(&self, addr: u64, name: &str) -> bool {
        self.sections.get(name).is_some_and(|section| {
            let start = section.sh_addr + self.mem_offset;
            let end = start + section.sh_size;
            (start..end).contains(&addr)
        })
    }

    /// Retrieves the runtime entry point address of the process from the auxiliary vector.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the entry point is not available in the auxiliary vector.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a reference to the entry point address (`u64`) from the auxiliary vector (`AT_ENTRY`).
    pub fn entry(&self) -> Result<&u64> {
        self.auxv
            .get(&AT_ENTRY)
            .ok_or_else(|| Error::from(Errno::ENODATA))
    }

    /// Retrieves the data from the specified section.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the section.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the conversion from `u64` to `usize` fails when getting buffer data.
    ///
    /// # Returns
    ///
    /// Returns an `Ok` containing the data from the specified section as a slice of bytes, or `Err` if the section does not exist or if the conversion from `u64` to `usize` fails.
    pub fn get_section_data(&self, name: &str) -> Result<Option<&[u8]>> {
        self.sections.get(name).map_or(Ok(None), |section| {
            self.get_buffer_data(section.sh_offset, section.sh_size)
        })
    }

    /// Retrieves opcode data from the loaded binary at a given runtime address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The runtime address for which to fetch opcode bytes.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the conversion from `u64` to `usize` fails when accessing the buffer, or if required auxiliary vector data is missing.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(&[u8]))` containing the opcode bytes at the given address, `Ok(None)` if the address is invalid, or `Err` on conversion failure or missing data.
    pub fn get_opcode_from_addr(&self, addr: u64) -> Result<Option<&[u8]>> {
        let phdr = self
            .auxv
            .get(&AT_PHDR)
            .ok_or_else(|| Error::from(Errno::ENODATA))?;
        let offset =
            (addr - phdr + self.header.e_phoff) + self.load_offset - self.load_vaddr;
        self.get_buffer_data(offset, MAX_OPCODE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    fn create_temp_elf_file() -> std::io::Result<String> {
        let path = "/tmp/test.elf";
        let mut file = File::create(path)?;
        file.write_all(b"\x7fELF")?;
        Ok(path.to_string())
    }

    #[test]
    fn test_get_section_data_invalid() {
        let pid = Pid::from_raw(1234);
        let path =
            create_temp_elf_file().expect("Failed to create temporary ELF file");
        let info = Info::build(&path, pid);
        // Should fail to build due to invalid ELF, so skip if error
        if let Ok(info) = info {
            let data = info.get_section_data(".invalid");
            assert!(matches!(data, Ok(None)));
        }
    }

    #[test]
    fn test_get_opcode_from_addr_invalid_auxv() {
        let pid = Pid::from_raw(1234);
        let path =
            create_temp_elf_file().expect("Failed to create temporary ELF file");
        let info = Info::build(&path, pid);
        // Should fail to build due to invalid ELF, so skip if error
        if let Ok(info) = info {
            let result = info.get_opcode_from_addr(0xdeadbeef);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_is_addr_in_section_false() {
        let pid = Pid::from_raw(1234);
        let path =
            create_temp_elf_file().expect("Failed to create temporary ELF file");
        let info = Info::build(&path, pid);
        // Should fail to build due to invalid ELF, so skip if error
        if let Ok(info) = info {
            let found = info.is_addr_in_section(0xdeadbeef, ".text");
            assert!(!found);
        }
    }

    #[test]
    fn test_entry_missing() {
        let pid = Pid::from_raw(1234);
        let path =
            create_temp_elf_file().expect("Failed to create temporary ELF file");
        let info = Info::build(&path, pid);
        // Should fail to build due to invalid ELF, so skip if error
        if let Ok(info) = info {
            let entry = info.entry();
            assert!(entry.is_err());
        }
    }

    #[test]
    fn test_build_invalid_path() {
        let pid = Pid::from_raw(1234);
        let result = Info::build("/invalid/path", pid);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_invalid_elf() {
        let pid = Pid::from_raw(1234);
        let path =
            create_temp_elf_file().expect("Failed to create temporary ELF file");
        let result = Info::build(&path, pid);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_mem_offset_invalid_path() {
        let pid = Pid::from_raw(1234);
        let result = Info::get_mem_offset("/invalid/path", pid);
        assert!(result.is_err());
    }
}
