use gimli::{
    DebugAbbrev, DebugAranges, DebugInfo, DebugInfoOffset, DebugLine, Dwarf,
    EndianSlice, LineProgramHeader, LineRow, RunTimeEndian, UnitHeader,
};
use goblin::elf::header::{ELFDATA2LSB, ELFDATA2MSB};
use nix::errno::Errno;
use std::{
    collections::{hash_map::Entry, HashMap},
    path::PathBuf,
};

use crate::diag::{Error, Result};
use crate::elf;

pub mod line;

// FIXME should dwarf and elf be in the same module??

pub struct Reader<'a> {
    // FIXME is Reader the correct name? same for elf?
    dwarf: Dwarf<EndianSlice<'a, RunTimeEndian>>,
    aranges: HashMap<DebugInfoOffset, Vec<(u64, u64)>>,
    cache: HashMap<u64, Option<line::Info>>,
}

impl<'a> Reader<'a> {
    pub fn build(elf: &'a elf::Reader) -> Result<Self> {
        let endianness = match elf.endianness() {
            ELFDATA2LSB => Ok(RunTimeEndian::Little),
            ELFDATA2MSB => Ok(RunTimeEndian::Big),
            _ => Err(Errno::ENOEXEC),
        }?;

        let get_section_data = |section| {
            elf.get_section_data(section)?
                .ok_or_else(|| Error::from(Errno::ENODATA))
        };
        let debug_abbrev =
            DebugAbbrev::new(get_section_data(".debug_abbrev")?, endianness);
        let debug_info =
            DebugInfo::new(get_section_data(".debug_info")?, endianness);
        let debug_line =
            DebugLine::new(get_section_data(".debug_line")?, endianness);
        let dwarf = Dwarf {
            debug_abbrev,
            debug_info,
            debug_line,
            ..Default::default()
        };

        let debug_aranges =
            DebugAranges::new(get_section_data(".debug_aranges")?, endianness);
        let mut aranges = HashMap::new();
        let mut aranges_iter = debug_aranges.headers();
        while let Some(header) = aranges_iter.next()? {
            let offset = header.debug_info_offset();
            let mut vec = Vec::new();
            let mut entries_iter = header.entries();
            while let Some(entry) = entries_iter.next()? {
                let addr = entry.address();
                let len = entry.length();
                vec.push((addr, addr + len));
            }
            aranges.insert(offset, vec);
        }

        Ok(Self {
            dwarf,
            aranges,
            cache: HashMap::new(),
        })
    }

    // FIXME the facto doesn't look neat..

    // FIXME gimli::..?
    fn is_addr_in_unit<R: gimli::Reader<Offset = usize>>(
        &mut self,
        addr: u64,
        unit_header: &UnitHeader<R>,
    ) -> Result<bool> {
        if let Some(offset) = unit_header.offset().as_debug_info_offset() {
            if let Some(ranges) = self.aranges.get(&offset) {
                let mut ret = false;
                for (start, end) in ranges {
                    if (*start..*end).contains(&addr) {
                        ret = true;
                        break;
                    }
                }
                Ok(ret)
            } else {
                Err(Error::from(Errno::ENODATA))
            }
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    fn path_for_row(
        &self,
        unit_header: &UnitHeader<EndianSlice<'_, RunTimeEndian>>,
        program_header: &LineProgramHeader<EndianSlice<'_, RunTimeEndian>>,
        row: &LineRow,
    ) -> Result<PathBuf> {
        let unit = self.dwarf.unit(*unit_header)?;
        if let Some(file) = row.file(program_header) {
            // FIXME comp_dir below should give absolute path. try using unit.unit_ref (see
            // simple_line.rs)
            let mut path = if let Some(dir) = unit.comp_dir {
                PathBuf::from(dir.to_string_lossy().into_owned())
            } else {
                PathBuf::new()
            };

            if file.directory_index() != 0 {
                if let Some(dir) = file.directory(program_header) {
                    path.push(
                        self.dwarf
                            .attr_string(&unit, dir)?
                            .to_string_lossy()
                            .as_ref(),
                    );
                }
            }

            path.push(
                self.dwarf
                    .attr_string(&unit, file.path_name())?
                    .to_string_lossy()
                    .as_ref(),
            );

            Ok(path)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    fn info_from_row(
        &self,
        unit_header: &UnitHeader<EndianSlice<'_, RunTimeEndian>>,
        program_header: &LineProgramHeader<EndianSlice<'_, RunTimeEndian>>,
        row: &LineRow,
    ) -> Result<line::Info> {
        if let Some(line) = row.line() {
            let line = line.get();
            let path = self.path_for_row(&unit_header, &program_header, &row)?;
            Ok(line::Info::new(row.address(), path, line)?)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    fn do_addr2line(&mut self, addr: u64) -> Result<Option<line::Info>> {
        let mut info: Option<line::Info> = None;
        let mut iter = self.dwarf.units();
        while let Some(unit_header) = iter.next()? {
            if let Some(_) = info {
                // Address already found.
                break;
            }

            if !self.is_addr_in_unit(addr, &unit_header)? {
                continue;
            }

            let unit = self.dwarf.unit(unit_header)?;
            if let Some(program) = unit.line_program {
                let mut rows = program.rows();
                while let Some((program_header, row)) = rows.next_row()? {
                    if row.end_sequence() {
                        continue;
                    }

                    if addr != row.address() {
                        continue;
                    }

                    info = Some(self.info_from_row(
                        &unit_header,
                        &program_header,
                        &row,
                    )?);
                    break;
                }
            }
        }

        Ok(info)
    }

    pub fn addr2line(&mut self, addr: u64) -> Result<&Option<line::Info>> {
        if let Entry::Vacant(_) = self.cache.entry(addr) {
            let info = self.do_addr2line(addr)?;
            self.cache.insert(addr, info);
        }

        Ok(self
            .cache
            .get(&addr)
            .ok_or_else(|| Error::from(Errno::ENODATA))?)
    }
}
