use gimli;
use goblin::elf::header::{ELFDATA2LSB, ELFDATA2MSB};
use nix::errno::Errno;
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use crate::{
    diag::{Error, Result},
    exec::Elf,
};

pub struct LineInfo {
    addr: u64,
    path: PathBuf,
    line: usize,
}

impl LineInfo {
    /// # Errors
    ///
    /// Will return `Err` upon failure to convert line (u64) to usize.
    pub fn new(addr: u64, path: PathBuf, line: u64) -> Result<Self> {
        Ok(Self {
            addr,
            path,
            line: usize::try_from(line)?,
        })
    }

    #[must_use]
    pub fn path(&self) -> String {
        self.path.display().to_string()
    }

    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }

    fn read(&self) -> Result<String> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut lines = reader.lines();
        if let Some(line) = lines.nth(self.line - 1) {
            Ok(line?)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }
}

impl fmt::Display for LineInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(line) = self.read() {
            write!(
                f,
                "0x{:x}: {}:{} | {}",
                self.addr,
                self.path.display(),
                self.line,
                line
            )
        } else {
            Err(fmt::Error)
        }
    }
}

type AddressRange = Vec<(u64, u64)>;
type DebugArangesMap = HashMap<gimli::DebugInfoOffset, AddressRange>;
type SectionData<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

pub struct Dwarf<'a> {
    dwarf: gimli::Dwarf<SectionData<'a>>,
    aranges: DebugArangesMap, // FIXME rename?
}

impl<'a> Dwarf<'a> {
    /// # Errors
    ///
    /// Will return `Err` upon any failure to retrieve ELF section.
    pub fn build(elf: &'a Elf) -> Result<Self> {
        let endianness = match elf.endianness() {
            ELFDATA2LSB => Ok(gimli::RunTimeEndian::Little),
            ELFDATA2MSB => Ok(gimli::RunTimeEndian::Big),
            _ => Err(Error::from(Errno::ENOEXEC)),
        }?;

        let debug_ranges = gimli::DebugRanges::new(Self::get_section(".debug_ranges", elf).unwrap_or(&[]), endianness);
        let debug_rnglists = gimli::DebugRngLists::new(Self::get_section(".debug_rnglists", elf).unwrap_or(&[]), endianness);
        let ranges = gimli::RangeLists::new(debug_ranges, debug_rnglists);
        let dwarf = gimli::Dwarf {
            debug_abbrev: gimli::DebugAbbrev::new(
                Self::get_section(".debug_abbrev", elf)?,
                endianness,
            ),
            debug_info: gimli::DebugInfo::new(
                Self::get_section(".debug_info", elf)?,
                endianness,
            ),
            debug_line: gimli::DebugLine::new(
                Self::get_section(".debug_line", elf)?,
                endianness,
            ),
            debug_str: gimli::DebugStr::new(
                Self::get_section(".debug_str", elf)?,
                endianness,
            ),
            ranges,
            ..Default::default()
        };

        let aranges = Self::build_aranges(&dwarf)?;

        Ok(Self { dwarf, aranges })
    }

    fn get_section(section_name: &'a str, elf: &'a Elf) -> Result<&'a [u8]> {
        elf.get_section_data(section_name)
            .map_err(Error::from)?
            .ok_or_else(|| Error::from(Errno::ENODATA))
    }

    fn build_aranges(dwarf: &gimli::Dwarf<gimli::EndianSlice<gimli::RunTimeEndian>>) -> Result<HashMap<gimli::DebugInfoOffset, Vec<(u64, u64)>>> {
        let mut aranges = HashMap::new();
        let mut iter = dwarf.units();
        while let Some(unit_header) = iter.next()? {
            let mut unit_ranges = Vec::new();
            let unit = dwarf.unit(unit_header)?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                let mut attrs = entry.attrs();
                let mut low_pc = None;
                let mut high_pc = None;
                let mut high_pc_offset = None; // FIXME really?
                let mut ranges_offset = None;
                while let Some(attr) = attrs.next()? {
                    match attr.name() {
                        gimli::DW_AT_low_pc => {
                            if let gimli::AttributeValue::Addr(addr) = attr.value() {
                                low_pc = Some(addr);
                            }
                        }
                        gimli::DW_AT_high_pc => match attr.value() {
                            gimli::AttributeValue::Addr(val) => high_pc = Some(val),
                            gimli::AttributeValue::Udata(val) => high_pc_offset = Some(val),
                            _ => return Err(Error::from(Errno::ENODATA)), // FIXME meh
                        },
                        gimli::DW_AT_ranges => {
                            if let gimli::AttributeValue::RangeListsRef(val) = attr.value() {
                                ranges_offset = Some(val);
                            }
                        },
                        _ => continue,
                    }
                }

                if let (Some(low_pc), Some(high_pc)) = (low_pc, high_pc) {
                    unit_ranges.push((low_pc, high_pc));
                } else if let (Some(low_pc), Some(high_pc_offset)) = (low_pc, high_pc_offset) {
                    unit_ranges.push((low_pc, (low_pc + high_pc_offset)));
                } else if let Some(ranges_offset) = ranges_offset {
                    let offset = dwarf.ranges_offset_from_raw(&unit, ranges_offset);
                    let mut iter = dwarf.ranges(&unit, offset)?;
                    while let Some(range) = iter.next()? {
                        unit_ranges.push((range.begin, range.end));
                    }
                }
            }

            aranges.insert(unit_header.offset().as_debug_info_offset().unwrap(), unit_ranges); // FIXME not unwrap
        }
        Ok(aranges)
    }

    fn is_addr_in_unit<R: gimli::Reader<Offset = usize>>(
        &self,
        addr: u64,
        unit_header: &gimli::UnitHeader<R>,
    ) -> Result<bool> {
        if let Some(offset) = unit_header.offset().as_debug_info_offset() {
            self.aranges
                .get(&offset)
                .map(|ranges| {
                    ranges
                        .iter()
                        .any(|(start, end)| {
                            (*start..*end).contains(&addr)
                    })
                })
                .ok_or_else(|| Error::from(Errno::ENODATA))
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    // FIXME code needs to be cleaned up, and we need to profile neuralnet-works again

    fn path_from_row(
        &self,
        unit_header: &gimli::UnitHeader<SectionData<'_>>,
        program_header: &gimli::LineProgramHeader<SectionData<'_>>,
        row: &gimli::LineRow,
    ) -> Result<PathBuf> {
        let mut path = PathBuf::new();

        let unit = self.dwarf.unit(*unit_header)?;
        if let Some(dir) = unit.comp_dir {
            path.push(dir.to_string_lossy().into_owned());
        }

        if let Some(file) = row.file(program_header) {
            if file.directory_index() != 0 {
                if let Some(dir) = file.directory(program_header) {
                    let dir_path = self
                        .dwarf
                        .attr_string(&unit, dir)?
                        .to_string_lossy()
                        .into_owned();
                    path.push(dir_path);
                }
            }

            let file_path = self
                .dwarf
                .attr_string(&unit, file.path_name())?
                .to_string_lossy()
                .into_owned();
            path.push(file_path);

            Ok(path)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    fn info_from_row(
        &self,
        unit_header: &gimli::UnitHeader<SectionData<'_>>,
        program_header: &gimli::LineProgramHeader<SectionData<'_>>,
        row: &gimli::LineRow,
    ) -> Result<LineInfo> {
        if let Some(line) = row.line() {
            let line = line.get();
            let path = self.path_from_row(unit_header, program_header, row)?;
            Ok(LineInfo::new(row.address(), path, line)?)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    fn info_from_unit(
        &self,
        addr: u64,
        unit_header: &gimli::UnitHeader<SectionData<'_>>,
    ) -> Result<Option<LineInfo>> {
        let mut info = None;

        let unit = self.dwarf.unit(*unit_header)?;
        if let Some(program) = unit.line_program {
            let mut rows = program.rows();
            while let Some((program_header, row)) = rows.next_row()? {
                if !row.is_stmt() {
                    continue;
                }

                if addr != row.address() {
                    continue;
                }

                info = Some(self.info_from_row(unit_header, program_header, row)?);
                break;
            }
        }

        Ok(info)
    }

    /// # Errors
    ///
    /// Will return `Err` upon any failure to read or parse DWARF format.
    pub fn addr2line(&self, addr: u64) -> Result<Option<LineInfo>> {
        let mut info: Option<LineInfo> = None;
        let mut iter = self.dwarf.units();
        while let Some(unit_header) = iter.next()? {
            if !self.is_addr_in_unit(addr, &unit_header)? {
                continue;
            }

            info = self.info_from_unit(addr, &unit_header)?;
            if info.is_some() {
                break;
            }
        }

        Ok(info)
    }
}
