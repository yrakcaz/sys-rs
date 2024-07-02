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
    process,
};

const FIRST_UNSUPPORTED_DWARF_VERSION: u16 = 5;

pub struct LineInfo {
    addr: u64,
    path: PathBuf,
    line: usize,
}

impl LineInfo {
    /// Represents information about a line in a file.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address of the line.
    /// * `path` - The path to the file.
    /// * `line` - The line number.
    ///
    /// # Errors
    ///
    /// This function may return an error if it fails to convert the line number from `u64` to `usize`.
    ///
    /// # Returns
    ///
    /// Returns a `LineInfo` object on success.
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
    aranges: DebugArangesMap,
    offset: u64,
}

impl<'a> Dwarf<'a> {
    /// Builds a `Dwarf` struct from the given process information.
    ///
    /// # Arguments
    ///
    /// * `process` - The process information.
    ///
    /// # Errors
    ///
    /// Returns an `Err` upon any failure to retrieve ELF sections or parse DWARF format.
    ///
    /// # Returns
    ///
    /// Returns a `Dwarf` struct on success, wrapped in an `Ok` variant. Returns an error on failure, wrapped in an `Err` variant.
    pub fn build(process: &'a process::Info) -> Result<Self> {
        let endianness = match process.endianness() {
            ELFDATA2LSB => Ok(gimli::RunTimeEndian::Little),
            ELFDATA2MSB => Ok(gimli::RunTimeEndian::Big),
            _ => Err(Error::from(Errno::ENOEXEC)),
        }?;

        let debug_ranges = gimli::DebugRanges::new(
            Self::get_section(".debug_ranges", process).unwrap_or(&[]),
            endianness,
        );
        let debug_rnglists = gimli::DebugRngLists::new(
            Self::get_section(".debug_rnglists", process).unwrap_or(&[]),
            endianness,
        );
        let ranges = gimli::RangeLists::new(debug_ranges, debug_rnglists);
        let dwarf = gimli::Dwarf {
            debug_abbrev: gimli::DebugAbbrev::new(
                Self::get_section(".debug_abbrev", process)?,
                endianness,
            ),
            debug_info: gimli::DebugInfo::new(
                Self::get_section(".debug_info", process)?,
                endianness,
            ),
            debug_line: gimli::DebugLine::new(
                Self::get_section(".debug_line", process)?,
                endianness,
            ),
            debug_str: gimli::DebugStr::new(
                Self::get_section(".debug_str", process)?,
                endianness,
            ),
            ranges,
            ..Default::default()
        };

        let aranges = Self::build_aranges(&dwarf)?;
        let offset = process.offset() - process.vaddr();

        Ok(Self {
            dwarf,
            aranges,
            offset,
        })
    }

    fn get_section(
        section_name: &'a str,
        process: &'a process::Info,
    ) -> Result<&'a [u8]> {
        process
            .get_section_data(section_name)
            .map_err(Error::from)?
            .ok_or_else(|| Error::from(Errno::ENODATA))
    }

    fn build_aranges(
        dwarf: &gimli::Dwarf<gimli::EndianSlice<gimli::RunTimeEndian>>,
    ) -> Result<HashMap<gimli::DebugInfoOffset, Vec<(u64, u64)>>> {
        let mut aranges = HashMap::new();
        let mut iter = dwarf.units();
        while let Some(unit_header) = iter.next()? {
            if unit_header.version() >= FIRST_UNSUPPORTED_DWARF_VERSION {
                Err(Errno::ENOEXEC)?;
            }

            let mut unit_ranges = Vec::new();
            let unit = dwarf.unit(unit_header)?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                let mut attrs = entry.attrs();
                let mut low_pc = None;
                let mut high_pc = None;
                let mut high_pc_offset = None;
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
                            gimli::AttributeValue::Udata(val) => {
                                high_pc_offset = Some(val);
                            }
                            _ => Err(Error::from(Errno::ENODATA))?,
                        },
                        gimli::DW_AT_ranges => {
                            if let gimli::AttributeValue::RangeListsRef(val) =
                                attr.value()
                            {
                                ranges_offset = Some(val);
                            }
                        }
                        _ => continue,
                    }
                }

                if let (Some(low_pc), Some(high_pc)) = (low_pc, high_pc) {
                    unit_ranges.push((low_pc, high_pc));
                } else if let (Some(low_pc), Some(high_pc_offset)) =
                    (low_pc, high_pc_offset)
                {
                    unit_ranges.push((low_pc, (low_pc + high_pc_offset)));
                } else if let Some(ranges_offset) = ranges_offset {
                    let offset = dwarf.ranges_offset_from_raw(&unit, ranges_offset);
                    let mut iter = dwarf.ranges(&unit, offset)?;
                    while let Some(range) = iter.next()? {
                        unit_ranges.push((range.begin, range.end));
                    }
                }
            }

            if let Some(offset) = unit_header.offset().as_debug_info_offset() {
                aranges.insert(offset, unit_ranges);
            } else {
                Err(Error::from(Errno::ENODATA))?;
            }
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
                        .any(|(start, end)| (*start..*end).contains(&addr))
                })
                .ok_or_else(|| Error::from(Errno::ENODATA))
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

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
            Ok(LineInfo::new(row.address() + self.offset, path, line)?)
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

    /// Resolves the source file name and line number for a given address in the binary.
    ///
    /// # Arguments
    ///
    /// * `addr`: The address in the binary's address space.
    ///
    /// # Errors
    ///
    /// Returns an error if there's any failure in reading or parsing the DWARF debug information.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(LineInfo))`: The resolved source file name and line number.
    /// - `Ok(None)`: The address does not correspond to any source line information.
    /// - `Err`: Error reading or parsing the DWARF information.
    pub fn addr2line(&self, addr: u64) -> Result<Option<LineInfo>> {
        let addr = addr - self.offset;

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
