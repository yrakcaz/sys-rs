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

/// Information about a source line mapped from an address.
///
/// `LineInfo` contains the instruction address, the source file path, and
/// the 1-based line number. It provides helpers for retrieving the line's
/// text and formatting it for display.
pub struct LineInfo {
    addr: u64,
    path: PathBuf,
    line: usize,
}

impl LineInfo {
    /// Create a new `LineInfo` from an address, path and 1-based line number.
    ///
    /// # Arguments
    ///
    /// * `addr` - The instruction address associated with the source line.
    /// * `path` - The path to the source file.
    /// * `line` - The 1-based line number in the file.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided `line` cannot be converted to a
    /// `usize`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(LineInfo)` on success with the provided address, path,
    /// and converted line number. Returns `Err` if the `line` argument
    /// cannot be converted to `usize`.
    pub fn new(addr: u64, path: PathBuf, line: u64) -> Result<Self> {
        Ok(Self {
            addr,
            path,
            line: usize::try_from(line)?,
        })
    }

    #[must_use]
    /// Return the source path as a displayable `String`.
    ///
    /// # Returns
    ///
    /// A `String` containing the display representation of the stored path.
    pub fn path(&self) -> String {
        self.path.display().to_string()
    }

    #[must_use]
    /// Return the 1-based source line number.
    ///
    /// # Returns
    ///
    /// The 1-based source line number stored in this `LineInfo`.
    pub fn line(&self) -> usize {
        self.line
    }

    fn read(&self) -> Result<String> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut lines = reader.lines();

        let line = lines
            .nth(self.line - 1)
            .ok_or_else(|| Error::from(Errno::ENODATA))??;
        Ok(line)
    }
}

impl fmt::Display for LineInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = self.read().map_err(|_| fmt::Error)?;
        write!(
            f,
            "{:#x}: {}:{} | {}",
            self.addr,
            self.path.display(),
            self.line,
            line
        )
    }
}

type AddressRange = Vec<(u64, u64)>;
type DebugArangesMap = HashMap<gimli::DebugInfoOffset, AddressRange>;
type SectionData<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// DWARF debugging information parsed from an ELF image.
///
/// `Dwarf` encapsulates parsed DWARF sections and a mapping from compile
/// unit offsets to address ranges. It provides helpers to build the DWARF
/// representation from an executable and resolve addresses to source
/// locations.
pub struct Dwarf<'a> {
    data: gimli::Dwarf<SectionData<'a>>,
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
        let data = gimli::Dwarf {
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

        let aranges = Self::build_aranges(&data)?;
        let offset = process.offset();

        Ok(Self {
            data,
            aranges,
            offset,
        })
    }

    fn get_section(
        section_name: &'a str,
        process: &'a process::Info,
    ) -> Result<&'a [u8]> {
        process
            .get_section_data(section_name)?
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
                        _ => {}
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

            let offset = unit_header
                .offset()
                .as_debug_info_offset()
                .ok_or_else(|| Error::from(Errno::ENODATA))?;
            aranges.insert(offset, unit_ranges);
        }

        Ok(aranges)
    }

    fn is_addr_in_unit<R: gimli::Reader<Offset = usize>>(
        &self,
        addr: u64,
        unit_header: &gimli::UnitHeader<R>,
    ) -> Result<bool> {
        let offset = unit_header
            .offset()
            .as_debug_info_offset()
            .ok_or_else(|| Error::from(Errno::ENODATA))?;

        self.aranges
            .get(&offset)
            .map(|ranges| {
                ranges
                    .iter()
                    .any(|(start, end)| (*start..*end).contains(&addr))
            })
            .ok_or_else(|| Error::from(Errno::ENODATA))
    }

    fn path_from_row(
        &self,
        unit_header: &gimli::UnitHeader<SectionData<'_>>,
        program_header: &gimli::LineProgramHeader<SectionData<'_>>,
        row: &gimli::LineRow,
    ) -> Result<PathBuf> {
        let mut path = PathBuf::new();

        let unit = self.data.unit(*unit_header)?;
        if let Some(dir) = unit.comp_dir {
            path.push(dir.to_string_lossy().into_owned());
        }

        let file = row
            .file(program_header)
            .ok_or_else(|| Error::from(Errno::ENODATA))?;
        if file.directory_index() != 0 {
            if let Some(dir) = file.directory(program_header) {
                let dir_path = self
                    .data
                    .attr_string(&unit, dir)?
                    .to_string_lossy()
                    .into_owned();
                path.push(dir_path);
            }
        }

        let file_path = self
            .data
            .attr_string(&unit, file.path_name())?
            .to_string_lossy()
            .into_owned();
        path.push(file_path);

        Ok(path)
    }

    fn info_from_row(
        &self,
        unit_header: &gimli::UnitHeader<SectionData<'_>>,
        program_header: &gimli::LineProgramHeader<SectionData<'_>>,
        row: &gimli::LineRow,
    ) -> Result<LineInfo> {
        let line = row.line().ok_or_else(|| Error::from(Errno::ENODATA))?;

        let line = line.get();
        let path = self.path_from_row(unit_header, program_header, row)?;
        LineInfo::new(row.address() + self.offset, path, line)
    }

    fn info_from_unit(
        &self,
        addr: u64,
        unit_header: &gimli::UnitHeader<SectionData<'_>>,
    ) -> Result<Option<LineInfo>> {
        let mut info = None;

        let unit = self.data.unit(*unit_header)?;
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
        let mut iter = self.data.units();
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

#[cfg(test)]
mod tests {
    use super::*;

    use gimli::{
        DebugAbbrev, DebugInfo, DebugLine, DebugRanges, DebugRngLists, DebugStr,
        RangeLists, RunTimeEndian,
    };
    use std::{collections::HashMap, io::Write};

    use crate::diag::Result;

    #[test]
    fn test_line_info_new() {
        let path = PathBuf::from("/path/to/file.rs");
        let line_info = LineInfo::new(0x1234, path.clone(), 42)
            .expect("Failed to create LineInfo");
        assert_eq!(line_info.addr, 0x1234);
        assert_eq!(line_info.path, path);
        assert_eq!(line_info.line, 42);
    }

    #[test]
    fn test_line_info_path() {
        let path = PathBuf::from("/path/to/file.rs");
        let line_info = LineInfo::new(0x1234, path.clone(), 42)
            .expect("Failed to create LineInfo");
        assert_eq!(line_info.path(), "/path/to/file.rs");
    }

    #[test]
    fn test_line_info_line() {
        let path = PathBuf::from("/path/to/file.rs");
        let line_info =
            LineInfo::new(0x1234, path, 42).expect("Failed to create LineInfo");
        assert_eq!(line_info.line(), 42);
    }

    #[test]
    fn test_line_info_display() {
        let mut tmpfile =
            tempfile::NamedTempFile::new().expect("Failed to create temp file");
        for i in 1..100 {
            writeln!(tmpfile, "line {}", i).expect("Failed to write to temp file");
        }
        let path = tmpfile.path().to_path_buf();
        let line_info = LineInfo::new(0x1234, path.clone(), 42)
            .expect("Failed to create LineInfo");
        let display = format!("{}", line_info);
        assert!(display.contains("0x1234"));
        assert!(
            display.contains(path.to_str().expect("Failed to convert path to str"))
        );
        assert!(display.contains("42"));
    }

    #[test]
    fn test_build_aranges_empty() -> Result<()> {
        let endian = RunTimeEndian::Little;
        let data = gimli::Dwarf {
            debug_abbrev: DebugAbbrev::new(&[], endian),
            debug_info: DebugInfo::new(&[], endian),
            debug_line: DebugLine::new(&[], endian),
            debug_str: DebugStr::new(&[], endian),
            ranges: RangeLists::new(
                DebugRanges::new(&[], endian),
                DebugRngLists::new(&[], endian),
            ),
            ..Default::default()
        };

        let map = Dwarf::build_aranges(&data)?;
        assert!(map.is_empty());
        Ok(())
    }

    #[test]
    fn test_addr2line_empty_returns_none() -> Result<()> {
        let endian = RunTimeEndian::Little;
        let data = gimli::Dwarf {
            debug_abbrev: DebugAbbrev::new(&[], endian),
            debug_info: DebugInfo::new(&[], endian),
            debug_line: DebugLine::new(&[], endian),
            debug_str: DebugStr::new(&[], endian),
            ranges: RangeLists::new(
                DebugRanges::new(&[], endian),
                DebugRngLists::new(&[], endian),
            ),
            ..Default::default()
        };

        let dwarf = Dwarf {
            data,
            aranges: HashMap::new(),
            offset: 0,
        };
        let res = dwarf.addr2line(0x1000)?;
        assert!(res.is_none());
        Ok(())
    }
}
