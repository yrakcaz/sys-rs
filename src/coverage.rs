use nix::errno::Errno;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    path::Path,
};

use crate::{
    asm::Instruction,
    debug::{Dwarf, LineInfo},
    diag::{Error, Result},
    print::{self, Layout},
    process,
    profile::{trace_with, Tracer},
    progress::{self, ProgressFn, State},
};

/// Coverage collector that maintains an in-memory mapping from source
/// locations to execution counts.
///
/// `Cached` keeps a small cache mapping instruction addresses to source
/// `LineInfo` (if available) and a `coverage` map counting visits per file
/// and line. It also tracks the set of files seen.
pub struct Cached {
    cache: HashMap<u64, Option<LineInfo>>,
    coverage: HashMap<(String, usize), usize>,
    files: HashSet<String>,
}

impl Cached {
    #[must_use]
    /// Create a new, empty `Cached` collector.
    ///
    /// # Returns
    ///
    /// A new, empty `Cached` instance.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            coverage: HashMap::new(),
            files: HashSet::new(),
        }
    }

    #[must_use]
    /// Get the coverage count for `path:line` if present.
    ///
    /// # Arguments
    ///
    /// * `path` - Source file path.
    /// * `line` - Line number in the source file.
    ///
    /// # Returns
    ///
    /// `Some(&usize)` with the execution count when present, otherwise
    /// `None`.
    pub fn coverage(&self, path: String, line: usize) -> Option<&usize> {
        let key = (path, line);
        self.coverage.get(&key)
    }

    #[must_use]
    /// Return the set of files observed by the collector.
    ///
    /// # Returns
    ///
    /// A reference to the `HashSet` of file paths that have been observed.
    pub fn files(&self) -> &HashSet<String> {
        &self.files
    }

    /// Print the source line corresponding to `instruction` when available.
    ///
    /// This looks up the DWARF line info for the instruction address and
    /// prints the source line if the file exists on disk. When `record` is
    /// true the collector updates its internal coverage counts and file set.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The disassembled instruction whose source line to print.
    /// * `dwarf` - DWARF helper used to resolve addresses to source lines.
    /// * `record` - When true the collector records coverage counts for the
    ///   located source line.
    ///
    /// # Errors
    ///
    /// Returns an error if DWARF lookup fails.
    pub fn print_source(
        &mut self,
        instruction: &Instruction,
        dwarf: &Dwarf,
        record: bool,
    ) -> Result<Option<String>> {
        let mut ret = None;
        let addr = instruction.address();
        if let Entry::Vacant(_) = self.cache.entry(addr) {
            let info = dwarf.addr2line(addr)?;
            self.cache.insert(addr, info);
        }

        if let Some(line) = self
            .cache
            .get(&addr)
            .ok_or_else(|| Error::from(Errno::ENODATA))?
        {
            if Path::new(&line.path()).exists() {
                if record {
                    let key = (line.path(), line.line());
                    *self.coverage.entry(key).or_insert(0) += 1;
                    self.files.insert(line.path());
                }
                let output = format!("{line}");
                println!("{output}");
                ret = Some(output);
            }
        }
        Ok(ret)
    }

    /// Run the tracer and print source lines when available.
    ///
    /// This convenience wraps `trace_with` using the collector's
    /// `print_source` formatter so each executed instruction prints a
    /// source line when the DWARF information is present.
    ///
    /// # Arguments
    ///
    /// * `context` - The tracer implementation used to run the program.
    /// * `process` - Process metadata for the target binary.
    ///
    /// # Errors
    ///
    /// Returns an error if DWARF construction fails or if tracing fails.
    pub fn trace_with_source_print(
        &mut self,
        context: &Tracer,
        process: &process::Info,
    ) -> Result<i32> {
        let dwarf = Dwarf::build(process)?;
        let state = State::new(process.pid(), Some(&dwarf));
        trace_with(
            context,
            process,
            state,
            |instruction, _| self.print_source(instruction, &dwarf, false),
            progress::default,
        )
    }

    /// Run the tracer using a custom progress function and optionally print
    /// source lines.
    ///
    /// If `dwarf` is `Some`, the tracer will attempt to print source lines
    /// (when the layout indicates source); otherwise it falls back to the
    /// default printer. When `record` is true coverage counts are collected.
    /// The provided `progress` function is used for user interaction between
    /// instructions.
    ///
    /// # Arguments
    ///
    /// * `context` - The tracer implementation used to run the program.
    /// * `process` - Process metadata for the target binary.
    /// * `dwarf` - Optional DWARF helper; when `Some` source printing is enabled.
    /// * `record` - If true, coverage counts are recorded.
    /// * `progress` - Custom progress function called between instructions.
    ///
    /// # Errors
    ///
    /// Returns an error if tracing or DWARF operations fail.
    pub fn trace_with_custom_progress(
        &mut self,
        context: &Tracer,
        process: &process::Info,
        dwarf: Option<&Dwarf>,
        record: bool,
        progress: impl ProgressFn,
    ) -> Result<i32> {
        let src_available = dwarf.is_some();
        let state = State::new(process.pid(), dwarf);
        trace_with(
            context,
            process,
            state,
            |instruction, layout| match (Layout::from(src_available), layout) {
                (Layout::Source, Layout::Source) => self.print_source(
                    instruction,
                    dwarf.ok_or_else(|| Error::from(Errno::ENODATA))?,
                    record,
                ),
                _ => print::default(instruction, layout),
            },
            progress,
        )
    }

    /// Run the tracer with the default progress function and recording
    /// enabled.
    ///
    /// This is the standard entry point for coverage collection: it tries
    /// to build DWARF info and then calls `trace_with_custom_progress`.
    ///
    /// # Arguments
    ///
    /// * `context` - The tracer implementation used to run the program.
    /// * `process` - Process metadata for the target binary.
    ///
    /// # Errors
    ///
    /// Returns an error if DWARF construction or tracing fails.
    pub fn trace_with_default_progress(
        &mut self,
        context: &Tracer,
        process: &process::Info,
    ) -> Result<i32> {
        let dwarf = Dwarf::build(process);
        self.trace_with_custom_progress(
            context,
            process,
            dwarf.as_ref().ok(),
            true,
            progress::default,
        )
    }
}

impl Default for Cached {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_new() {
        let cached = Cached::new();
        assert_eq!(cached.coverage.len(), 0);
        assert_eq!(cached.files.len(), 0);
    }

    #[test]
    fn test_cached_coverage() {
        let mut cached = Cached::new();
        cached.coverage.insert(("file1".to_string(), 10), 5);
        cached.coverage.insert(("file2".to_string(), 20), 10);

        assert_eq!(cached.coverage("file1".to_string(), 10), Some(&5));
        assert_eq!(cached.coverage("file2".to_string(), 20), Some(&10));
        assert_eq!(cached.coverage("file3".to_string(), 30), None);
    }

    #[test]
    fn test_cached_files() {
        let mut cached = Cached::new();
        cached.files.insert("file1".to_string());
        cached.files.insert("file2".to_string());

        assert_eq!(cached.files().len(), 2);
        assert!(cached.files().contains("file1"));
        assert!(cached.files().contains("file2"));
        assert!(!cached.files().contains("file3"));
    }
}
