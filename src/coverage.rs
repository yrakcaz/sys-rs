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
    progress::{self, ProgressFn},
};

pub struct Cached {
    cache: HashMap<u64, Option<LineInfo>>,
    coverage: HashMap<(String, usize), usize>,
    files: HashSet<String>,
}

impl Cached {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            coverage: HashMap::new(),
            files: HashSet::new(),
        }
    }

    #[must_use]
    pub fn coverage(&self, path: String, line: usize) -> Option<&usize> {
        let key = (path, line);
        self.coverage.get(&key)
    }

    #[must_use]
    pub fn files(&self) -> &HashSet<String> {
        &self.files
    }

    pub fn print_source(
        &mut self,
        instruction: &Instruction,
        dwarf: &Dwarf,
        record: bool,
    ) -> Result<bool> {
        let mut ret = false;
        let addr = instruction.addr();
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
                println!("{line}");
                ret = true;
            }
        }
        Ok(ret)
    }

    pub fn trace_with_source_print(
        &mut self,
        context: &Tracer,
        process: &process::Info,
    ) -> Result<i32> {
        let dwarf = Dwarf::build(process)?;
        trace_with(
            context,
            process,
            true,
            |instruction, _| self.print_source(instruction, &dwarf, false),
            progress::default,
        )
    }

    pub fn trace_with_custom_progress(
        &mut self,
        context: &Tracer,
        process: &process::Info,
        dwarf: Option<&Dwarf>,
        record: bool,
        progress: impl ProgressFn,
    ) -> Result<i32> {
        let src_available = dwarf.is_some();
        trace_with(
            context,
            process,
            src_available,
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
