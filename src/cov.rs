use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    path::Path,
};

use crate::{
    asm, breakpoint,
    debug::{Dwarf, LineInfo},
    diag::{Error, Result},
    process,
    trace::terminated,
};

pub struct Tracer {
    path: String,
    parser: asm::Parser,
}

impl Tracer {
    /// Creates a new `Tracer` instance.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the file.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if it fails to build `asm::Parser`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the newly created `Tracer` instance.
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
            parser: asm::Parser::new()?,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Traces the execution of a process and prints the instructions being executed.
///
/// # Arguments
///
/// * `context` - The `Tracer` instance containing the path to the file being traced.
/// * `process` - The process information.
/// * `child` - The process ID of the child process.
/// * `print` - A closure that takes an `asm::Instruction` and prints it.
///
/// # Errors
///
/// Returns an `Err` upon any failure related to parsing ELF or DWARF format, as well as issues related to syscalls usage (e.g. ptrace, wait).
///
/// # Returns
///
/// Returns a `Result` indicating success or failure.
fn trace_with<F>(
    context: &Tracer,
    process: &process::Info,
    mut print: F,
) -> Result<()>
where
    F: FnMut(&asm::Instruction) -> Result<()>,
{
    let child = process.pid();
    let mut breakpoint_mgr = breakpoint::Manager::new(child);

    let mut startup_complete = false;
    let mut last_instruction: Option<asm::Instruction> = None;

    breakpoint_mgr.set_breakpoint(process.entry())?;

    ptrace::cont(child, None)?;
    loop {
        let status = wait()?;
        match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                let mut regs = ptrace::getregs(child)?;
                breakpoint_mgr.handle_breakpoint(&mut regs)?;

                let rip = regs.rip;
                if let Some(opcode) =
                    process.get_opcode_from_section(rip, ".text")?
                {
                    let instruction =
                        context.parser.get_instruction_from(opcode, rip)?;
                    print(&instruction)?;
                    last_instruction = Some(instruction);
                } else if let Some(instruction) = last_instruction.as_ref() {
                    // The purpose of this scope is to prevent single stepping
                    // through libraries execution as a non-neglible amount of time
                    // is spent in those.

                    if instruction.is_call() {
                        #[allow(clippy::cast_sign_loss)]
                        let ret =
                            ptrace::read(child, regs.rsp as ptrace::AddressType)?
                                as u64;

                        // Keep single stepping after the first call as it is
                        // likely to be part of the startup routine so it
                        // might never return.
                        if process.is_addr_in_section(ret, ".text")
                            && startup_complete
                        {
                            breakpoint_mgr.set_breakpoint(ret)?;
                            ptrace::cont(child, None)?;
                            continue;
                        }
                        startup_complete = true;
                    }
                    last_instruction = None;
                }

                ptrace::step(child, None)?;
            }
            WaitStatus::Stopped(_, signal) => ptrace::cont(child, signal)?,
            _ if terminated(status) => break,
            _ => {}
        }
    }

    Ok(())
}

/// Traces the execution of a process and prints the instructions being executed using a simple print function.
///
/// # Arguments
///
/// * `context` - The `Tracer` instance containing the path to the file being traced.
/// * `child` - The process ID of the child process.
///
/// # Errors
///
/// Returns an `Err` upon any failure related to parsing ELF or DWARF format, as well as issues related to syscalls usage (e.g. ptrace, wait).
///
/// # Returns
///
/// Returns a `Result` indicating success or failure.
pub fn trace_with_simple_print(
    context: &Tracer,
    process: &process::Info,
) -> Result<()> {
    trace_with(context, process, |instruction| {
        println!("{instruction}");
        Ok(())
    })
}

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

    /// Traces the execution of a child process and updates the coverage information.
    ///
    /// # Arguments
    ///
    /// * `context` - The tracer context.
    /// * `child` - The process ID of the child process.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if the `trace_with` operation fails.
    ///
    /// # Returns
    ///
    /// Returns a `Result` indicating success or failure.
    pub fn trace(
        &mut self,
        context: &Tracer,
        process: &process::Info,
    ) -> Result<()> {
        let dwarf = Dwarf::build(process)?;
        trace_with(context, process, |instruction| {
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
                    let key = (line.path(), line.line());
                    *self.coverage.entry(key).or_insert(0) += 1;
                    self.files.insert(line.path());
                    println!("{line}");
                }
            }

            Ok(())
        })
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
    fn test_tracer_new() {
        let path = "/path/to/file";
        let tracer = Tracer::new(path).unwrap();
        assert_eq!(tracer.path(), path);
    }

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
