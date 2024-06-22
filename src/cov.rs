use goblin::elf;
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::Pid,
};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    path::Path,
};

use crate::{
    asm, breakpoint,
    debug::{Dwarf, LineInfo},
    diag::{Error, Result},
    exec::{get_mem_range, Elf},
    trace::terminated,
};

pub struct Tracer {
    path: String,
    elf: Elf,
    parser: asm::Parser,
}

impl Tracer {
    /// # Errors
    ///
    /// Will return `Err` upon failure to build `exec::Elf` or `asm::Parser`.
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            path: path.to_string(),
            elf: Elf::build(path)?,
            parser: asm::Parser::new()?,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn elf(&self) -> &Elf {
        &self.elf
    }
}

// FIXME this version seems to be working on EXEC/DYN with gdwarf4, but not Rust binaries.
// FIXME we should check what dwarf version we support and 1) update readme, 2) fail if wrong version.

/// # Errors
///
/// Will return `Err` upon any failure related to parsing ELF or DWARF format,
/// as well as issues related to syscalls usage (e.g. ptrace, wait).
fn trace_with<F>(context: &Tracer, child: Pid, mut print: F) -> Result<()>
where
    F: FnMut(&asm::Instruction, u64) -> Result<()>,
{
    let mut breakpoint_mgr = breakpoint::Manager::new(child);

    let mut startup_complete = false;
    let mut last_instruction: Option<asm::Instruction> = None;

    wait()?;
    // FIXME we need a better way to discard unsupported types and all
    // FIXME and this should somehow be hidden in the elf with the rest of the PIE logic...
    let offset = if context.elf.etype() == elf::header::ET_DYN {
        get_mem_range(child, context.path())?.start
    } else {
        0
    };

    breakpoint_mgr.set_breakpoint(context.elf.entry(offset))?;

    ptrace::cont(child, None)?;
    loop {
        let status = wait()?;
        match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                let mut regs = ptrace::getregs(child)?;
                breakpoint_mgr.handle_breakpoint(&mut regs)?;

                let rip = regs.rip;
                if let Some(opcode) =
                    context.elf.get_opcode_from_section(rip, ".text", offset)?
                {
                    let instruction =
                        context.parser.get_instruction_from(opcode, rip)?;
                    print(&instruction, offset - context.elf.load().unwrap_or(0))?; // FIXME avoid unwrap_or here..
                    last_instruction = Some(instruction);
                } else if let Some(instruction) = last_instruction.as_ref() {
                    if instruction.is_call() {
                        #[allow(clippy::cast_sign_loss)]
                        let ret =
                            ptrace::read(child, regs.rsp as ptrace::AddressType)?
                                as u64;

                        // Keep single stepping after the first call as it is
                        // likely to be part of the startup routine so it
                        // might never return.
                        //
                        // FIXME Not sure whether the code below is actually ran?]
                        //       Offset doesn't change anything...
                        if context.elf.is_addr_in_section(ret, ".text", offset)
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

/// # Errors
///
/// Will return `Err` upon `trace_with` failure.
pub fn trace_with_simple_print(context: &Tracer, child: Pid) -> Result<()> {
    trace_with(context, child, |instruction, offset| {
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

    /// # Errors
    ///
    /// Will return `Err` upon `trace_with` failure.
    pub fn trace(&mut self, context: &Tracer, child: Pid) -> Result<()> {
        let dwarf = Dwarf::build(context.elf())?;
        trace_with(context, child, |instruction, offset| {
            let addr = instruction.addr();
            if let Entry::Vacant(_) = self.cache.entry(addr) {
                let info = dwarf.addr2line(addr - offset)?;
                self.cache.insert(addr, info);
            }

            if let Some(line) = self
                .cache
                .get(&addr)
                .ok_or_else(|| Error::from(Errno::ENODATA))?
            {
                if Path::new(&line.path()).exists() { // FIXME really this way?
                    let key = (line.path(), line.line());
                    *self.coverage.entry(key).or_insert(0) += 1;
                    self.files.insert(line.path());
                    println!("{line}"); // FIXME this prints offset with PIE. should it?
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
