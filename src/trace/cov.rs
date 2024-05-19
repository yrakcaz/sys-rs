use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::Pid,
};
use std::collections::{hash_map::Entry, HashMap, HashSet};

use crate::{
    asm, breakpoint,
    diag::{Error, Result},
    exec::{
        debug::{line, Dwarf},
        Elf,
    },
    trace::terminated,
};

pub struct Tracer {
    elf: Elf,
    parser: asm::Parser,
}

impl Tracer {
    /// # Errors
    ///
    /// Will return `Err` upon failure to build `exec::Elf` or `asm::Parser`.
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            elf: Elf::build(path)?,
            parser: asm::Parser::new()?,
        })
    }

    #[must_use]
    pub fn elf(&self) -> &Elf {
        &self.elf
    }
}

/// # Errors
///
/// Will return `Err` upon any failure related to parsing ELF or DWARF format,
/// as well as issues related to syscalls usage (e.g. ptrace, wait).
fn trace_with<F>(context: &Tracer, child: Pid, mut print: F) -> Result<()>
where
    F: FnMut(&asm::instruction::Wrapper) -> Result<()>,
{
    let mut breakpoint_mgr = breakpoint::Manager::new(child);

    let mut startup_complete = false;
    let mut last_instruction: Option<asm::instruction::Wrapper> = None;

    wait()?;
    breakpoint_mgr.set_breakpoint(context.elf.entry())?;

    ptrace::cont(child, None)?;
    loop {
        let status = wait()?;
        match status {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                let mut regs = ptrace::getregs(child)?;
                breakpoint_mgr.handle_breakpoint(&mut regs)?;

                let rip = regs.rip;
                if let Some(opcode) =
                    context.elf.get_opcode_from_section(rip, ".text")?
                {
                    let instruction =
                        context.parser.get_instruction_from(opcode, rip)?;
                    print(&instruction)?;
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
                        if context.elf.is_addr_in_section(ret, ".text")
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

pub fn trace_with_basic_print(context: &Tracer, child: Pid) -> Result<()> {
    trace_with(context, child, |instruction| {
        println!("{instruction}");
        Ok(())
    })
}

pub struct Cached {
    cache: HashMap<u64, Option<line::Info>>,
    coverage: HashMap<(String, usize), usize>,
    files: HashSet<String>,
}

impl Cached {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            coverage: HashMap::new(),
            files: HashSet::new(),
        }
    }

    pub fn coverage(&self, path: String, line: usize) -> Option<&usize> {
        let key = (path, line);
        self.coverage.get(&key)
    }

    pub fn files(&self) -> &HashSet<String> {
        &self.files
    }

    pub fn trace(
        &mut self,
        context: &Tracer,
        child: Pid,
    ) -> Result<()> {
        let dwarf = Dwarf::build(context.elf())?;
        trace_with(&context, child, |instruction| {
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
                let key = (line.path(), line.line());
                *self.coverage.entry(key).or_insert(0) += 1;
                self.files.insert(line.path());
                println!("{line}");
            }

            Ok(())
        })
    }
}
