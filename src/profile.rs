use nix::sys::{
    ptrace,
    signal::Signal,
    wait::{wait, WaitStatus},
};

use crate::{
    asm, breakpoint,
    diag::Result,
    print::{self, PrintFn},
    process,
    progress::{self, ProgressFn},
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
pub fn trace_with(
    context: &Tracer,
    process: &process::Info,
    src_available: bool,
    mut print: impl PrintFn,
    mut progress: impl ProgressFn,
) -> Result<i32> {
    let mut ret = 0;

    let child = process.pid();
    let mut breakpoint_mgr = breakpoint::Manager::new(child);

    let mut startup_complete = false;
    let mut state = progress::State::new(child, src_available);
    let mut last_instruction: Option<asm::Instruction> = None;

    breakpoint_mgr.set_breakpoint(*process.entry()?)?;

    ptrace::cont(child, None)?;
    loop {
        if state.running() {
            state.set_running(false);
            let status = wait()?;
            match status {
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    let mut regs = ptrace::getregs(child)?;
                    breakpoint_mgr.handle_breakpoint(&mut regs)?;

                    let rip = regs.rip;
                    if let Some(opcode) = process.get_opcode_from_addr(rip)? {
                        let instruction =
                            context.parser.get_instruction_from(opcode, rip)?;
                        if !print(&instruction, state.layout())? {
                            ptrace::step(child, None)?;
                            state.set_running(true);
                            continue;
                        }
                        last_instruction = Some(instruction);
                    } else if let Some(instruction) = last_instruction.as_ref() {
                        // The purpose of this scope is to prevent single stepping
                        // through libraries execution as a non-neglible amount of time
                        // is spent in those.

                        if instruction.is_call() {
                            #[allow(clippy::cast_sign_loss)]
                            let ret_addr = ptrace::read(
                                child,
                                regs.rsp as ptrace::AddressType,
                            )? as u64;

                            // Keep single stepping after the first call as it is
                            // likely to be part of the startup routine so it
                            // might never return.
                            if process.is_addr_in_section(ret_addr, ".text")
                                && startup_complete
                            {
                                breakpoint_mgr.set_breakpoint(ret_addr)?;
                                ptrace::cont(child, None)?;
                                state.set_running(true);
                                continue;
                            }
                            startup_complete = true;
                        }
                        last_instruction = None;
                    }

                    ptrace::step(child, None)?;
                    state.set_running(true);
                }
                WaitStatus::Stopped(_, signal) => {
                    ptrace::cont(child, signal)?;
                    state.set_running(true);
                }
                _ => {
                    if let Some(code) = terminated(status) {
                        ret = code;
                        break;
                    }
                }
            }
        }

        progress(last_instruction.as_ref(), &mut state)?;
        if state.layout_changed() {
            if let Some(instruction) = last_instruction.as_ref() {
                print(instruction, state.layout())?;
            }
        }

        if state.exiting() {
            break;
        }
    }

    Ok(ret)
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
pub fn trace_with_default_print(
    context: &Tracer,
    process: &process::Info,
) -> Result<i32> {
    trace_with(context, process, false, print::default, progress::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_new() {
        let path = "/path/to/file";
        let tracer = Tracer::new(path).expect("Failed to create Tracer instance");
        assert_eq!(tracer.path(), path);
    }
}
