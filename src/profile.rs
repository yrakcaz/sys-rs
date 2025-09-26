use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

use crate::{
    asm,
    diag::Result,
    hwaccess::Registers,
    print::{self, PrintFn},
    process,
    progress::{self, Execution, Mode, ProgressFn, State},
    trace::terminated,
};

/// Holds resources needed to parse and trace a target binary.
///
/// `Tracer` owns the path to the traced executable and an `asm::Parser`
/// used to decode instructions from raw bytes.
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
    /// Return the path to the traced executable as a `&str`.
    ///
    /// # Returns
    ///
    /// A `&str` reference to the stored path of the traced executable.
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn init_tracer(process: &process::Info, state: &mut State, pid: Pid) -> Result<()> {
    state
        .breakpoint_mgr()
        .set_breakpoint(*process.entry()?, true, false, None)?;
    ptrace::cont(pid, None)?;

    Ok(())
}

fn handle_mode(
    process: &process::Info,
    state: &mut State,
    pid: Pid,
) -> Result<bool> {
    match state.mode() {
        Mode::Continue => {
            state.set_mode(Mode::StepInto);
            ptrace::cont(pid, None)?;
            println!("Continuing");
            Ok(true)
        }
        Mode::StepOverInProgress => {
            state.set_mode(Mode::StepInto);
            skip_func(process, state, pid)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn handle_step_over(instr: &asm::Instruction, state: &mut State) -> bool {
    let mut ret = false;

    if let Mode::StepOver = state.mode() {
        if instr.is_call() {
            state.set_execution(Execution::Run);
            state.set_mode(Mode::StepOverInProgress);
            ret = true;
        } else {
            state.set_mode(Mode::StepInto);
        }
    }

    ret
}

fn handle_sigtrap(
    context: &Tracer,
    process: &process::Info,
    state: &mut State,
    pid: Pid,
    last_instr: &mut Option<asm::Instruction>,
    startup_complete: &mut bool,
    print: &mut impl PrintFn,
) -> Result<bool> {
    let mut regs = Registers::read(pid)?;
    if let Some(bp) = state.breakpoint_mgr().handle_breakpoint(&mut regs)? {
        let addr = bp.address();
        if state
            .breakpoint_mgr()
            .set_breakpoint(addr, false, true, bp.id())
            .is_err()
        {
            eprintln!("Failed to set breakpoint at address {addr:#x}");
        }
    }

    let rip = regs.rip();
    let mut ret = false;

    if let Some(opcode) = process.get_opcode_from_addr(rip)? {
        let instr = context.parser.get_instruction_from(opcode, rip)?;
        state.set_printed(print(&instr, state.layout())?);
        state.set_prev_rip(rip);
        *last_instr = Some(instr);
    } else if let Some(instr) = last_instr.as_ref() {
        // The purpose of this scope is to prevent single stepping through libraries
        // execution as a non-neglible amount of time is spent in those.
        if instr.is_call() {
            // Keep single stepping after the first call as it is likely to be part
            // of the startup routine so it might never return.
            if *startup_complete {
                skip_func(process, state, pid)?;
                ret = true;
            } else {
                *startup_complete = true;
            }
        }

        if !ret {
            *last_instr = None;
        }
    }

    if !ret {
        state.breakpoint_mgr().save_breakpoint(rip)?;
        ptrace::step(pid, None)?;
        state.set_execution(Execution::Run);
    }

    Ok(ret)
}

fn do_progress_ui(
    instr: &asm::Instruction,
    state: &mut State,
    print: &mut impl PrintFn,
    progress: &mut impl ProgressFn,
) -> Result<()> {
    progress(state)?;

    if let Some(layout) = state.take_requested_layout() {
        state.set_layout(layout);
        if let Some(line) = print(instr, state.layout())? {
            state.set_printed(Some(line));
        }
    }

    Ok(())
}

fn skip_func(process: &process::Info, state: &mut State, pid: Pid) -> Result<()> {
    let regs = Registers::read(pid)?;
    let ret_addr =
        u64::try_from(ptrace::read(pid, regs.rsp() as ptrace::AddressType)?)?;

    if process.is_addr_in_section(ret_addr, ".text") {
        state
            .breakpoint_mgr()
            .set_breakpoint(ret_addr, true, false, None)?;
        ptrace::cont(pid, None)?;
        state.set_execution(Execution::Run);
    }

    Ok(())
}

/// Traces the execution of a process and prints the instructions being executed.
///
/// This function owns the tracer loop: it drives the traced child using
/// ptrace, restores and manages breakpoints, decodes instructions with the
/// provided `Tracer`, and uses the supplied `print` and `progress` callbacks
/// to render output and update the tracing UI.
///
/// # Arguments
///
/// * `context` - The `Tracer` instance used to decode instructions and hold
///   tracer-local resources (e.g., an `asm::Parser`).
/// * `process` - The `process::Info` describing the traced process (provides
///   PID, sections, entry point, etc.).
/// * `state` - A `progress::State` instance which holds runtime tracing state
///   such as breakpoints, layout, and execution mode.
/// * `print` - A printing callback used to render a single `asm::Instruction`.
/// * `progress` - A progress/update callback invoked each trace iteration to
///   update UI state and possibly change tracing behavior.
///
/// # Errors
///
/// Returns an `Err` if any underlying operation fails: ELF/DWARF parsing,
/// ptrace/syscall errors, register reads/writes, or instruction decoding.
///
/// # Returns
///
/// Returns `Ok(exit_code)` where `exit_code` is the child's exit status when
/// tracing finishes, or an `Err` on failure.
pub fn trace_with(
    context: &Tracer,
    process: &process::Info,
    state: State,
    mut print: impl PrintFn,
    mut progress: impl ProgressFn,
) -> Result<i32> {
    let pid = process.pid();
    let mut state = state;

    let mut ret = 0;
    let mut startup_complete = false;
    let mut last_instr: Option<asm::Instruction> = None;

    init_tracer(process, &mut state, pid)?;

    loop {
        if let Execution::Run = state.execution() {
            let status = waitpid(pid, None)?;
            state.breakpoint_mgr().restore_breakpoint()?;

            if handle_mode(process, &mut state, pid)? {
                continue;
            }

            if let Some(code) = terminated(status) {
                ret = code;
                break;
            }

            match status {
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    if handle_sigtrap(
                        context,
                        process,
                        &mut state,
                        pid,
                        &mut last_instr,
                        &mut startup_complete,
                        &mut print,
                    )? {
                        continue;
                    }
                }
                WaitStatus::Stopped(_, signal) => {
                    ptrace::cont(pid, signal)?;
                    state.set_execution(Execution::Run);
                }
                _ => {}
            }
        }

        let Some(instr) = last_instr.as_ref() else {
            continue;
        };

        if handle_step_over(instr, &mut state) {
            continue;
        }

        if state.printed().is_some() {
            do_progress_ui(instr, &mut state, &mut print, &mut progress)?;
        }

        if let Execution::Exit = state.execution() {
            break;
        }
    }

    Ok(ret)
}

/// Convenience wrapper around `trace_with` that uses the default print and
/// progress callbacks.
///
/// This function allocates a fresh `progress::State` and then calls
/// `trace_with` with `print::default` and `progress::default` to perform the
/// trace.
///
/// # Arguments
///
/// * `context` - The `Tracer` used to decode instructions.
/// * `process` - The traced `process::Info` describing the child process.
///
/// # Returns
///
/// `Ok(exit_code)` where `exit_code` is the child's exit status when tracing finishes, or `Err` on failure.
///
/// # Errors
///
/// Returns an `Err` if any underlying operation fails, such as ELF/DWARF parsing,
/// ptrace/syscall errors, register reads/writes, or instruction decoding.
pub fn trace_with_default_print(
    context: &Tracer,
    process: &process::Info,
) -> Result<i32> {
    let state = State::new(process.pid(), None);
    trace_with(context, process, state, print::default, progress::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::unistd::Pid;

    use crate::{asm::Parser, print::Layout};

    #[test]
    fn test_tracer_new() {
        let path = "/path/to/file";
        let tracer = Tracer::new(path).expect("Failed to create Tracer instance");
        assert_eq!(tracer.path(), path);
    }

    #[test]
    fn test_handle_step_over_call_and_noncall() {
        let parser = Parser::new().expect("parser");
        let opcode_call: [u8; 5] = [0xe8, 0x05, 0x00, 0x00, 0x00];
        let call_inst = parser.get_instruction_from(&opcode_call, 0x1000).unwrap();

        let opcode_nop: [u8; 1] = [0x90];
        let nop_inst = parser.get_instruction_from(&opcode_nop, 0x2000).unwrap();

        let mut state = progress::State::new(Pid::from_raw(1), None);
        state.set_mode(progress::Mode::StepOver);

        let ret = handle_step_over(&call_inst, &mut state);
        assert!(ret);
        assert!(matches!(state.execution(), progress::Execution::Run));
        assert!(matches!(state.mode(), progress::Mode::StepOverInProgress));

        state.set_mode(progress::Mode::StepOver);
        let ret = handle_step_over(&nop_inst, &mut state);
        assert!(!ret);
        assert!(matches!(state.mode(), progress::Mode::StepInto));
    }

    #[test]
    fn test_do_progress_ui_applies_requested_layout_and_records_print() {
        let parser = Parser::new().expect("parser");
        let opcode_call: [u8; 5] = [0xe8, 0x05, 0x00, 0x00, 0x00];
        let inst = parser.get_instruction_from(&opcode_call, 0x1000).unwrap();

        let mut state = progress::State::new(Pid::from_raw(1), None);
        state.set_requested_layout(Layout::Source);

        let mut progress_called = false;
        let mut print = |_: &asm::Instruction,
                         _layout: &print::Layout|
         -> crate::diag::Result<Option<String>> {
            Ok(Some("printed line".to_string()))
        };

        let mut progress_fn = |_s: &mut State| -> crate::diag::Result<()> {
            progress_called = true;
            Ok(())
        };

        do_progress_ui(&inst, &mut state, &mut print, &mut progress_fn)
            .expect("do_progress_ui failed");

        assert!(progress_called);
        assert!(state.printed().is_some());
        assert_eq!(state.printed().unwrap(), "printed line");
        assert!(matches!(state.layout(), print::Layout::Source));
    }
}
