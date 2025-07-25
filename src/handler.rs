use libunwind_rs::{Accessors, AddressSpace, Byteorder, Cursor, PtraceState};
use nix::{errno::Errno, sys::ptrace};
use std::fs::read_to_string;

use crate::{
    diag::{Error, Result},
    hwaccess::Registers,
    param::{Join, Value},
    print::Layout,
    progress::{Execution, Mode, State},
};

/// Type of a command handler function.
///
/// A `CommandFn` is a function that receives the parsed argument list and
/// a mutable reference to the current `progress::State` and returns a
/// `Result` indicating success or failure.
pub type CommandFn = fn(&[Value], &mut State) -> Result<()>;

fn exit_with(args: &[Value], state: &mut State, f: CommandFn) -> Result<()> {
    f(args, state)?;
    state.set_execution(Execution::Exit);
    Ok(())
}

fn proceed_with(args: &[Value], state: &mut State, f: CommandFn) -> Result<()> {
    f(args, state)?;
    state.set_execution(Execution::Run);
    Ok(())
}

fn stall_with(args: &[Value], state: &mut State, f: CommandFn) -> Result<()> {
    f(args, state)?;
    state.set_execution(Execution::Skip);
    Ok(())
}

fn do_breakpoint_common(
    args: &[Value],
    state: &mut State,
    temporary: bool,
) -> Result<()> {
    let addr = match args {
        [Value::Address(addr)] => Ok(*addr),
        [] => state.prev_rip().ok_or_else(|| Error::from(Errno::ENODATA)),
        _ => Err(Error::from(Errno::EINVAL)),
    }?;

    if let Ok(id) = state
        .breakpoint_mgr()
        .set_breakpoint(addr, temporary, true, None)
    {
        let id = id.ok_or_else(|| Error::from(Errno::ENODATA))?;
        let bp_type = if temporary { "Temporary" } else { "Permanent" };
        println!("{bp_type} breakpoint #{id} set at address {addr:#x}");
    } else {
        eprintln!("Failed to set breakpoint at address {addr:#x}");
    }

    Ok(())
}

/// Handler for ambiguous commands (user input matches multiple commands).
///
/// Prints an error message indicating the command was ambiguous and does
/// not change execution state.
///
/// # Errors
///
/// Returns an error if the underlying printing operation fails (rare).
pub fn do_ambiguous(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, _| {
        eprintln!("{}: ambiguous command", args.join(" "));
        Ok(())
    })
}

/// Handler that prints a backtrace for the traced process.
///
/// Uses libunwind via ptrace to walk the tracee's stack and prints each
/// frame. When DWARF line information is available it will include file and
/// line information.
///
/// # Errors
///
/// Returns an error if libunwind/ptrace operations fail or if address
/// -> line resolution fails.
pub fn do_backtrace(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        let pstate = PtraceState::new(u32::try_from(state.pid().as_raw())?)?;
        let mut aspace = AddressSpace::new(Accessors::ptrace(), Byteorder::Default)?;
        let mut cursor = Cursor::ptrace(&mut aspace, &pstate)?;

        let mut i = 0;
        loop {
            let ip = cursor.ip()?;
            let name = cursor
                .proc_name()
                .unwrap_or_else(|_| "<unknown>".to_string());

            let frame = format!("#{i} {ip:#018x} in {name} ()");
            match state.addr2line(u64::try_from(ip)?)? {
                Some(line) => println!("{frame} at {}:{}", line.path(), line.line()),
                None => println!("{frame}"),
            }

            if !cursor.step()? {
                break;
            }

            i += 1;
        }

        Ok(())
    })
}

/// Set a permanent breakpoint at the given address or the previous RIP.
///
/// # Errors
///
/// Returns an error if argument parsing fails or if setting the
/// breakpoint via the breakpoint manager fails.
pub fn do_breakpoint(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, state| {
        do_breakpoint_common(args, state, false)
    })
}

/// Continue execution of the traced process.
///
/// Transitions the tracer into `Continue` mode and resumes execution.
///
/// # Errors
///
/// Returns an error if state update fails (rare).
pub fn do_continue(args: &[Value], state: &mut State) -> Result<()> {
    proceed_with(args, state, |_, state| {
        state.set_mode(Mode::Continue);
        Ok(())
    })
}

/// Delete a breakpoint by id.
///
/// # Errors
///
/// Returns an error if arguments are invalid or deletion fails.
pub fn do_delete(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, state| match args {
        [Value::Id(id)] => {
            if state.breakpoint_mgr().delete_breakpoint(*id).is_err() {
                eprintln!("No breakpoint number {id}");
            }
            Ok(())
        }
        _ => Err(Error::from(Errno::EINVAL)),
    })
}

/// Examine memory at a given address and format the bytes.
///
/// # Errors
///
/// Returns an error if arguments are invalid, memory cannot be read, or formatting fails.
pub fn do_examine(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, state| match args {
        [Value::Format(format), Value::Size(size), Value::Address(addr)] => {
            let word_size = std::mem::size_of::<usize>();
            let mut buf = vec![0u8; usize::try_from(*size)?];
            let mut offset = 0;

            while offset < buf.len() {
                let read_addr = *addr + offset as u64;
                let word = if let Ok(val) =
                    ptrace::read(state.pid(), read_addr as ptrace::AddressType)
                {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss
                    )]
                    let ret = val as usize;
                    ret
                } else {
                    eprintln!("Failed to read memory at {read_addr:#x}");
                    break;
                };

                for i in 0..word_size {
                    if offset >= buf.len() {
                        break;
                    }
                    buf[offset] = u8::try_from((word >> (i * 8)) & 0xff)?;
                    offset += 1;
                }
            }

            format.bytes(&buf, *addr)
        }
        _ => Err(Error::from(Errno::EINVAL)),
    })
}

/// Print help text for available commands.
///
/// Accepts a list of strings to print; used by the REPL to display help.
///
/// # Errors
///
/// Returns an error if printing fails.
pub fn do_help(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, _| {
        println!("{}", args.join("\n"));
        Ok(())
    })
}

/// Print information about currently set breakpoints.
///
/// # Errors
///
/// Returns an error if state access fails (rare).
pub fn do_info_breakpoints(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        state.print_breakpoints();
        Ok(())
    })
}

/// Print the memory map (`/proc/PID/maps`) of the traced process.
///
/// # Errors
///
/// Returns an error if reading `/proc/PID/maps` fails.
pub fn do_info_memory(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        print!("{}", read_to_string(format!("/proc/{}/maps", state.pid()))?);
        Ok(())
    })
}

/// Print the current register state of the traced process.
///
/// # Errors
///
/// Returns an error if reading registers via ptrace fails.
pub fn do_info_registers(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        let regs = Registers::read(state.pid())?;
        println!("{regs}");
        Ok(())
    })
}

/// Handler for invalid argument errors.
///
/// Prints an error indicating the provided arguments were invalid.
///
/// # Errors
///
/// Returns an error if printing fails.
pub fn do_invalid_arguments(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, _| {
        eprintln!("{}: invalid arguments", args.join(" "));
        Ok(())
    })
}

/// Switch the display layout to assembly mode.
///
/// If already in assembly layout, prints a message and does nothing.
///
/// # Errors
///
/// Returns an error on I/O failure while printing (unlikely).
pub fn do_layout_asm(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        if *state.layout() == Layout::Assembly {
            eprintln!("Already in assembly layout mode");
        } else {
            println!("Switching to assembly layout mode");
            state.set_requested_layout(Layout::Assembly);
        }
        Ok(())
    })
}

/// Switch the display layout to source mode (when available).
///
/// If no source layout is available or already in source mode, prints a
/// message accordingly.
///
/// # Errors
///
/// Returns an error if printing fails.
pub fn do_layout_src(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        if state.initial_layout() == Layout::Assembly {
            eprintln!("No source layout available (DWARF symbols missing?)");
        } else if *state.layout() == Layout::Source {
            eprintln!("Already in source layout mode");
        } else {
            println!("Switching to source layout mode");
            state.set_requested_layout(Layout::Source);
        }
        Ok(())
    })
}

/// Re-print the last printed source or assembly chunk.
///
/// Useful after stepping when the REPL wants to show the previously
/// displayed context again.
///
/// # Errors
///
/// Returns an error if printing fails.
pub fn do_list(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        if let Some(text) = state.printed() {
            println!("{text}");
        }
        Ok(())
    })
}

/// Step over the next instruction (implement stepping semantics).
///
/// Transitions the tracer into `StepOver` mode.
///
/// # Errors
///
/// Returns an error if state update fails.
pub fn do_next(args: &[Value], state: &mut State) -> Result<()> {
    proceed_with(args, state, |_, state| {
        state.set_mode(Mode::StepOver);
        Ok(())
    })
}

/// A no-op handler that does nothing and stalls execution.
///
/// # Errors
///
/// Never returns an error.
pub fn do_nothing(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, _| Ok(()))
}

/// Quit the debugger and exit the tracer loop.
///
/// Marks the execution state as Exit and prints a message.
///
/// # Errors
///
/// Returns an error if the underlying exit action fails (unlikely).
pub fn do_quit(args: &[Value], state: &mut State) -> Result<()> {
    exit_with(args, state, |_, _| {
        println!("Exiting...");
        Ok(())
    })
}

/// Step a single instruction (single-step execution).
///
/// # Errors
///
/// Returns an error if state update fails.
pub fn do_step(args: &[Value], state: &mut State) -> Result<()> {
    proceed_with(args, state, |_, _| Ok(()))
}

/// Set a temporary breakpoint at the given address or previous RIP.
///
/// Temporary breakpoints are removed after they are hit.
///
/// # Errors
///
/// Returns an error if argument parsing or breakpoint insertion fails.
pub fn do_tbreakpoint(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, state| {
        do_breakpoint_common(args, state, true)
    })
}

/// Handler for completely unknown commands.
///
/// Prints an error message indicating the command is unknown.
///
/// # Errors
///
/// Returns an error if printing fails.
pub fn do_unknown(args: &[Value], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, _| {
        eprintln!("{}: unknown command", args.join(" "));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::unistd::Pid;

    use crate::{
        param::Value,
        print::Layout,
        progress::{Execution, State},
    };

    #[test]
    fn test_do_help_sets_skip() {
        let mut state = State::new(Pid::from_raw(1), None);
        let cmds: Vec<Value> = vec![Value::String("one"), Value::String("two")];
        let res = do_help(&cmds, &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Skip));
    }

    #[test]
    fn test_do_invalid_arguments_sets_skip() {
        let mut state = State::new(Pid::from_raw(1), None);
        let args: Vec<Value> = vec![Value::String("bad")];
        let res = do_invalid_arguments(&args, &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Skip));
    }

    #[test]
    fn test_do_nothing_sets_skip() {
        let mut state = State::new(Pid::from_raw(1), None);
        let res = do_nothing(&[], &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Skip));
    }

    #[test]
    fn test_do_layout_asm_switches_when_not_assembly() {
        let mut state = State::new(Pid::from_raw(1), None);
        state.set_layout(Layout::Source);
        let res = do_layout_asm(&[], &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Skip));
        let taken = state.take_requested_layout();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap(), Layout::Assembly);
    }

    #[test]
    fn test_do_layout_src_no_source_available() {
        let mut state = State::new(Pid::from_raw(1), None);
        let res = do_layout_src(&[], &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Skip));
        assert!(state.take_requested_layout().is_none());
    }

    #[test]
    fn test_do_continue_next_step_quit() {
        let mut state = State::new(Pid::from_raw(1), None);

        let res = do_continue(&[], &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Run));
        assert!(matches!(state.mode(), crate::progress::Mode::Continue));

        let mut state2 = State::new(Pid::from_raw(1), None);
        let res = do_next(&[], &mut state2);
        assert!(res.is_ok());
        assert!(matches!(state2.execution(), Execution::Run));
        assert!(matches!(state2.mode(), crate::progress::Mode::StepOver));

        let mut state3 = State::new(Pid::from_raw(1), None);
        let res = do_step(&[], &mut state3);
        assert!(res.is_ok());
        assert!(matches!(state3.execution(), Execution::Run));

        let mut state4 = State::new(Pid::from_raw(1), None);
        let res = do_quit(&[], &mut state4);
        assert!(res.is_ok());
        assert!(matches!(state4.execution(), Execution::Exit));
    }

    #[test]
    fn test_do_list_printed() {
        let mut state = State::new(Pid::from_raw(1), None);
        state.set_printed(Some("hello".to_string()));
        let res = do_list(&[], &mut state);
        assert!(res.is_ok());
        assert!(matches!(state.execution(), Execution::Skip));
    }
}
