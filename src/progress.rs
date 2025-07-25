use nix::unistd::Pid;

use crate::{
    breakpoint,
    debug::{Dwarf, LineInfo},
    diag::Result,
    print::Layout,
};

/// Execution state for the tracer loop.
pub enum Execution {
    /// The tracer should stop and exit.
    Exit,
    /// The tracer should continue running.
    Run,
    /// The tracer should skip waiting for the child and process UI.
    Skip,
}

/// Tracing mode used to control stepping behavior.
pub enum Mode {
    /// Continue running until the next breakpoint.
    Continue,
    /// Step into the next instruction.
    StepInto,
    /// Step over the next instruction.
    StepOver,
    /// Internal state used while a step-over is in progress.
    StepOverInProgress,
}

/// Runtime state shared with progress callbacks and handlers.
pub struct State<'a> {
    pid: Pid,
    dwarf: Option<&'a Dwarf<'a>>,
    breakpoint_mgr: breakpoint::Manager,
    layout: Layout,
    requested_layout: Option<Layout>,
    execution: Execution,
    mode: Mode,
    prev_rip: Option<u64>,
    printed: Option<String>,
}

impl<'a> State<'a> {
    #[must_use]
    /// Create a new runtime `State` for the given `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The PID of the traced process.
    /// * `dwarf` - Optional DWARF info used for source lookups.
    ///
    /// # Returns
    ///
    /// A freshly-initialized `State` ready for tracing.
    pub fn new(pid: Pid, dwarf: Option<&'a Dwarf<'a>>) -> Self {
        Self {
            pid,
            dwarf,
            breakpoint_mgr: breakpoint::Manager::new(pid),
            layout: Layout::from(dwarf.is_some()),
            requested_layout: None,
            execution: Execution::Run,
            mode: Mode::StepInto,
            prev_rip: None,
            printed: None,
        }
    }

    #[must_use]
    /// Return the PID associated with this state.
    ///
    /// # Returns
    ///
    /// The `Pid` belonging to the traced process.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Resolve an address to DWARF line information when available.
    ///
    /// # Arguments
    ///
    /// * `addr` - The target runtime address to resolve.
    ///
    /// # Returns
    ///
    /// `Ok(Some(LineInfo))` when DWARF had a mapping, `Ok(None)` when no
    /// mapping is available.
    ///
    /// # Errors
    ///
    /// Returns `Err` if a DWARF lookup failure occurs during address resolution.
    pub fn addr2line(&self, addr: u64) -> Result<Option<LineInfo>> {
        self.dwarf.map_or(Ok(None), |dwarf| dwarf.addr2line(addr))
    }

    #[must_use]
    /// Return the initial layout computed from available DWARF.
    ///
    /// # Returns
    ///
    /// The initial `Layout` chosen based on whether DWARF is available.
    pub fn initial_layout(&self) -> Layout {
        Layout::from(self.dwarf.is_some())
    }

    #[must_use]
    /// Return the currently active layout.
    ///
    /// # Returns
    ///
    /// A reference to the current `Layout`.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Set the active layout.
    ///
    /// # Arguments
    ///
    /// * `layout` - The new `Layout` to activate.
    pub fn set_layout(&mut self, layout: Layout) {
        self.layout = layout;
    }

    /// Request a new layout which will be applied by the tracer loop.
    ///
    /// # Arguments
    ///
    /// * `layout` - The requested `Layout` which will be applied asynchronously by the tracer loop.
    pub fn set_requested_layout(&mut self, layout: Layout) {
        self.requested_layout = Some(layout);
    }

    #[must_use]
    /// Take and return any requested layout.
    ///
    /// # Returns
    ///
    /// `Some(Layout)` when a layout was requested, otherwise `None`.
    pub fn take_requested_layout(&mut self) -> Option<Layout> {
        self.requested_layout.take()
    }

    /// Mutable access to the breakpoint manager owned by the state.
    ///
    /// # Returns
    ///
    /// A mutable reference to the internal `breakpoint::Manager`.
    pub fn breakpoint_mgr(&mut self) -> &mut breakpoint::Manager {
        &mut self.breakpoint_mgr
    }

    /// Print the currently registered breakpoints to stdout.
    ///
    /// This function writes the breakpoint manager's display representation to stdout.
    pub fn print_breakpoints(&self) {
        println!("{}", self.breakpoint_mgr);
    }

    #[must_use]
    /// Return the previous RIP (if set).
    ///
    /// # Returns
    ///
    /// The previous `RIP` value if one has been recorded.
    pub fn prev_rip(&self) -> Option<u64> {
        self.prev_rip
    }

    /// Set the previous RIP value.
    ///
    /// # Arguments
    ///
    /// * `rip` - The RIP value to record as previous.
    pub fn set_prev_rip(&mut self, rip: u64) {
        self.prev_rip = Some(rip);
    }

    #[must_use]
    /// Return the last printed text (if any).
    ///
    /// # Returns
    ///
    /// An optional reference to the last printed string.
    pub fn printed(&self) -> Option<&String> {
        self.printed.as_ref()
    }

    /// Set the last printed text.
    ///
    /// # Arguments
    ///
    /// * `printed` - Optional string to record as the last printed text.
    pub fn set_printed(&mut self, printed: Option<String>) {
        self.printed = printed;
    }

    #[must_use]
    /// Return the current execution state.
    ///
    /// # Returns
    ///
    /// A reference to the `Execution` enum representing the current execution state.
    pub fn execution(&self) -> &Execution {
        &self.execution
    }

    /// Update the execution state.
    ///
    /// # Arguments
    ///
    /// * `execution` - The new `Execution` state to apply.
    pub fn set_execution(&mut self, execution: Execution) {
        self.execution = execution;
    }

    #[must_use]
    /// Return the current tracing mode.
    ///
    /// # Returns
    ///
    /// A reference to the current `Mode` used for tracing.
    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    /// Set the tracing mode.
    ///
    /// # Arguments
    ///
    /// * `mode` - The new `Mode` to set for tracing.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }
}

/// Progress callback signature used by the tracer loop.
///
/// The callback is invoked by the tracer loop to allow periodic UI updates
/// or other bookkeeping. Implementations receive a mutable reference to the
/// current `State` and may return an error to abort tracing.
///
/// # Arguments
///
/// * `&mut State` - Mutable reference to the tracer `State`.
///
/// # Returns
///
/// A `Result<()>` where `Ok(())` continues normal execution and `Err` aborts.
pub trait ProgressFn = FnMut(&mut State) -> Result<()>;

/// Default no-op progress function.
///
/// # Returns
///
/// Always returns `Ok(())`.
///
/// # Errors
///
/// This function never returns an error; it always returns `Ok(())`.
pub fn default(_: &mut State) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::unistd::Pid;

    #[test]
    fn test_state_initial_layout_and_pid() {
        let pid = Pid::from_raw(1234);
        let state: State = State::new(pid, None);
        assert_eq!(state.pid(), pid);
        assert_eq!(state.initial_layout(), *state.layout());
    }

    #[test]
    fn test_requested_layout_roundtrip() {
        let pid = Pid::from_raw(1);
        let mut state = State::new(pid, None);
        let orig = state.initial_layout();
        state.set_requested_layout(orig);
        let taken = state.take_requested_layout();
        assert!(taken.is_some());
        assert_eq!(taken.unwrap(), state.initial_layout());
    }
}
