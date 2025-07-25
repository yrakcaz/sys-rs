use nix::unistd::Pid;

use crate::{asm::Instruction, diag::Result, print::Layout};

pub struct State {
    pid: Pid,
    initial_layout: Layout,
    layout: Layout,
    layout_changed: bool,
    running: bool,
    exiting: bool,
}

impl State {
    pub fn new(pid: Pid, src_available: bool) -> Self {
        Self {
            pid,
            initial_layout: Layout::from(src_available),
            layout: Layout::from(src_available),
            layout_changed: false,
            running: true,
            exiting: false,
        }
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn initial_layout(&self) -> &Layout {
        &self.initial_layout
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn set_layout(&mut self, layout: Layout) {
        self.layout_changed = self.layout != layout;
        self.layout = layout;
    }

    pub fn layout_changed(&mut self) -> bool {
        let ret = self.layout_changed;
        self.layout_changed = false;
        ret
    }

    pub fn running(&self) -> bool {
        self.running
    }

    pub fn set_running(&mut self, value: bool) {
        self.running = value;
    }

    pub fn exiting(&self) -> bool {
        self.exiting
    }

    pub fn set_exiting(&mut self) {
        self.exiting = true;
    }
}

pub trait ProgressFn = FnMut(Option<&Instruction>, &mut State) -> Result<()>;

pub fn default(_: Option<&Instruction>, _: &mut State) -> Result<()> {
    Ok(())
}
