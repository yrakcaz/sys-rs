use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};
use std::collections::HashMap;

use crate::diag::Result;

pub struct Manager {
    pid: Pid,
    breakpoints: HashMap<u64, i64>,
}

impl Manager {
    #[must_use]
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            breakpoints: HashMap::new(),
        }
    }

    /// # Errors
    ///
    /// Will return `Err` upon ptrace failure.
    pub fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        let instruction = ptrace::read(self.pid, addr as ptrace::AddressType)?;
        let breakpoint = (instruction & !0xff) | 0xcc;
        unsafe {
            ptrace::write(
                self.pid,
                addr as ptrace::AddressType,
                breakpoint as *mut _,
            )
        }?;

        self.breakpoints.insert(addr, instruction);
        Ok(())
    }

    /// # Errors
    ///
    /// Will return `Err` upon ptrace failure.
    pub fn handle_breakpoint(&mut self, regs: &mut user_regs_struct) -> Result<()> {
        let addr = regs.rip - 1;
        if let Some(instruction) = self.breakpoints.remove(&addr) {
            unsafe {
                ptrace::write(
                    self.pid,
                    addr as ptrace::AddressType,
                    instruction as *mut _,
                )
            }?;

            regs.rip = addr;
            ptrace::setregs(self.pid, *regs)?;
        }

        Ok(())
    }
}
