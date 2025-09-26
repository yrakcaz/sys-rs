use core::fmt;

use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};

use crate::diag::Result;

/// Helpers for reading and writing register state of the traced process.
///
/// `Registers` stores a snapshot of the platform `user_regs_struct` for a
/// given `Pid` and provides convenience accessors. Currently this module
/// assumes `x86_64` register layout.
pub struct Registers {
    pid: Pid,
    regs: user_regs_struct,
}

impl Registers {
    /// Read the current register state for `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process id of the traced process to read registers from.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `ptrace::getregs` call fails.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `Registers` snapshot on success.
    pub fn read(pid: Pid) -> Result<Self> {
        Ok(Self {
            pid,
            regs: ptrace::getregs(pid)?,
        })
    }

    /// Write the locally-modified register state back to the tracee.
    ///
    /// # Errors
    ///
    /// Returns an error if `ptrace::setregs` fails.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    pub fn write(&self) -> Result<()> {
        ptrace::setregs(self.pid, self.regs)?;
        Ok(())
    }

    #[must_use]
    /// Instruction pointer (RIP).
    ///
    /// # Returns
    ///
    /// The current value of the instruction pointer (RIP) for the stored
    /// register snapshot.
    pub fn rip(&self) -> u64 {
        self.regs.rip
    }

    /// Set the instruction pointer.
    ///
    /// # Arguments
    ///
    /// * `value` - The new instruction pointer (RIP) value to store in the snapshot.
    pub fn set_rip(&mut self, value: u64) {
        self.regs.rip = value;
    }

    #[must_use]
    /// Stack pointer (RSP).
    ///
    /// # Returns
    ///
    /// The current value of the stack pointer (RSP).
    pub fn rsp(&self) -> u64 {
        self.regs.rsp
    }

    #[must_use]
    /// Return the RAX register value.
    ///
    /// # Returns
    ///
    /// The value of the `rax` register in the snapshot.
    pub fn rax(&self) -> u64 {
        self.regs.rax
    }

    #[must_use]
    /// Return the original RAX value saved by the kernel (useful for syscalls).
    ///
    /// # Returns
    ///
    /// The `orig_rax` register value recorded by the kernel.
    pub fn orig_rax(&self) -> u64 {
        self.regs.orig_rax
    }

    #[must_use]
    /// Return the 6 register parameters passed in registers for `x86_64`
    /// (rdi, rsi, rdx, r10, r8, r9).
    ///
    /// # Returns
    ///
    /// An array with the six parameter registers as u64 in calling
    /// convention order.
    pub fn function_params(&self) -> [u64; 6] {
        [
            self.regs.rdi,
            self.regs.rsi,
            self.regs.rdx,
            self.regs.r10,
            self.regs.r8,
            self.regs.r9,
        ]
    }
}

impl fmt::Display for Registers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "rip: {:#x}", self.regs.rip)?;
        writeln!(f, "rsp: {:#x}", self.regs.rsp)?;
        writeln!(f, "rbp: {:#x}", self.regs.rbp)?;
        writeln!(f, "eflags: {:#x}", self.regs.eflags)?;
        writeln!(f, "orig_rax: {:#x}", self.regs.orig_rax)?;
        writeln!(f, "rax: {:#x}", self.regs.rax)?;
        writeln!(f, "rbx: {:#x}", self.regs.rbx)?;
        writeln!(f, "rcx: {:#x}", self.regs.rcx)?;
        writeln!(f, "rdx: {:#x}", self.regs.rdx)?;
        writeln!(f, "rdi: {:#x}", self.regs.rdi)?;
        writeln!(f, "rsi: {:#x}", self.regs.rsi)?;
        writeln!(f, "r8: {:#x}", self.regs.r8)?;
        writeln!(f, "r9: {:#x}", self.regs.r9)?;
        writeln!(f, "r10: {:#x}", self.regs.r10)?;
        writeln!(f, "r11: {:#x}", self.regs.r11)?;
        writeln!(f, "r12: {:#x}", self.regs.r12)?;
        writeln!(f, "r13: {:#x}", self.regs.r13)?;
        writeln!(f, "r14: {:#x}", self.regs.r14)?;
        writeln!(f, "r15: {:#x}", self.regs.r15)?;
        writeln!(f, "cs: {:#x}", self.regs.cs)?;
        writeln!(f, "ds: {:#x}", self.regs.ds)?;
        writeln!(f, "es: {:#x}", self.regs.es)?;
        writeln!(f, "fs: {:#x}", self.regs.fs)?;
        writeln!(f, "gs: {:#x}", self.regs.gs)?;
        writeln!(f, "ss: {:#x}", self.regs.ss)?;
        writeln!(f, "fs_base: {:#x}", self.regs.fs_base)?;
        write!(f, "gs_base: {:#x}", self.regs.gs_base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::user_regs_struct;
    use nix::unistd::Pid;

    fn make_regs() -> user_regs_struct {
        user_regs_struct {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0x2000,
            rbx: 0x3000,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 1,
            rcx: 2,
            rdx: 3,
            rsi: 4,
            rdi: 5,
            orig_rax: 0,
            rip: 0x1000,
            cs: 0,
            eflags: 0,
            rsp: 0x4000,
            ss: 0,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }

    #[test]
    fn test_registers_accessors_and_display() {
        let regs = make_regs();
        let r = Registers {
            pid: Pid::from_raw(1),
            regs,
        };
        assert_eq!(r.rip(), 0x1000);
        assert_eq!(r.rsp(), 0x4000);
        assert_eq!(r.rax(), 1);
        assert_eq!(r.function_params()[0], 5);

        let s = format!("{}", r);
        assert!(s.contains("rip:"));
        assert!(s.contains("rsp:"));
    }
}
