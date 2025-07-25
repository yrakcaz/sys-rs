use core::fmt;

use libc::user_regs_struct;
use nix::{sys::ptrace, unistd::Pid};

use crate::diag::Result;

// FIXME we currently only support x86_64, make sure this is clear in README, TODO and all..

pub struct Registers {
    pid: Pid,
    regs: user_regs_struct,
}

impl Registers {
    pub fn read(pid: Pid) -> Result<Self> {
        Ok(Self {
            pid,
            regs: ptrace::getregs(pid)?,
        })
    }

    pub fn write(&self) -> Result<()> {
        ptrace::setregs(self.pid, self.regs)?;
        Ok(())
    }

    pub fn rip(&self) -> u64 {
        self.regs.rip
    }

    pub fn set_rip(&mut self, value: u64) {
        self.regs.rip = value;
    }

    pub fn rsp(&self) -> u64 {
        self.regs.rsp
    }

    pub fn rax(&self) -> u64 {
        self.regs.rax
    }

    pub fn orig_rax(&self) -> u64 {
        self.regs.orig_rax
    }

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
        writeln!(f, "rip: 0x{:x}", self.regs.rip)?;
        writeln!(f, "rsp: 0x{:x}", self.regs.rsp)?;
        writeln!(f, "rbp: 0x{:x}", self.regs.rbp)?;
        writeln!(f, "eflags: 0x{:x}", self.regs.eflags)?;
        writeln!(f, "orig_rax: 0x{:x}", self.regs.orig_rax)?;
        writeln!(f, "rax: 0x{:x}", self.regs.rax)?;
        writeln!(f, "rbx: 0x{:x}", self.regs.rbx)?;
        writeln!(f, "rcx: 0x{:x}", self.regs.rcx)?;
        writeln!(f, "rdx: 0x{:x}", self.regs.rdx)?;
        writeln!(f, "rdi: 0x{:x}", self.regs.rdi)?;
        writeln!(f, "rsi: 0x{:x}", self.regs.rsi)?;
        writeln!(f, "r8: 0x{:x}", self.regs.r8)?;
        writeln!(f, "r9: 0x{:x}", self.regs.r9)?;
        writeln!(f, "r10: 0x{:x}", self.regs.r10)?;
        writeln!(f, "r11: 0x{:x}", self.regs.r11)?;
        writeln!(f, "r12: 0x{:x}", self.regs.r12)?;
        writeln!(f, "r13: 0x{:x}", self.regs.r13)?;
        writeln!(f, "r14: 0x{:x}", self.regs.r14)?;
        writeln!(f, "r15: 0x{:x}", self.regs.r15)?;
        writeln!(f, "cs: 0x{:x}", self.regs.cs)?;
        writeln!(f, "ds: 0x{:x}", self.regs.ds)?;
        writeln!(f, "es: 0x{:x}", self.regs.es)?;
        writeln!(f, "fs: 0x{:x}", self.regs.fs)?;
        writeln!(f, "gs: 0x{:x}", self.regs.gs)?;
        writeln!(f, "ss: 0x{:x}", self.regs.ss)?;
        writeln!(f, "fs_base: 0x{:x}", self.regs.fs_base)?;
        write!(f, "gs_base: 0x{:x}", self.regs.gs_base)
    }
}
