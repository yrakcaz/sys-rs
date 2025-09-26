use libc::c_long;
use nix::{errno::Errno, sys::ptrace, unistd::Pid};
use std::{collections::HashMap, fmt, mem::size_of};

use crate::{
    diag::{Error, Result},
    hwaccess::Registers,
};

const INT3: u8 = 0xcc;

fn set_byte_in_word(word: c_long, offset: usize, byte: u8) -> c_long {
    #[allow(clippy::cast_sign_loss)]
    let mut w = word as u64;
    let shift = offset * 8;

    w &= !(0xffu64 << shift);
    w |= u64::from(byte) << shift;

    #[allow(clippy::cast_possible_wrap)]
    let ret = w as c_long;

    ret
}

struct Active {
    id: Option<u64>,
    byte: u8,
    temporary: bool,
}

impl Active {
    fn new(id: Option<u64>, byte: u8, temporary: bool) -> Self {
        Self {
            id,
            byte,
            temporary,
        }
    }

    fn restore_byte(&self, pid: Pid, addr: u64) -> Result<()> {
        let aligned = addr & !(size_of::<c_long>() as u64 - 1);
        let word = ptrace::read(pid, aligned as ptrace::AddressType)? as c_long;

        let offset = usize::try_from(addr - aligned)?;
        let restored = set_byte_in_word(word, offset, self.byte);
        ptrace::write(pid, aligned as ptrace::AddressType, restored)?;

        Ok(())
    }
}

/// Represents a breakpoint event that needs to be processed by the tracer.
///
/// When a permanent breakpoint is hit we return a `Pending` value containing
/// the breakpoint id (if assigned) and the address where it was hit. This
/// allows the tracer to re-install or re-register the breakpoint as needed.
pub struct Pending {
    id: Option<u64>,
    address: u64,
}

impl Pending {
    #[must_use]
    /// Create a new `Pending` event.
    ///
    /// # Arguments
    ///
    /// * `id` - Optional breakpoint id assigned by the manager.
    /// * `address` - Address where the breakpoint was hit.
    ///
    /// # Returns
    ///
    /// A newly-created `Pending` event.
    pub fn new(id: Option<u64>, address: u64) -> Self {
        Self { id, address }
    }

    #[must_use]
    /// Return the optional breakpoint id associated with this pending event.
    ///
    /// # Returns
    ///
    /// The optional breakpoint id assigned by the manager, or `None` if the
    /// breakpoint was not registered.
    pub fn id(&self) -> Option<u64> {
        self.id
    }

    #[must_use]
    /// Return the address where the breakpoint was hit.
    ///
    /// # Returns
    ///
    /// The instruction address where the breakpoint occurred.
    pub fn address(&self) -> u64 {
        self.address
    }
}

/// Breakpoint manager that owns breakpoint metadata for a traced process.
///
/// `Manager` keeps track of installed software breakpoints (INT3) and the
/// original bytes they replaced. It provides helpers to install, remove and
/// temporarily save/restore breakpoints. All ptrace operations are performed
/// by this manager and therefore require the tracee to be stopped when called.
pub struct Manager {
    pid: Pid,
    next_id: u64,
    saved: Option<u64>,
    breakpoints: HashMap<u64, Active>,
}

impl Manager {
    #[must_use]
    /// Create a new `Manager` for `pid`.
    ///
    /// # Arguments
    ///
    /// * `pid` - PID of the traced process this manager will operate on.
    ///
    /// # Returns
    ///
    /// A new `Manager` ready to install and manage breakpoints for `pid`.
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            next_id: 1,
            saved: None,
            breakpoints: HashMap::new(),
        }
    }

    fn install_breakpoint(&self, addr: u64) -> Result<u8> {
        let aligned = addr & !(size_of::<c_long>() as u64 - 1);
        let offset = usize::try_from(addr - aligned)?;

        let word = ptrace::read(self.pid, aligned as ptrace::AddressType)? as c_long;

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let byte = ((word as u64) >> (8 * offset)) as u8;

        let patched = set_byte_in_word(word, offset, INT3);
        ptrace::write(self.pid, aligned as ptrace::AddressType, patched)?;

        Ok(byte)
    }

    /// Set a breakpoint at `addr`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address where the breakpoint should be set.
    /// * `temporary` - If true the breakpoint is considered temporary and
    ///   won't be returned as a `Pending` event when hit.
    /// * `registered` - If true allocate or use an id and persist the
    ///   breakpoint in the manager's table. If false the breakpoint is not
    ///   assigned an id.
    /// * `id` - Optionally provide an explicit id to use when `registered` is
    ///   true.
    ///
    /// # Errors
    ///
    /// Returns an error if a ptrace read/write fails while patching memory.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(id))` when the breakpoint is registered and has an id,
    /// `Ok(None)` when it is not registered.
    pub fn set_breakpoint(
        &mut self,
        addr: u64,
        temporary: bool,
        registered: bool,
        id: Option<u64>,
    ) -> Result<Option<u64>> {
        if let Some(bp) = self.breakpoints.get(&addr) {
            let new_id = bp.id;
            if bp.temporary != temporary {
                self.breakpoints
                    .insert(addr, Active::new(new_id, bp.byte, temporary));
            }

            Ok(new_id)
        } else {
            let byte = self.install_breakpoint(addr)?;

            let new_id = if registered {
                id.or_else(|| {
                    let ret = self.next_id;
                    self.next_id = self.next_id.wrapping_add(1);
                    Some(ret)
                })
            } else {
                None
            };

            self.breakpoints
                .insert(addr, Active::new(new_id, byte, temporary));
            Ok(new_id)
        }
    }

    /// Handle a breakpoint stop at RIP-1.
    ///
    /// When the tracee hits an INT3 the RIP points at the instruction after
    /// the breakpoint; this method restores the original byte, rewrites RIP
    /// to point at the original instruction and writes the registers back.
    ///
    /// # Arguments
    ///
    /// * `regs` - Mutable register snapshot for the stopped tracee.
    ///
    /// # Errors
    ///
    /// Returns an error if ptrace operations fail while restoring the
    /// original instruction or writing registers.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Some(Pending))` for non-temporary breakpoints that need
    /// further processing (reinstallation), or `Ok(None)` when nothing needs
    /// to be done.
    pub fn handle_breakpoint(
        &mut self,
        regs: &mut Registers,
    ) -> Result<Option<Pending>> {
        let mut ret = None;

        let addr = regs.rip() - 1;
        if let Some(bp) = self.breakpoints.remove(&addr) {
            bp.restore_byte(self.pid, addr)?;
            regs.set_rip(addr);
            regs.write()?;

            if !bp.temporary {
                ret = Some(Pending::new(bp.id, addr));
            }
        }

        Ok(ret)
    }

    /// Delete a registered breakpoint by `id`.
    ///
    /// # Arguments
    ///
    /// * `id` - The identifier of the breakpoint to delete.
    ///
    /// # Errors
    ///
    /// Returns `ENODATA` when no breakpoint with the given id exists or when
    /// the ptrace write to restore the original byte fails.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success; returns `Err` if no matching breakpoint
    /// exists or if restoring the original byte fails.
    pub fn delete_breakpoint(&mut self, id: u64) -> Result<()> {
        let addr = self
            .breakpoints
            .iter()
            .find_map(
                |(addr, bp)| if bp.id == Some(id) { Some(*addr) } else { None },
            )
            .ok_or_else(|| Error::from(Errno::ENODATA))?;

        if let Some(bp) = self.breakpoints.remove(&addr) {
            bp.restore_byte(self.pid, addr)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }

    /// Temporarily remove (save) the breakpoint at `addr`.
    ///
    /// This is used when single-stepping over an instruction that previously
    /// had an INT3 installed: we restore the original byte so the single
    /// step executes the original instruction. The manager records `addr` in
    /// its `saved` slot so `restore_breakpoint` can re-install it later.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address of the breakpoint to temporarily remove (save).
    ///
    /// # Errors
    ///
    /// Returns `EBUSY` if there is already a saved breakpoint in progress.
    /// Returns an error if the underlying ptrace restore fails.
    pub fn save_breakpoint(&mut self, addr: u64) -> Result<()> {
        self.saved
            .is_none()
            .then_some(())
            .ok_or_else(|| Error::from(Errno::EBUSY))?;

        if let Some(bp) = self.breakpoints.get(&addr) {
            bp.restore_byte(self.pid, addr)?;
        }

        self.saved = Some(addr);
        Ok(())
    }

    /// Reinstall a previously saved breakpoint (if any).
    ///
    /// # Errors
    ///
    /// Returns an error if reinstallation via ptrace write fails.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success. If there was no saved breakpoint this
    /// method is a no-op and still returns `Ok(())`.
    pub fn restore_breakpoint(&mut self) -> Result<()> {
        if let Some(addr) = self.saved.take() {
            if self.breakpoints.contains_key(&addr) {
                self.install_breakpoint(addr)?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for Manager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut items: Vec<(u64, bool, u64)> = self
            .breakpoints
            .iter()
            .filter_map(|(addr, bp)| bp.id.map(|id| (id, bp.temporary, *addr)))
            .collect();
        items.sort_by_key(|(id, _, _)| *id);

        if items.is_empty() {
            write!(f, "No breakpoints")
        } else {
            let mut lines = Vec::with_capacity(items.len() + 1);
            lines.push("Num   Type        Address".to_string());

            for (id, temporary, addr) in items {
                lines.push(format!(
                    "{:<6}{:<12}{:#018x}",
                    id,
                    if temporary { "Temporary" } else { "Permanent" },
                    addr
                ));
            }

            write!(f, "{}", lines.join("\n"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::unistd::Pid;

    #[test]
    fn test_set_byte_in_word_basic() {
        let word: c_long = 0x1122334455667788;
        let out = set_byte_in_word(word, 0, 0xaa);
        assert_eq!(out as u64 & 0xff, 0xaa);

        let out = set_byte_in_word(word, 7, 0xbb);
        assert_eq!(((out as u64) >> 56) & 0xff, 0xbb);
    }

    #[test]
    fn test_pending_new_and_accessors() {
        let p = Pending::new(Some(3), 0x1000);
        assert_eq!(p.id(), Some(3));
        assert_eq!(p.address(), 0x1000);
    }

    #[test]
    fn test_manager_display_empty() {
        let mgr = Manager::new(Pid::from_raw(1));
        let s = format!("{}", mgr);
        assert!(s.contains("No breakpoints"));
    }

    #[test]
    fn test_manager_display_with_entries() {
        let mut mgr = Manager::new(Pid::from_raw(1));
        mgr.breakpoints
            .insert(0x1000, Active::new(Some(2), 0x90, false));
        let s = format!("{}", mgr);
        assert!(s.contains("Num"));
        assert!(s.contains("2"));
        assert!(s.contains("0x0000000000001000"));
    }
}
