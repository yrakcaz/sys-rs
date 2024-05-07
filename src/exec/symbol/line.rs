use nix::errno::Errno;
use std::{
    fmt,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use crate::diag::{Error, Result};

pub struct Info {
    addr: u64,
    path: PathBuf,
    line: usize,
}

impl Info {
    /// # Errors
    ///
    /// Will return `Err` upon failure to convert line (u64) to usize.
    pub fn new(addr: u64, path: PathBuf, line: u64) -> Result<Self> {
        Ok(Self {
            addr,
            path,
            line: usize::try_from(line)?,
        })
    }

    fn read(&self) -> Result<String> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut lines = reader.lines();
        if let Some(line) = lines.nth(self.line - 1) {
            Ok(line?)
        } else {
            Err(Error::from(Errno::ENODATA))
        }
    }
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(line) = self.read() {
            write!(
                f,
                "0x{:x}: {}:{} | {}",
                self.addr,
                self.path.display(),
                self.line,
                line
            )
        } else {
            Err(fmt::Error)
        }
    }
}
