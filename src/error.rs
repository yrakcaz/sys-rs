use std::{
    backtrace::{Backtrace, BacktraceStatus},
    fmt,
};

pub struct SysError {
    error: String,
    backtrace: Backtrace,
}

impl SysError {
    fn new(error: String) -> Self {
        Self {
            error,
            backtrace: Backtrace::capture(),
        }
    }
}

impl fmt::Debug for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        if self.backtrace.status() == BacktraceStatus::Captured {
            write!(f, "\nBacktrace:\n{}", self.backtrace)
        } else {
            Ok(())
        }
    }
}

impl<E: fmt::Display> From<E> for SysError {
    fn from(e: E) -> SysError {
        SysError::new(e.to_string())
    }
}

pub type SysResult<T> = Result<T, SysError>;
