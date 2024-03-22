use std::{
    backtrace::{Backtrace, BacktraceStatus},
    fmt, result,
};

pub struct Error {
    error: String,
    backtrace: Backtrace,
}

impl Error {
    fn new(error: String) -> Self {
        Self {
            error,
            backtrace: Backtrace::capture(),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        if self.backtrace.status() == BacktraceStatus::Captured {
            write!(f, "\nBacktrace:\n{}", self.backtrace)
        } else {
            Ok(())
        }
    }
}

impl<E: fmt::Display> From<E> for Error {
    fn from(e: E) -> Error {
        Error::new(e.to_string())
    }
}

pub type Result<T> = result::Result<T, Error>;
