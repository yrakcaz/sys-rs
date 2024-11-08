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

#[cfg(test)]
mod tests {
    use super::*;

    use ctor::ctor;

    #[ctor]
    fn init() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    #[test]
    fn test_error_new() {
        let error = Error::new("Test error".to_string());
        assert_eq!(error.error, "Test error");
        assert!(error.backtrace.status() == BacktraceStatus::Captured);
    }

    #[test]
    fn test_error_from() {
        let error: Error = "Test error".to_string().into();
        assert_eq!(error.error, "Test error");
        assert!(error.backtrace.status() == BacktraceStatus::Captured);
    }

    #[test]
    fn test_error_debug() {
        let error = Error::new("Test error".to_string());
        let debug_output = format!("{:?}", error);
        assert!(debug_output.contains("Test error"));
        assert!(debug_output.contains("Backtrace"));
    }

    #[test]
    fn test_result_ok() {
        let result: Result<u32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.expect("Expected Ok value"), 42);
    }

    #[test]
    fn test_result_err() {
        let result: Result<u32> = Err("Test error".to_string().into());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error, "Test error");
    }
}
