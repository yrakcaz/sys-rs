use nix::errno::Errno;
use serde_json::Error as SerdeJsonError;
use std::{ffi::NulError, fmt};

pub enum SysError {
    Nix(Errno),
    Json(SerdeJsonError),
    CString(NulError),
    EnvVar,
    InvalidArgument,
}

impl fmt::Debug for SysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nix(e) => {
                write!(f, "System error: {}", e)
            }
            Self::Json(e) => {
                write!(f, "JSON parsing error: {}", e)
            }
            Self::CString(e) => {
                write!(f, "CString conversion error: {}", e)
            }
            Self::EnvVar => {
                write!(f, "Environment variable conversion error")
            }
            Self::InvalidArgument => {
                write!(f, "Invalid argument")
            }
        }
    }
}

impl From<Errno> for SysError {
    fn from(e: Errno) -> SysError {
        SysError::Nix(e)
    }
}

impl From<SerdeJsonError> for SysError {
    fn from(e: SerdeJsonError) -> SysError {
        SysError::Json(e)
    }
}

pub type SysResult<T> = Result<T, SysError>;
