use nix::errno::Errno;

pub type SysResult<T> = Result<T, Errno>;

pub fn invalid_argument() -> SysResult<()> {
    Err(Errno::EINVAL)
}

pub fn invalid_io() -> SysResult<()> {
    Err(Errno::EIO)
}
