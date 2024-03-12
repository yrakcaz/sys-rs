use nix::errno::Errno;

pub type SysResult<T> = Result<T, Errno>;

pub fn invalid_argument() -> SysResult<()> {
    Err(Errno::EINVAL)
}

pub fn operation_not_permitted() -> SysResult<()> {
    Err(Errno::EPERM)
}
