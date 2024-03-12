use nix::errno::Errno;

pub type SysResult<T> = Result<T, Errno>;

pub fn invalid_argument() -> Errno {
    Errno::EINVAL
}

pub fn operation_not_permitted() -> Errno {
    Errno::EPERM
}
