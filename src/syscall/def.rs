use std::collections::HashMap;

use crate::syscall::{SyscallArg, SyscallDef, SyscallType};

lazy_static! {
    pub static ref SYSCALL: HashMap<u64, SyscallDef> = hashmap![
        0 => SyscallDef::new("read", SyscallType::UINT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("buf", SyscallType::PTR),
            SyscallArg::new("count", SyscallType::UINT),
        ]),
        1 => SyscallDef::new("write", SyscallType::UINT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("buf", SyscallType::PTR),
            SyscallArg::new("count", SyscallType::UINT),
        ]),
        2 => SyscallDef::new("open", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        3 => SyscallDef::new("close", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
        ]),
        4 => SyscallDef::new("stat", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        5 => SyscallDef::new("fstat", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        6 => SyscallDef::new("lstat", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        7 => SyscallDef::new("poll", SyscallType::INT, vec![
            SyscallArg::new("fds", SyscallType::PTR),
            SyscallArg::new("nfds", SyscallType::INT),
            SyscallArg::new("timeout", SyscallType::INT),
        ]),
        8 => SyscallDef::new("lseek", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("offset", SyscallType::INT),
            SyscallArg::new("whence", SyscallType::INT),
        ]),
        9 => SyscallDef::new("mmap", SyscallType::INT, vec![
        ]),
        10 => SyscallDef::new("mprotect", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("len", SyscallType::UINT),
            SyscallArg::new("prot", SyscallType::INT),
        ]),
        11 => SyscallDef::new("munmap", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("length", SyscallType::UINT),
        ]),
        12 => SyscallDef::new("brk", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
        ]),
        13 => SyscallDef::new("rt_sigaction", SyscallType::INT, vec![
            SyscallArg::new("signum", SyscallType::INT),
            SyscallArg::new("act", SyscallType::PTR),
            SyscallArg::new("oldact", SyscallType::PTR),
        ]),
        14 => SyscallDef::new("rt_sigprocmask", SyscallType::INT, vec![
            SyscallArg::new("how", SyscallType::INT),
            SyscallArg::new("set", SyscallType::PTR),
            SyscallArg::new("oldset", SyscallType::PTR),
        ]),
        15 => SyscallDef::new("rt_sigreturn", SyscallType::INT, vec![
            SyscallArg::new("__unused", SyscallType::UINT),
        ]),
        16 => SyscallDef::new("ioctl", SyscallType::INT, vec![
            SyscallArg::new("d", SyscallType::INT),
            SyscallArg::new("request", SyscallType::INT),
        ]),
        17 => SyscallDef::new("pread64", SyscallType::INT, vec![
        ]),
        18 => SyscallDef::new("pwrite64", SyscallType::INT, vec![
        ]),
        19 => SyscallDef::new("readv", SyscallType::UINT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("iov", SyscallType::PTR),
            SyscallArg::new("iovcnt", SyscallType::INT),
        ]),
        20 => SyscallDef::new("writev", SyscallType::UINT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("iov", SyscallType::PTR),
            SyscallArg::new("iovcnt", SyscallType::INT),
        ]),
        21 => SyscallDef::new("access", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
        ]),
        22 => SyscallDef::new("pipe", SyscallType::INT, vec![
            SyscallArg::new("pipefd", SyscallType::PTR),
        ]),
        23 => SyscallDef::new("select", SyscallType::INT, vec![
        ]),
        24 => SyscallDef::new("sched_yield", SyscallType::INT, vec![
        ]),
        25 => SyscallDef::new("mremap", SyscallType::INT, vec![
        ]),
        26 => SyscallDef::new("msync", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("length", SyscallType::UINT),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        27 => SyscallDef::new("mincore", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("length", SyscallType::UINT),
            SyscallArg::new("vec", SyscallType::STR),
        ]),
        28 => SyscallDef::new("madvise", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("length", SyscallType::UINT),
            SyscallArg::new("advice", SyscallType::INT),
        ]),
        29 => SyscallDef::new("shmget", SyscallType::INT, vec![
            SyscallArg::new("key", SyscallType::INT),
            SyscallArg::new("size", SyscallType::UINT),
            SyscallArg::new("shmflg", SyscallType::INT),
        ]),
        30 => SyscallDef::new("shmat", SyscallType::INT, vec![
            SyscallArg::new("shmid", SyscallType::INT),
            SyscallArg::new("shmaddr", SyscallType::PTR),
            SyscallArg::new("shmflg", SyscallType::INT),
        ]),
        31 => SyscallDef::new("shmctl", SyscallType::INT, vec![
            SyscallArg::new("shmid", SyscallType::INT),
            SyscallArg::new("cmd", SyscallType::INT),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        32 => SyscallDef::new("dup", SyscallType::INT, vec![
            SyscallArg::new("oldfd", SyscallType::INT),
        ]),
        33 => SyscallDef::new("dup2", SyscallType::INT, vec![
            SyscallArg::new("oldfd", SyscallType::INT),
            SyscallArg::new("newfd", SyscallType::INT),
        ]),
        34 => SyscallDef::new("pause", SyscallType::INT, vec![
        ]),
        35 => SyscallDef::new("nanosleep", SyscallType::INT, vec![
            SyscallArg::new("req", SyscallType::PTR),
            SyscallArg::new("rem", SyscallType::PTR),
        ]),
        36 => SyscallDef::new("getitimer", SyscallType::INT, vec![
            SyscallArg::new("which", SyscallType::INT),
            SyscallArg::new("curr_value", SyscallType::PTR),
        ]),
        37 => SyscallDef::new("alarm", SyscallType::INT, vec![
            SyscallArg::new("seconds", SyscallType::UINT),
        ]),
        38 => SyscallDef::new("setitimer", SyscallType::INT, vec![
        ]),
        39 => SyscallDef::new("getpid", SyscallType::INT, vec![
        ]),
        40 => SyscallDef::new("sendfile", SyscallType::UINT, vec![
            SyscallArg::new("out_fd", SyscallType::INT),
            SyscallArg::new("in_fd", SyscallType::INT),
            SyscallArg::new("offset", SyscallType::PTR),
            SyscallArg::new("count", SyscallType::UINT),
        ]),
        41 => SyscallDef::new("socket", SyscallType::INT, vec![
            SyscallArg::new("domain", SyscallType::INT),
            SyscallArg::new("type", SyscallType::INT),
            SyscallArg::new("protocol", SyscallType::INT),
        ]),
        42 => SyscallDef::new("connect", SyscallType::INT, vec![
        ]),
        43 => SyscallDef::new("accept", SyscallType::INT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("addrlen", SyscallType::PTR),
        ]),
        44 => SyscallDef::new("sendto", SyscallType::UINT, vec![
        ]),
        45 => SyscallDef::new("recvfrom", SyscallType::UINT, vec![
        ]),
        46 => SyscallDef::new("sendmsg", SyscallType::UINT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("msg", SyscallType::PTR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        47 => SyscallDef::new("recvmsg", SyscallType::UINT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("msg", SyscallType::PTR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        48 => SyscallDef::new("shutdown", SyscallType::INT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("how", SyscallType::INT),
        ]),
        49 => SyscallDef::new("bind", SyscallType::INT, vec![
        ]),
        50 => SyscallDef::new("listen", SyscallType::INT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("backlog", SyscallType::INT),
        ]),
        51 => SyscallDef::new("getsockname", SyscallType::INT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("addrlen", SyscallType::PTR),
        ]),
        52 => SyscallDef::new("getpeername", SyscallType::INT, vec![
            SyscallArg::new("sockfd", SyscallType::INT),
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("addrlen", SyscallType::PTR),
        ]),
        53 => SyscallDef::new("socketpair", SyscallType::INT, vec![
            SyscallArg::new("domain", SyscallType::INT),
            SyscallArg::new("type", SyscallType::INT),
            SyscallArg::new("protocol", SyscallType::INT),
            SyscallArg::new("sv", SyscallType::PTR),
        ]),
        54 => SyscallDef::new("setsockopt", SyscallType::INT, vec![
        ]),
        55 => SyscallDef::new("getsockopt", SyscallType::INT, vec![
        ]),
        56 => SyscallDef::new("clone", SyscallType::INT, vec![
            SyscallArg::new("(*fn", SyscallType::INT),
        ]),
        57 => SyscallDef::new("fork", SyscallType::INT, vec![
        ]),
        58 => SyscallDef::new("vfork", SyscallType::INT, vec![
        ]),
        59 => SyscallDef::new("execve", SyscallType::INT, vec![
        ]),
        60 => SyscallDef::new("exit", SyscallType::INT, vec![
        ]),
        61 => SyscallDef::new("wait4", SyscallType::INT, vec![
        ]),
        62 => SyscallDef::new("kill", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
            SyscallArg::new("sig", SyscallType::INT),
        ]),
        63 => SyscallDef::new("uname", SyscallType::INT, vec![
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        64 => SyscallDef::new("semget", SyscallType::INT, vec![
            SyscallArg::new("key", SyscallType::INT),
            SyscallArg::new("nsems", SyscallType::INT),
            SyscallArg::new("semflg", SyscallType::INT),
        ]),
        65 => SyscallDef::new("semop", SyscallType::INT, vec![
            SyscallArg::new("semid", SyscallType::INT),
            SyscallArg::new("sops", SyscallType::PTR),
            SyscallArg::new("nsops", SyscallType::UINT),
        ]),
        66 => SyscallDef::new("semctl", SyscallType::INT, vec![
            SyscallArg::new("semid", SyscallType::INT),
            SyscallArg::new("semnum", SyscallType::INT),
            SyscallArg::new("cmd", SyscallType::INT),
        ]),
        67 => SyscallDef::new("shmdt", SyscallType::INT, vec![
            SyscallArg::new("shmaddr", SyscallType::PTR),
        ]),
        68 => SyscallDef::new("msgget", SyscallType::INT, vec![
            SyscallArg::new("key", SyscallType::INT),
            SyscallArg::new("msgflg", SyscallType::INT),
        ]),
        69 => SyscallDef::new("msgsnd", SyscallType::INT, vec![
            SyscallArg::new("msqid", SyscallType::INT),
            SyscallArg::new("msgp", SyscallType::PTR),
            SyscallArg::new("msgsz", SyscallType::UINT),
            SyscallArg::new("msgflg", SyscallType::INT),
        ]),
        70 => SyscallDef::new("msgrcv", SyscallType::UINT, vec![
        ]),
        71 => SyscallDef::new("msgctl", SyscallType::INT, vec![
            SyscallArg::new("msqid", SyscallType::INT),
            SyscallArg::new("cmd", SyscallType::INT),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        72 => SyscallDef::new("fcntl", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("cmd", SyscallType::INT),
            SyscallArg::new("/", SyscallType::PTR),
        ]),
        73 => SyscallDef::new("flock", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("operation", SyscallType::INT),
        ]),
        74 => SyscallDef::new("fsync", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
        ]),
        75 => SyscallDef::new("fdatasync", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
        ]),
        76 => SyscallDef::new("truncate", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("length", SyscallType::INT),
        ]),
        77 => SyscallDef::new("ftruncate", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("length", SyscallType::INT),
        ]),
        78 => SyscallDef::new("getdents", SyscallType::INT, vec![
        ]),
        79 => SyscallDef::new("getcwd", SyscallType::INT, vec![
            SyscallArg::new("buf", SyscallType::STR),
            SyscallArg::new("size", SyscallType::UINT),
        ]),
        80 => SyscallDef::new("chdir", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
        ]),
        81 => SyscallDef::new("fchdir", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
        ]),
        82 => SyscallDef::new("rename", SyscallType::INT, vec![
            SyscallArg::new("oldpath", SyscallType::STR),
            SyscallArg::new("newpath", SyscallType::STR),
        ]),
        83 => SyscallDef::new("mkdir", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
        ]),
        84 => SyscallDef::new("rmdir", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
        ]),
        85 => SyscallDef::new("creat", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
        ]),
        86 => SyscallDef::new("link", SyscallType::INT, vec![
            SyscallArg::new("oldpath", SyscallType::STR),
            SyscallArg::new("newpath", SyscallType::STR),
        ]),
        87 => SyscallDef::new("unlink", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
        ]),
        88 => SyscallDef::new("symlink", SyscallType::INT, vec![
            SyscallArg::new("oldpath", SyscallType::STR),
            SyscallArg::new("newpath", SyscallType::STR),
        ]),
        89 => SyscallDef::new("readlink", SyscallType::UINT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("buf", SyscallType::STR),
            SyscallArg::new("bufsiz", SyscallType::UINT),
        ]),
        90 => SyscallDef::new("chmod", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
        ]),
        91 => SyscallDef::new("fchmod", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("mode", SyscallType::INT),
        ]),
        92 => SyscallDef::new("chown", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("owner", SyscallType::INT),
            SyscallArg::new("group", SyscallType::INT),
        ]),
        93 => SyscallDef::new("fchown", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("owner", SyscallType::INT),
            SyscallArg::new("group", SyscallType::INT),
        ]),
        94 => SyscallDef::new("lchown", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("owner", SyscallType::INT),
            SyscallArg::new("group", SyscallType::INT),
        ]),
        95 => SyscallDef::new("umask", SyscallType::INT, vec![
            SyscallArg::new("mask", SyscallType::INT),
        ]),
        96 => SyscallDef::new("gettimeofday", SyscallType::INT, vec![
            SyscallArg::new("tv", SyscallType::PTR),
            SyscallArg::new("tz", SyscallType::PTR),
        ]),
        97 => SyscallDef::new("getrlimit", SyscallType::INT, vec![
            SyscallArg::new("resource", SyscallType::INT),
            SyscallArg::new("rlim", SyscallType::PTR),
        ]),
        98 => SyscallDef::new("getrusage", SyscallType::INT, vec![
            SyscallArg::new("who", SyscallType::INT),
            SyscallArg::new("usage", SyscallType::PTR),
        ]),
        99 => SyscallDef::new("sysinfo", SyscallType::INT, vec![
            SyscallArg::new("info", SyscallType::PTR),
        ]),
        100 => SyscallDef::new("times", SyscallType::INT, vec![
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        101 => SyscallDef::new("ptrace", SyscallType::INT, vec![
        ]),
        102 => SyscallDef::new("getuid", SyscallType::INT, vec![
        ]),
        103 => SyscallDef::new("syslog", SyscallType::INT, vec![
            SyscallArg::new("type", SyscallType::INT),
            SyscallArg::new("bufp", SyscallType::STR),
            SyscallArg::new("len", SyscallType::INT),
        ]),
        104 => SyscallDef::new("getgid", SyscallType::INT, vec![
        ]),
        105 => SyscallDef::new("setuid", SyscallType::INT, vec![
            SyscallArg::new("uid", SyscallType::INT),
        ]),
        106 => SyscallDef::new("setgid", SyscallType::INT, vec![
            SyscallArg::new("gid", SyscallType::INT),
        ]),
        107 => SyscallDef::new("geteuid", SyscallType::INT, vec![
        ]),
        108 => SyscallDef::new("getegid", SyscallType::INT, vec![
        ]),
        109 => SyscallDef::new("setpgid", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
            SyscallArg::new("pgid", SyscallType::INT),
        ]),
        110 => SyscallDef::new("getppid", SyscallType::INT, vec![
        ]),
        111 => SyscallDef::new("getpgrp", SyscallType::INT, vec![
        ]),
        112 => SyscallDef::new("setsid", SyscallType::INT, vec![
        ]),
        113 => SyscallDef::new("setreuid", SyscallType::INT, vec![
            SyscallArg::new("ruid", SyscallType::INT),
            SyscallArg::new("euid", SyscallType::INT),
        ]),
        114 => SyscallDef::new("setregid", SyscallType::INT, vec![
            SyscallArg::new("rgid", SyscallType::INT),
            SyscallArg::new("egid", SyscallType::INT),
        ]),
        115 => SyscallDef::new("getgroups", SyscallType::INT, vec![
            SyscallArg::new("size", SyscallType::INT),
            SyscallArg::new("list", SyscallType::PTR),
        ]),
        116 => SyscallDef::new("setgroups", SyscallType::INT, vec![
            SyscallArg::new("size", SyscallType::UINT),
            SyscallArg::new("list", SyscallType::PTR),
        ]),
        117 => SyscallDef::new("setresuid", SyscallType::INT, vec![
            SyscallArg::new("ruid", SyscallType::INT),
            SyscallArg::new("euid", SyscallType::INT),
            SyscallArg::new("suid", SyscallType::INT),
        ]),
        118 => SyscallDef::new("getresuid", SyscallType::INT, vec![
            SyscallArg::new("ruid", SyscallType::PTR),
            SyscallArg::new("euid", SyscallType::PTR),
            SyscallArg::new("suid", SyscallType::PTR),
        ]),
        119 => SyscallDef::new("setresgid", SyscallType::INT, vec![
            SyscallArg::new("rgid", SyscallType::INT),
            SyscallArg::new("egid", SyscallType::INT),
            SyscallArg::new("sgid", SyscallType::INT),
        ]),
        120 => SyscallDef::new("getresgid", SyscallType::INT, vec![
            SyscallArg::new("rgid", SyscallType::PTR),
            SyscallArg::new("egid", SyscallType::PTR),
            SyscallArg::new("sgid", SyscallType::PTR),
        ]),
        121 => SyscallDef::new("getpgid", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
        ]),
        122 => SyscallDef::new("setfsuid", SyscallType::INT, vec![
            SyscallArg::new("fsuid", SyscallType::INT),
        ]),
        123 => SyscallDef::new("setfsgid", SyscallType::INT, vec![
            SyscallArg::new("fsgid", SyscallType::INT),
        ]),
        124 => SyscallDef::new("getsid", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
        ]),
        125 => SyscallDef::new("capget", SyscallType::INT, vec![
            SyscallArg::new("hdrp", SyscallType::INT),
            SyscallArg::new("datap", SyscallType::INT),
        ]),
        126 => SyscallDef::new("capset", SyscallType::INT, vec![
            SyscallArg::new("hdrp", SyscallType::INT),
            SyscallArg::new("datap", SyscallType::INT),
        ]),
        129 => SyscallDef::new("rt_sigqueueinfo", SyscallType::INT, vec![
            SyscallArg::new("tgid", SyscallType::INT),
            SyscallArg::new("sig", SyscallType::INT),
            SyscallArg::new("uinfo", SyscallType::PTR),
        ]),
        131 => SyscallDef::new("sigaltstack", SyscallType::INT, vec![
            SyscallArg::new("ss", SyscallType::PTR),
            SyscallArg::new("oss", SyscallType::PTR),
        ]),
        132 => SyscallDef::new("utime", SyscallType::INT, vec![
            SyscallArg::new("filename", SyscallType::STR),
            SyscallArg::new("times", SyscallType::PTR),
        ]),
        133 => SyscallDef::new("mknod", SyscallType::INT, vec![
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
            SyscallArg::new("dev", SyscallType::INT),
        ]),
        134 => SyscallDef::new("uselib", SyscallType::INT, vec![
            SyscallArg::new("library", SyscallType::STR),
        ]),
        135 => SyscallDef::new("personality", SyscallType::INT, vec![
            SyscallArg::new("persona", SyscallType::UINT),
        ]),
        136 => SyscallDef::new("ustat", SyscallType::INT, vec![
            SyscallArg::new("dev", SyscallType::INT),
            SyscallArg::new("ubuf", SyscallType::PTR),
        ]),
        137 => SyscallDef::new("statfs", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        138 => SyscallDef::new("fstatfs", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        139 => SyscallDef::new("sysfs", SyscallType::INT, vec![
            SyscallArg::new("option", SyscallType::INT),
            SyscallArg::new("fsname", SyscallType::STR),
        ]),
        140 => SyscallDef::new("getpriority", SyscallType::INT, vec![
            SyscallArg::new("which", SyscallType::INT),
            SyscallArg::new("who", SyscallType::INT),
        ]),
        141 => SyscallDef::new("setpriority", SyscallType::INT, vec![
            SyscallArg::new("which", SyscallType::INT),
            SyscallArg::new("who", SyscallType::INT),
            SyscallArg::new("prio", SyscallType::INT),
        ]),
        142 => SyscallDef::new("sched_setparam", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
            SyscallArg::new("param", SyscallType::PTR),
        ]),
        143 => SyscallDef::new("sched_getparam", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
            SyscallArg::new("param", SyscallType::PTR),
        ]),
        144 => SyscallDef::new("sched_setscheduler", SyscallType::INT, vec![
        ]),
        145 => SyscallDef::new("sched_getscheduler", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
        ]),
        146 => SyscallDef::new("sched_get_priority_max", SyscallType::INT, vec![
            SyscallArg::new("policy", SyscallType::INT),
        ]),
        147 => SyscallDef::new("sched_get_priority_min", SyscallType::INT, vec![
            SyscallArg::new("policy", SyscallType::INT),
        ]),
        148 => SyscallDef::new("sched_rr_get_interval", SyscallType::INT, vec![
            SyscallArg::new("pid", SyscallType::INT),
            SyscallArg::new("tp", SyscallType::PTR),
        ]),
        149 => SyscallDef::new("mlock", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("len", SyscallType::UINT),
        ]),
        150 => SyscallDef::new("munlock", SyscallType::INT, vec![
            SyscallArg::new("addr", SyscallType::PTR),
            SyscallArg::new("len", SyscallType::UINT),
        ]),
        151 => SyscallDef::new("mlockall", SyscallType::INT, vec![
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        152 => SyscallDef::new("munlockall", SyscallType::INT, vec![
        ]),
        153 => SyscallDef::new("vhangup", SyscallType::INT, vec![
        ]),
        154 => SyscallDef::new("modify_ldt", SyscallType::INT, vec![
            SyscallArg::new("func", SyscallType::INT),
            SyscallArg::new("ptr", SyscallType::PTR),
            SyscallArg::new("bytecount", SyscallType::UINT),
        ]),
        155 => SyscallDef::new("pivot_root", SyscallType::INT, vec![
            SyscallArg::new("new_root", SyscallType::STR),
            SyscallArg::new("put_old", SyscallType::STR),
        ]),
        156 => SyscallDef::new("_sysctl", SyscallType::INT, vec![
            SyscallArg::new("args", SyscallType::PTR),
        ]),
        157 => SyscallDef::new("prctl", SyscallType::INT, vec![
        ]),
        158 => SyscallDef::new("arch_prctl", SyscallType::INT, vec![
            SyscallArg::new("code", SyscallType::INT),
            SyscallArg::new("addr", SyscallType::UINT),
        ]),
        159 => SyscallDef::new("adjtimex", SyscallType::INT, vec![
            SyscallArg::new("buf", SyscallType::PTR),
        ]),
        160 => SyscallDef::new("setrlimit", SyscallType::INT, vec![
            SyscallArg::new("resource", SyscallType::INT),
            SyscallArg::new("rlim", SyscallType::PTR),
        ]),
        161 => SyscallDef::new("chroot", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
        ]),
        162 => SyscallDef::new("sync", SyscallType::INT, vec![
        ]),
        163 => SyscallDef::new("acct", SyscallType::INT, vec![
            SyscallArg::new("filename", SyscallType::STR),
        ]),
        164 => SyscallDef::new("settimeofday", SyscallType::INT, vec![
            SyscallArg::new("tv", SyscallType::PTR),
            SyscallArg::new("tz", SyscallType::PTR),
        ]),
        165 => SyscallDef::new("mount", SyscallType::INT, vec![
        ]),
        166 => SyscallDef::new("umount2", SyscallType::INT, vec![
            SyscallArg::new("target", SyscallType::STR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        167 => SyscallDef::new("swapon", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("swapflags", SyscallType::INT),
        ]),
        168 => SyscallDef::new("swapoff", SyscallType::INT, vec![
            SyscallArg::new("path", SyscallType::STR),
        ]),
        169 => SyscallDef::new("reboot", SyscallType::INT, vec![
            SyscallArg::new("magic", SyscallType::INT),
            SyscallArg::new("magic2", SyscallType::INT),
            SyscallArg::new("cmd", SyscallType::INT),
            SyscallArg::new("arg", SyscallType::PTR),
        ]),
        170 => SyscallDef::new("sethostname", SyscallType::INT, vec![
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("len", SyscallType::UINT),
        ]),
        171 => SyscallDef::new("setdomainname", SyscallType::INT, vec![
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("len", SyscallType::UINT),
        ]),
        172 => SyscallDef::new("iopl", SyscallType::INT, vec![
            SyscallArg::new("level", SyscallType::INT),
        ]),
        173 => SyscallDef::new("ioperm", SyscallType::INT, vec![
            SyscallArg::new("from", SyscallType::UINT),
            SyscallArg::new("num", SyscallType::UINT),
            SyscallArg::new("turn_on", SyscallType::INT),
        ]),
        174 => SyscallDef::new("create_module", SyscallType::INT, vec![
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("size", SyscallType::UINT),
        ]),
        175 => SyscallDef::new("init_module", SyscallType::INT, vec![
        ]),
        176 => SyscallDef::new("delete_module", SyscallType::INT, vec![
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        177 => SyscallDef::new("get_kernel_syms", SyscallType::INT, vec![
            SyscallArg::new("table", SyscallType::PTR),
        ]),
        178 => SyscallDef::new("query_module", SyscallType::INT, vec![
        ]),
        179 => SyscallDef::new("quotactl", SyscallType::INT, vec![
            SyscallArg::new("cmd", SyscallType::INT),
            SyscallArg::new("special", SyscallType::STR),
            SyscallArg::new("id", SyscallType::INT),
            SyscallArg::new("addr", SyscallType::INT),
        ]),
        186 => SyscallDef::new("gettid", SyscallType::INT, vec![
        ]),
        187 => SyscallDef::new("readahead", SyscallType::UINT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("offset", SyscallType::INT),
            SyscallArg::new("count", SyscallType::UINT),
        ]),
        191 => SyscallDef::new("getxattr", SyscallType::UINT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("value", SyscallType::PTR),
            SyscallArg::new("size", SyscallType::UINT),
        ]),
        192 => SyscallDef::new("lgetxattr", SyscallType::UINT, vec![
            SyscallArg::new("path", SyscallType::STR),
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("value", SyscallType::PTR),
            SyscallArg::new("size", SyscallType::UINT),
        ]),
        193 => SyscallDef::new("fgetxattr", SyscallType::UINT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("value", SyscallType::PTR),
            SyscallArg::new("size", SyscallType::UINT),
        ]),
        200 => SyscallDef::new("tkill", SyscallType::INT, vec![
            SyscallArg::new("tid", SyscallType::INT),
            SyscallArg::new("sig", SyscallType::INT),
        ]),
        201 => SyscallDef::new("time", SyscallType::INT, vec![
            SyscallArg::new("t", SyscallType::PTR),
        ]),
        202 => SyscallDef::new("futex", SyscallType::INT, vec![
        ]),
        203 => SyscallDef::new("sched_setaffinity", SyscallType::INT, vec![
        ]),
        204 => SyscallDef::new("sched_getaffinity", SyscallType::INT, vec![
        ]),
        205 => SyscallDef::new("set_thread_area", SyscallType::INT, vec![
            SyscallArg::new("u_info", SyscallType::PTR),
        ]),
        206 => SyscallDef::new("io_setup", SyscallType::INT, vec![
            SyscallArg::new("nr_events", SyscallType::UINT),
            SyscallArg::new("ctx_idp", SyscallType::PTR),
        ]),
        207 => SyscallDef::new("io_destroy", SyscallType::INT, vec![
            SyscallArg::new("ctx_id", SyscallType::INT),
        ]),
        208 => SyscallDef::new("io_getevents", SyscallType::INT, vec![
        ]),
        209 => SyscallDef::new("io_submit", SyscallType::INT, vec![
            SyscallArg::new("ctx_id", SyscallType::INT),
            SyscallArg::new("nr", SyscallType::INT),
            SyscallArg::new("*iocbpp", SyscallType::PTR),
        ]),
        210 => SyscallDef::new("io_cancel", SyscallType::INT, vec![
        ]),
        211 => SyscallDef::new("get_thread_area", SyscallType::INT, vec![
            SyscallArg::new("u_info", SyscallType::PTR),
        ]),
        212 => SyscallDef::new("lookup_dcookie", SyscallType::INT, vec![
            SyscallArg::new("cookie", SyscallType::INT),
            SyscallArg::new("buffer", SyscallType::STR),
            SyscallArg::new("len", SyscallType::UINT),
        ]),
        213 => SyscallDef::new("epoll_create", SyscallType::INT, vec![
            SyscallArg::new("size", SyscallType::INT),
        ]),
        216 => SyscallDef::new("remap_file_pages", SyscallType::INT, vec![
        ]),
        217 => SyscallDef::new("getdents64", SyscallType::INT, vec![
        ]),
        218 => SyscallDef::new("set_tid_address", SyscallType::INT, vec![
            SyscallArg::new("tidptr", SyscallType::PTR),
        ]),
        219 => SyscallDef::new("restart_syscall", SyscallType::INT, vec![
        ]),
        220 => SyscallDef::new("semtimedop", SyscallType::INT, vec![
        ]),
        221 => SyscallDef::new("fadvise64", SyscallType::INT, vec![
        ]),
        222 => SyscallDef::new("timer_create", SyscallType::INT, vec![
        ]),
        223 => SyscallDef::new("timer_settime", SyscallType::INT, vec![
        ]),
        224 => SyscallDef::new("timer_gettime", SyscallType::INT, vec![
            SyscallArg::new("timerid", SyscallType::INT),
            SyscallArg::new("curr_value", SyscallType::PTR),
        ]),
        225 => SyscallDef::new("timer_getoverrun", SyscallType::INT, vec![
            SyscallArg::new("timerid", SyscallType::INT),
        ]),
        226 => SyscallDef::new("timer_delete", SyscallType::INT, vec![
            SyscallArg::new("timerid", SyscallType::INT),
        ]),
        227 => SyscallDef::new("clock_settime", SyscallType::INT, vec![
            SyscallArg::new("clk_id", SyscallType::INT),
            SyscallArg::new("tp", SyscallType::PTR),
        ]),
        228 => SyscallDef::new("clock_gettime", SyscallType::INT, vec![
            SyscallArg::new("clk_id", SyscallType::INT),
            SyscallArg::new("tp", SyscallType::PTR),
        ]),
        229 => SyscallDef::new("clock_getres", SyscallType::INT, vec![
            SyscallArg::new("clk_id", SyscallType::INT),
            SyscallArg::new("res", SyscallType::PTR),
        ]),
        230 => SyscallDef::new("clock_nanosleep", SyscallType::INT, vec![
        ]),
        231 => SyscallDef::new("exit_group", SyscallType::INT, vec![
            SyscallArg::new("status", SyscallType::INT),
        ]),
        232 => SyscallDef::new("epoll_wait", SyscallType::INT, vec![
        ]),
        233 => SyscallDef::new("epoll_ctl", SyscallType::INT, vec![
            SyscallArg::new("epfd", SyscallType::INT),
            SyscallArg::new("op", SyscallType::INT),
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("event", SyscallType::PTR),
        ]),
        234 => SyscallDef::new("tgkill", SyscallType::INT, vec![
            SyscallArg::new("tgid", SyscallType::INT),
            SyscallArg::new("tid", SyscallType::INT),
            SyscallArg::new("sig", SyscallType::INT),
        ]),
        235 => SyscallDef::new("utimes", SyscallType::INT, vec![
            SyscallArg::new("filename", SyscallType::STR),
            SyscallArg::new("times", SyscallType::PTR),
        ]),
        237 => SyscallDef::new("mbind", SyscallType::INT, vec![
        ]),
        238 => SyscallDef::new("set_mempolicy", SyscallType::INT, vec![
        ]),
        239 => SyscallDef::new("get_mempolicy", SyscallType::INT, vec![
        ]),
        240 => SyscallDef::new("mq_open", SyscallType::INT, vec![
            SyscallArg::new("name", SyscallType::STR),
            SyscallArg::new("oflag", SyscallType::INT),
        ]),
        241 => SyscallDef::new("mq_unlink", SyscallType::INT, vec![
            SyscallArg::new("name", SyscallType::STR),
        ]),
        242 => SyscallDef::new("mq_timedsend", SyscallType::INT, vec![
        ]),
        243 => SyscallDef::new("mq_timedreceive", SyscallType::UINT, vec![
        ]),
        244 => SyscallDef::new("mq_notify", SyscallType::INT, vec![
            SyscallArg::new("mqdes", SyscallType::INT),
            SyscallArg::new("sevp", SyscallType::PTR),
        ]),
        246 => SyscallDef::new("kexec_load", SyscallType::INT, vec![
        ]),
        247 => SyscallDef::new("waitid", SyscallType::INT, vec![
            SyscallArg::new("idtype", SyscallType::INT),
            SyscallArg::new("id", SyscallType::INT),
            SyscallArg::new("infop", SyscallType::PTR),
            SyscallArg::new("options", SyscallType::INT),
        ]),
        248 => SyscallDef::new("add_key", SyscallType::INT, vec![
        ]),
        249 => SyscallDef::new("request_key", SyscallType::INT, vec![
        ]),
        250 => SyscallDef::new("keyctl", SyscallType::INT, vec![
            SyscallArg::new("cmd", SyscallType::INT),
        ]),
        251 => SyscallDef::new("ioprio_set", SyscallType::INT, vec![
            SyscallArg::new("which", SyscallType::INT),
            SyscallArg::new("who", SyscallType::INT),
            SyscallArg::new("ioprio", SyscallType::INT),
        ]),
        252 => SyscallDef::new("ioprio_get", SyscallType::INT, vec![
            SyscallArg::new("which", SyscallType::INT),
            SyscallArg::new("who", SyscallType::INT),
        ]),
        253 => SyscallDef::new("inotify_init", SyscallType::INT, vec![
        ]),
        254 => SyscallDef::new("inotify_add_watch", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mask", SyscallType::INT),
        ]),
        255 => SyscallDef::new("inotify_rm_watch", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("wd", SyscallType::INT),
        ]),
        256 => SyscallDef::new("migrate_pages", SyscallType::INT, vec![
        ]),
        257 => SyscallDef::new("openat", SyscallType::INT, vec![
            SyscallArg::new("dirfd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        258 => SyscallDef::new("mkdirat", SyscallType::INT, vec![
            SyscallArg::new("dirfd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
        ]),
        259 => SyscallDef::new("mknodat", SyscallType::INT, vec![
            SyscallArg::new("dirfd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
            SyscallArg::new("dev", SyscallType::INT),
        ]),
        260 => SyscallDef::new("fchownat", SyscallType::INT, vec![
        ]),
        261 => SyscallDef::new("futimesat", SyscallType::INT, vec![
        ]),
        263 => SyscallDef::new("unlinkat", SyscallType::INT, vec![
            SyscallArg::new("dirfd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        264 => SyscallDef::new("renameat", SyscallType::INT, vec![
        ]),
        265 => SyscallDef::new("linkat", SyscallType::INT, vec![
        ]),
        266 => SyscallDef::new("symlinkat", SyscallType::INT, vec![
            SyscallArg::new("oldpath", SyscallType::STR),
            SyscallArg::new("newdirfd", SyscallType::INT),
            SyscallArg::new("newpath", SyscallType::STR),
        ]),
        267 => SyscallDef::new("readlinkat", SyscallType::INT, vec![
        ]),
        268 => SyscallDef::new("fchmodat", SyscallType::INT, vec![
            SyscallArg::new("dirfd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        269 => SyscallDef::new("faccessat", SyscallType::INT, vec![
            SyscallArg::new("dirfd", SyscallType::INT),
            SyscallArg::new("pathname", SyscallType::STR),
            SyscallArg::new("mode", SyscallType::INT),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        270 => SyscallDef::new("pselect6", SyscallType::INT, vec![
        ]),
        271 => SyscallDef::new("ppoll", SyscallType::INT, vec![
        ]),
        272 => SyscallDef::new("unshare", SyscallType::INT, vec![
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        273 => SyscallDef::new("set_robust_list", SyscallType::INT, vec![
            SyscallArg::new("head", SyscallType::PTR),
            SyscallArg::new("len", SyscallType::UINT),
        ]),
        274 => SyscallDef::new("get_robust_list", SyscallType::INT, vec![
        ]),
        275 => SyscallDef::new("splice", SyscallType::UINT, vec![
        ]),
        276 => SyscallDef::new("tee", SyscallType::UINT, vec![
            SyscallArg::new("fd_in", SyscallType::INT),
            SyscallArg::new("fd_out", SyscallType::INT),
            SyscallArg::new("len", SyscallType::UINT),
            SyscallArg::new("flags", SyscallType::UINT),
        ]),
        277 => SyscallDef::new("sync_file_range", SyscallType::INT, vec![
        ]),
        278 => SyscallDef::new("vmsplice", SyscallType::UINT, vec![
        ]),
        279 => SyscallDef::new("move_pages", SyscallType::INT, vec![
        ]),
        280 => SyscallDef::new("utimensat", SyscallType::INT, vec![
        ]),
        281 => SyscallDef::new("epoll_pwait", SyscallType::INT, vec![
        ]),
        282 => SyscallDef::new("signalfd", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("mask", SyscallType::PTR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        283 => SyscallDef::new("timerfd_create", SyscallType::INT, vec![
            SyscallArg::new("clockid", SyscallType::INT),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        284 => SyscallDef::new("eventfd", SyscallType::INT, vec![
            SyscallArg::new("initval", SyscallType::UINT),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        285 => SyscallDef::new("fallocate", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("mode", SyscallType::INT),
            SyscallArg::new("offset", SyscallType::INT),
            SyscallArg::new("len", SyscallType::INT),
        ]),
        286 => SyscallDef::new("timerfd_settime", SyscallType::INT, vec![
        ]),
        287 => SyscallDef::new("timerfd_gettime", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("curr_value", SyscallType::PTR),
        ]),
        288 => SyscallDef::new("accept4", SyscallType::INT, vec![
        ]),
        289 => SyscallDef::new("signalfd4", SyscallType::INT, vec![
        ]),
        290 => SyscallDef::new("eventfd2", SyscallType::INT, vec![
        ]),
        291 => SyscallDef::new("epoll_create1", SyscallType::INT, vec![
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        292 => SyscallDef::new("dup3", SyscallType::INT, vec![
            SyscallArg::new("oldfd", SyscallType::INT),
            SyscallArg::new("newfd", SyscallType::INT),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        293 => SyscallDef::new("pipe2", SyscallType::INT, vec![
            SyscallArg::new("pipefd", SyscallType::PTR),
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        294 => SyscallDef::new("inotify_init1", SyscallType::INT, vec![
            SyscallArg::new("flags", SyscallType::INT),
        ]),
        295 => SyscallDef::new("preadv", SyscallType::UINT, vec![
        ]),
        296 => SyscallDef::new("pwritev", SyscallType::UINT, vec![
        ]),
        297 => SyscallDef::new("rt_tgsigqueueinfo", SyscallType::INT, vec![
        ]),
        298 => SyscallDef::new("perf_event_open", SyscallType::INT, vec![
        ]),
        299 => SyscallDef::new("recvmmsg", SyscallType::INT, vec![
        ]),
        306 => SyscallDef::new("syncfs", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
        ]),
        307 => SyscallDef::new("sendmmsg", SyscallType::INT, vec![
        ]),
        308 => SyscallDef::new("setns", SyscallType::INT, vec![
            SyscallArg::new("fd", SyscallType::INT),
            SyscallArg::new("nstype", SyscallType::INT),
        ]),
        309 => SyscallDef::new("getcpu", SyscallType::INT, vec![
            SyscallArg::new("cpu", SyscallType::UINT),
            SyscallArg::new("node", SyscallType::UINT),
            SyscallArg::new("tcache", SyscallType::PTR),
        ]),
        310 => SyscallDef::new("process_vm_readv", SyscallType::UINT, vec![
        ]),
        311 => SyscallDef::new("process_vm_writev", SyscallType::UINT, vec![
        ]),
        312 => SyscallDef::new("kcmp", SyscallType::INT, vec![
        ]),
        313 => SyscallDef::new("finit_module", SyscallType::INT, vec![
        ]),
        318 => SyscallDef::new("getrandom", SyscallType::UINT, vec![
            SyscallArg::new("buf", SyscallType::PTR),
            SyscallArg::new("buflen", SyscallType::UINT),
            SyscallArg::new("flags", SyscallType::UINT),
        ]),
    ];
}
