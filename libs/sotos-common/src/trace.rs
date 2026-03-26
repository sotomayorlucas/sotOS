//! Shared tracing constants and helpers for sotOS.
//!
//! This module provides trace levels, category bitmasks, and formatting helpers
//! used by both the kernel and userspace services. NO I/O logic lives here.

/// Trace severity level, ordered from most to least severe.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TraceLevel {
    Error = 0,
    Warn  = 1,
    Info  = 2,
    Debug = 3,
    Trace = 4,
}

impl TraceLevel {
    /// Return a single ASCII byte representing the level: E/W/I/D/T.
    pub const fn as_byte(self) -> u8 {
        match self {
            TraceLevel::Error => b'E',
            TraceLevel::Warn  => b'W',
            TraceLevel::Info  => b'I',
            TraceLevel::Debug => b'D',
            TraceLevel::Trace => b'T',
        }
    }
}

/// Category bitmask constants for trace filtering.
pub mod cat {
    pub const SYSCALL:  u16 = 1 << 0;
    pub const IPC:      u16 = 1 << 1;
    pub const SCHED:    u16 = 1 << 2;
    pub const MM:       u16 = 1 << 3;
    pub const FS:       u16 = 1 << 4;
    pub const NET:      u16 = 1 << 5;
    pub const SIGNAL:   u16 = 1 << 6;
    pub const PROCESS:  u16 = 1 << 7;
    pub const REGISTER: u16 = 1 << 8;
    pub const ALL:      u16 = 0xFFFF;
}

/// Return a short human-readable name for the lowest set bit in `mask`.
pub const fn cat_name_bytes(mask: u16) -> &'static [u8] {
    if mask & cat::SYSCALL  != 0 { return b"SYSCALL"; }
    if mask & cat::IPC      != 0 { return b"IPC"; }
    if mask & cat::SCHED    != 0 { return b"SCHED"; }
    if mask & cat::MM       != 0 { return b"MM"; }
    if mask & cat::FS       != 0 { return b"FS"; }
    if mask & cat::NET      != 0 { return b"NET"; }
    if mask & cat::SIGNAL   != 0 { return b"SIGNAL"; }
    if mask & cat::PROCESS  != 0 { return b"PROCESS"; }
    if mask & cat::REGISTER != 0 { return b"REG"; }
    b"???"
}

/// Map a Linux x86_64 syscall number to its lowercase name (without `sys_` prefix).
///
/// All constants are sourced from `crate::linux_abi::SYS_*`.
pub const fn syscall_name(nr: u64) -> &'static [u8] {
    match nr {
        0   => b"read",
        1   => b"write",
        2   => b"open",
        3   => b"close",
        4   => b"stat",
        5   => b"fstat",
        6   => b"lstat",
        7   => b"poll",
        8   => b"lseek",
        9   => b"mmap",
        10  => b"mprotect",
        11  => b"munmap",
        12  => b"brk",
        13  => b"rt_sigaction",
        14  => b"rt_sigprocmask",
        15  => b"rt_sigreturn",
        16  => b"ioctl",
        17  => b"pread64",
        18  => b"pwrite64",
        19  => b"readv",
        20  => b"writev",
        21  => b"access",
        22  => b"pipe",
        23  => b"select",
        24  => b"sched_yield",
        25  => b"mremap",
        26  => b"msync",
        27  => b"mincore",
        28  => b"madvise",
        29  => b"shmget",
        30  => b"shmat",
        31  => b"shmctl",
        32  => b"dup",
        33  => b"dup2",
        34  => b"pause",
        35  => b"nanosleep",
        36  => b"getitimer",
        37  => b"alarm",
        38  => b"setitimer",
        39  => b"getpid",
        40  => b"sendfile",
        41  => b"socket",
        42  => b"connect",
        43  => b"accept",
        44  => b"sendto",
        45  => b"recvfrom",
        46  => b"sendmsg",
        47  => b"recvmsg",
        48  => b"shutdown",
        49  => b"bind",
        50  => b"listen",
        51  => b"getsockname",
        52  => b"getpeername",
        53  => b"socketpair",
        54  => b"setsockopt",
        55  => b"getsockopt",
        56  => b"clone",
        57  => b"fork",
        58  => b"vfork",
        59  => b"execve",
        60  => b"exit",
        61  => b"wait4",
        62  => b"kill",
        63  => b"uname",
        72  => b"fcntl",
        73  => b"flock",
        74  => b"fsync",
        75  => b"fdatasync",
        77  => b"ftruncate",
        79  => b"getcwd",
        80  => b"chdir",
        82  => b"rename",
        83  => b"mkdir",
        84  => b"rmdir",
        85  => b"creat",
        86  => b"link",
        87  => b"unlink",
        88  => b"symlink",
        89  => b"readlink",
        90  => b"chmod",
        91  => b"fchmod",
        93  => b"fchown",
        94  => b"lchown",
        95  => b"umask",
        96  => b"gettimeofday",
        97  => b"getrlimit",
        98  => b"getrusage",
        99  => b"sysinfo",
        100 => b"times",
        102 => b"getuid",
        104 => b"getgid",
        105 => b"setuid",
        106 => b"setgid",
        107 => b"geteuid",
        108 => b"getegid",
        109 => b"setpgid",
        110 => b"getppid",
        111 => b"getpgrp",
        112 => b"setsid",
        113 => b"setreuid",
        114 => b"setregid",
        115 => b"getgroups",
        116 => b"setgroups",
        117 => b"setresuid",
        118 => b"getresuid",
        119 => b"setresgid",
        120 => b"getresgid",
        121 => b"getpgid",
        122 => b"setfsuid",
        123 => b"setfsgid",
        124 => b"getsid",
        125 => b"capget",
        126 => b"capset",
        127 => b"rt_sigpending",
        128 => b"rt_sigtimedwait",
        129 => b"rt_sigqueueinfo",
        130 => b"rt_sigsuspend",
        131 => b"sigaltstack",
        133 => b"mknod",
        135 => b"personality",
        137 => b"statfs",
        138 => b"fstatfs",
        140 => b"getpriority",
        141 => b"setpriority",
        143 => b"sched_getparam",
        144 => b"sched_setscheduler",
        145 => b"sched_getscheduler",
        146 => b"sched_get_priority_max",
        147 => b"sched_get_priority_min",
        149 => b"mlock",
        150 => b"munlock",
        151 => b"mlockall",
        152 => b"munlockall",
        155 => b"prctl",
        157 => b"setrlimit",
        186 => b"gettid",
        200 => b"tkill",
        201 => b"time",
        202 => b"futex",
        203 => b"sched_setaffinity",
        204 => b"sched_getaffinity",
        206 => b"io_setup",
        207 => b"io_destroy",
        208 => b"io_getevents",
        209 => b"io_submit",
        210 => b"io_cancel",
        213 => b"epoll_create",
        217 => b"getdents64",
        218 => b"set_tid_address",
        221 => b"fadvise64",
        228 => b"clock_gettime",
        229 => b"clock_getres",
        230 => b"clock_nanosleep",
        231 => b"exit_group",
        232 => b"epoll_wait",
        233 => b"epoll_ctl",
        234 => b"tgkill",
        235 => b"utimes",
        247 => b"waitid",
        254 => b"inotify_add_watch",
        255 => b"inotify_rm_watch",
        257 => b"openat",
        258 => b"mkdirat",
        259 => b"mknodat",
        260 => b"fchownat",
        261 => b"futimesat",
        262 => b"fstatat",
        263 => b"unlinkat",
        264 => b"renameat",
        265 => b"linkat",
        266 => b"symlinkat",
        267 => b"readlinkat",
        268 => b"fchmodat",
        269 => b"faccessat",
        270 => b"pselect6",
        271 => b"ppoll",
        272 => b"unshare",
        273 => b"set_robust_list",
        274 => b"get_robust_list",
        275 => b"splice",
        276 => b"tee",
        280 => b"utimensat",
        281 => b"epoll_pwait",
        282 => b"signalfd",
        283 => b"timerfd_create",
        284 => b"eventfd",
        285 => b"fallocate",
        286 => b"timerfd_settime",
        287 => b"timerfd_gettime",
        288 => b"accept4",
        289 => b"signalfd4",
        290 => b"eventfd2",
        291 => b"epoll_create1",
        292 => b"dup3",
        293 => b"pipe2",
        302 => b"prlimit64",
        295 => b"preadv",
        296 => b"pwritev",
        294 => b"inotify_init1",
        316 => b"renameat2",
        318 => b"getrandom",
        319 => b"memfd_create",
        326 => b"copy_file_range",
        332 => b"statx",
        334 => b"rseq",
        435 => b"clone3",
        439 => b"faccessat2",
        _   => b"unknown",
    }
}

/// Format `"  NAME=0x<16hex>\n"` into `buf`, returning the number of bytes written.
///
/// `name` is the register label (e.g. b"rdi"). The output always uses exactly
/// 16 hex digits (zero-padded) for the value.
pub fn fmt_reg(name: &[u8], val: u64, buf: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pos = 0;
    // "  "
    if pos < buf.len() { buf[pos] = b' '; pos += 1; }
    if pos < buf.len() { buf[pos] = b' '; pos += 1; }
    // name
    for &b in name {
        if pos >= buf.len() { break; }
        buf[pos] = b;
        pos += 1;
    }
    // "=0x"
    if pos < buf.len() { buf[pos] = b'='; pos += 1; }
    if pos < buf.len() { buf[pos] = b'0'; pos += 1; }
    if pos < buf.len() { buf[pos] = b'x'; pos += 1; }
    // 16 hex digits
    for i in (0..16).rev() {
        if pos >= buf.len() { break; }
        buf[pos] = HEX[((val >> (i * 4)) & 0xF) as usize];
        pos += 1;
    }
    // newline
    if pos < buf.len() { buf[pos] = b'\n'; pos += 1; }
    pos
}
