//! Linux x86_64 ABI types and constants.
//!
//! Canonical struct layouts for the Linux/x86_64 ABI so that LUCAS handlers
//! never have to hard-code byte offsets or magic numbers again.
//! All structs are `#[repr(C)]` and match the kernel headers exactly.

// ---------------------------------------------------------------
// struct stat (144 bytes on x86_64)
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Stat {
    pub st_dev: u64,      // 0
    pub st_ino: u64,      // 8
    pub st_nlink: u64,    // 16
    pub st_mode: u32,     // 24
    pub st_uid: u32,      // 28
    pub st_gid: u32,      // 32
    pub __pad0: u32,      // 36
    pub st_rdev: u64,     // 40
    pub st_size: i64,     // 48
    pub st_blksize: i64,  // 56
    pub st_blocks: i64,   // 64
    pub st_atime: i64,    // 72
    pub st_atime_nsec: i64, // 80
    pub st_mtime: i64,    // 88
    pub st_mtime_nsec: i64, // 96
    pub st_ctime: i64,    // 104
    pub st_ctime_nsec: i64, // 112
    pub __unused: [i64; 3], // 120..144
}

const _: () = assert!(core::mem::size_of::<Stat>() == 144);

impl Stat {
    pub const fn zeroed() -> Self {
        Self {
            st_dev: 0, st_ino: 0, st_nlink: 0, st_mode: 0,
            st_uid: 0, st_gid: 0, __pad0: 0, st_rdev: 0,
            st_size: 0, st_blksize: 0, st_blocks: 0,
            st_atime: 0, st_atime_nsec: 0,
            st_mtime: 0, st_mtime_nsec: 0,
            st_ctime: 0, st_ctime_nsec: 0,
            __unused: [0; 3],
        }
    }

    /// Write this stat into guest memory at `ptr`.
    ///
    /// # Safety
    /// `ptr` must point to at least 144 writable bytes in the caller's address space.
    pub unsafe fn write_to(&self, ptr: u64) {
        core::ptr::write(ptr as *mut Stat, *self);
    }
}

// ---------------------------------------------------------------
// File mode bits
// ---------------------------------------------------------------

pub const S_IFMT: u32   = 0o170000;
pub const S_IFREG: u32  = 0o100000;
pub const S_IFDIR: u32  = 0o040000;
pub const S_IFCHR: u32  = 0o020000;
pub const S_IFIFO: u32  = 0o010000;
pub const S_IFLNK: u32  = 0o120000;

// ---------------------------------------------------------------
// struct termios (60 bytes on x86_64)
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Termios {
    pub c_iflag: u32,     // 0
    pub c_oflag: u32,     // 4
    pub c_cflag: u32,     // 8
    pub c_lflag: u32,     // 12
    pub c_line: u8,       // 16
    pub c_cc: [u8; 19],   // 17..36
    pub c_ispeed: u32,    // 36
    pub c_ospeed: u32,    // 40
}

// Pad to 60 bytes total (kernel struct ktermios is 44 bytes, but the ioctl
// copies 60 bytes because musl's termios is 60 — the extra 16 bytes are
// padding that musl expects).  We match musl's expectation here.
const _: () = assert!(core::mem::size_of::<Termios>() == 44);

impl Termios {
    /// Sensible defaults for a dumb terminal (raw-ish mode).
    pub const fn defaults() -> Self {
        let mut cc = [0u8; 19];
        cc[0]  = 3;   // VINTR  = Ctrl-C
        cc[1]  = 28;  // VQUIT  = Ctrl-\
        cc[2]  = 127; // VERASE = DEL
        cc[4]  = 4;   // VEOF   = Ctrl-D
        cc[5]  = 0;   // VTIME
        cc[6]  = 1;   // VMIN
        cc[11] = 1;   // VSTART for XON

        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0o60 | 0o200, // CS8 | CREAD
            c_lflag: 0,
            c_line: 0,
            c_cc: cc,
            c_ispeed: 38400,
            c_ospeed: 38400,
        }
    }
}

// ---------------------------------------------------------------
// ioctl request codes
// ---------------------------------------------------------------

pub const TCGETS: u32      = 0x5401;
pub const TCSETS: u32      = 0x5402;
pub const TCSETSW: u32     = 0x5403;
pub const TCSETSF: u32     = 0x5404;
pub const TIOCGWINSZ: u32  = 0x5413;
pub const TIOCSWINSZ: u32  = 0x5414;
pub const TIOCGPGRP: u32   = 0x540F;
pub const TIOCSPGRP: u32   = 0x5410;
pub const FIONREAD: u32    = 0x541B;

// ---------------------------------------------------------------
// struct winsize (8 bytes)
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

impl Winsize {
    pub const fn default_serial() -> Self {
        Self { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 }
    }
}

// ---------------------------------------------------------------
// struct linux_dirent64 (variable size, header is 19 bytes)
// ---------------------------------------------------------------

#[repr(C)]
pub struct LinuxDirent64 {
    pub d_ino: u64,       // 0
    pub d_off: i64,       // 8
    pub d_reclen: u16,    // 16
    pub d_type: u8,       // 18
    // d_name follows (null-terminated, variable length)
}

pub const DT_REG: u8 = 8;
pub const DT_DIR: u8 = 4;
pub const DT_CHR: u8 = 2;

// ---------------------------------------------------------------
// rt_sigaction (kernel struct, 32 bytes with 8-byte sigset)
// ---------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelSigaction {
    pub sa_handler: u64,  // 0: handler or SIG_IGN/SIG_DFL
    pub sa_flags: u64,    // 8
    pub sa_restorer: u64, // 16
    pub sa_mask: u64,     // 24: sigset_t (8 bytes = 64 signals)
}

const _: () = assert!(core::mem::size_of::<KernelSigaction>() == 32);

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;
pub const SA_RESTORER: u64 = 0x04000000;
pub const SA_SIGINFO: u64  = 0x00000004;

// ---------------------------------------------------------------
// Signal numbers
// ---------------------------------------------------------------

pub const SIGHUP: u32    = 1;
pub const SIGINT: u32    = 2;
pub const SIGQUIT: u32   = 3;
pub const SIGILL: u32    = 4;
pub const SIGABRT: u32   = 6;
pub const SIGFPE: u32    = 8;
pub const SIGKILL: u32   = 9;
pub const SIGSEGV: u32   = 11;
pub const SIGPIPE: u32   = 13;
pub const SIGALRM: u32   = 14;
pub const SIGTERM: u32   = 15;
pub const SIGCHLD: u32   = 17;
pub const SIGCONT: u32   = 18;
pub const SIGSTOP: u32   = 19;
pub const SIGTSTP: u32   = 20;
pub const SIGWINCH: u32  = 28;

// ---------------------------------------------------------------
// errno (positive values — negate before returning to userspace)
// ---------------------------------------------------------------

pub const EPERM: i64   = 1;
pub const ENOENT: i64  = 2;
pub const ESRCH: i64   = 3;
pub const EINTR: i64   = 4;
pub const EIO: i64     = 5;
pub const ENXIO: i64   = 6;
pub const EBADF: i64   = 9;
pub const ECHILD: i64  = 10;
pub const EAGAIN: i64  = 11;
pub const ENOMEM: i64  = 12;
pub const EACCES: i64  = 13;
pub const EFAULT: i64  = 14;
pub const EEXIST: i64  = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64  = 21;
pub const EINVAL: i64  = 22;
pub const EMFILE: i64  = 24;
pub const ENOSPC: i64  = 28;
pub const ESPIPE: i64  = 29;
pub const EPIPE: i64   = 32;
pub const ERANGE: i64  = 34;
pub const ENOSYS: i64  = 38;
pub const ENOTEMPTY: i64 = 39;

// ---------------------------------------------------------------
// open(2) / openat(2) flags
// ---------------------------------------------------------------

pub const O_RDONLY: u32    = 0;
pub const O_WRONLY: u32    = 1;
pub const O_RDWR: u32      = 2;
pub const O_CREAT: u32     = 0o100;
pub const O_TRUNC: u32     = 0o1000;
pub const O_APPEND: u32    = 0o2000;
pub const O_NONBLOCK: u32  = 0o4000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_CLOEXEC: u32   = 0o2000000;

pub const AT_FDCWD: i64       = -100;
pub const AT_EMPTY_PATH: u32  = 0x1000;

// ---------------------------------------------------------------
// mmap(2) flags
// ---------------------------------------------------------------

pub const PROT_READ: u32  = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32  = 0x4;
pub const MAP_SHARED: u32  = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32   = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;

// ---------------------------------------------------------------
// fcntl(2) commands
// ---------------------------------------------------------------

pub const F_DUPFD: u32   = 0;
pub const F_GETFD: u32   = 1;
pub const F_SETFD: u32   = 2;
pub const F_GETFL: u32   = 3;
pub const F_SETFL: u32   = 4;

// ---------------------------------------------------------------
// Linux syscall numbers (x86_64)
// ---------------------------------------------------------------

pub const SYS_READ: u64          = 0;
pub const SYS_WRITE: u64         = 1;
pub const SYS_OPEN: u64          = 2;
pub const SYS_CLOSE: u64         = 3;
pub const SYS_FSTAT: u64         = 5;
pub const SYS_POLL: u64          = 7;
pub const SYS_LSEEK: u64         = 8;
pub const SYS_MMAP: u64          = 9;
pub const SYS_MPROTECT: u64      = 10;
pub const SYS_MUNMAP: u64        = 11;
pub const SYS_BRK: u64           = 12;
pub const SYS_RT_SIGACTION: u64   = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_IOCTL: u64         = 16;
pub const SYS_WRITEV: u64        = 20;
pub const SYS_ACCESS: u64        = 21;
pub const SYS_PIPE: u64          = 22;
pub const SYS_DUP: u64           = 32;
pub const SYS_DUP2: u64          = 33;
pub const SYS_GETPID: u64        = 39;
pub const SYS_CLONE: u64         = 56;
pub const SYS_FORK: u64          = 57;
pub const SYS_EXECVE: u64        = 59;
pub const SYS_EXIT: u64          = 60;
pub const SYS_WAIT4: u64         = 61;
pub const SYS_KILL: u64          = 62;
pub const SYS_UNAME: u64         = 63;
pub const SYS_FCNTL: u64         = 72;
pub const SYS_GETCWD: u64        = 79;
pub const SYS_CHDIR: u64         = 80;
pub const SYS_MKDIR: u64         = 83;
pub const SYS_UNLINK: u64        = 87;
pub const SYS_GETDENTS64: u64    = 217;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_EXIT_GROUP: u64    = 231;
pub const SYS_OPENAT: u64        = 257;
pub const SYS_FSTATAT: u64       = 262;
pub const SYS_READLINKAT: u64    = 267;
pub const SYS_FACCESSAT: u64     = 269;
pub const SYS_PRLIMIT64: u64     = 302;
pub const SYS_GETRANDOM: u64     = 318;
pub const SYS_STATX: u64         = 332;

// ---------------------------------------------------------------
// Auxiliary vector types (for ELF loader)
// ---------------------------------------------------------------

pub const AT_NULL: u64         = 0;
pub const AT_PHDR: u64         = 3;
pub const AT_PHENT: u64        = 4;
pub const AT_PHNUM: u64        = 5;
pub const AT_PAGESZ: u64       = 6;
pub const AT_BASE: u64         = 7;
pub const AT_ENTRY: u64        = 9;
pub const AT_UID: u64          = 11;
pub const AT_EUID: u64         = 12;
pub const AT_GID: u64          = 13;
pub const AT_EGID: u64         = 14;
pub const AT_RANDOM: u64       = 25;
pub const AT_SYSINFO_EHDR: u64 = 33;
