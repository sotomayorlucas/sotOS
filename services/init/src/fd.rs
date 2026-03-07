// ---------------------------------------------------------------------------
// FD table types, group management, and related helpers (extracted from main.rs)
// ---------------------------------------------------------------------------

use sotos_common::sys;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::process::MAX_PROCS;

// ---------------------------------------------------------------------------
// LUCAS FD table types (Phase 10.4)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum FdKind {
    Free = 0,
    Stdin = 1,
    Stdout = 2,
    VfsFile = 3,
    DirList = 4,
    Socket = 5,      // TCP socket
    PipeRead = 6,
    PipeWrite = 7,
    SocketUdp = 8,   // UDP socket
    EpollFd = 9,     // epoll instance
    DevUrandom = 10, // /dev/urandom, /dev/random
    DevZero = 11,    // /dev/zero
}

#[derive(Clone, Copy)]
pub(crate) struct FdEntry {
    pub(crate) kind: FdKind,
    pub(crate) vfs_fd: u32,
    /// For Socket/SocketUdp FDs: connection/socket ID in the net service.
    pub(crate) net_conn_id: u32,
    /// For SocketUdp: local port, remote IP, remote port (set by connect/sendto).
    pub(crate) udp_local_port: u16,
    pub(crate) udp_remote_ip: u32,
    pub(crate) udp_remote_port: u16,
    /// For EpollFd: index into epoll table.
    pub(crate) epoll_idx: u16,
    /// Socket flags (SOCK_NONBLOCK, SOCK_CLOEXEC).
    pub(crate) sock_flags: u16,
}

impl FdEntry {
    pub(crate) const fn free() -> Self {
        Self {
            kind: FdKind::Free, vfs_fd: 0, net_conn_id: 0,
            udp_local_port: 0, udp_remote_ip: 0, udp_remote_port: 0,
            epoll_idx: 0, sock_flags: 0,
        }
    }
    pub(crate) const fn new(kind: FdKind, vfs_fd: u32, net_conn_id: u32) -> Self {
        Self {
            kind, vfs_fd, net_conn_id,
            udp_local_port: 0, udp_remote_ip: 0, udp_remote_port: 0,
            epoll_idx: 0, sock_flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Uptime offset: make the system appear to have been running for 3 days.
// Applied to clock_gettime, gettimeofday, sysinfo, /proc/uptime.
// ---------------------------------------------------------------------------
pub(crate) const UPTIME_OFFSET_NS: u64 = 259_200 * 1_000_000_000; // 3 days in nanoseconds
pub(crate) const UPTIME_OFFSET_SECS: u64 = 259_200; // 3 days in seconds

// ---------------------------------------------------------------------------
// Epoll event table (Phase 4: real non-blocking epoll)
// ---------------------------------------------------------------------------
pub(crate) const MAX_EPOLL_INSTANCES: usize = 4;
pub(crate) const MAX_EPOLL_ENTRIES: usize = 16; // max FDs per epoll instance

/// EPOLL event flags (Linux ABI).
pub(crate) const EPOLLIN: u32 = 0x001;
pub(crate) const EPOLLOUT: u32 = 0x004;
pub(crate) const EPOLLERR: u32 = 0x008;
pub(crate) const EPOLLHUP: u32 = 0x010;

#[derive(Clone, Copy)]
pub(crate) struct EpollEntry {
    pub(crate) fd: u32,
    pub(crate) events: u32, // EPOLLIN, EPOLLOUT, etc.
    pub(crate) data: u64,   // user data (from epoll_event.data)
}

impl EpollEntry {
    pub(crate) const fn empty() -> Self { Self { fd: 0xFFFF, events: 0, data: 0 } }
}

/// Each epoll instance tracks up to MAX_EPOLL_ENTRIES file descriptors.
pub(crate) struct EpollInstance {
    pub(crate) entries: [EpollEntry; MAX_EPOLL_ENTRIES],
    pub(crate) count: usize,
}

impl EpollInstance {
    pub(crate) const fn new() -> Self {
        Self { entries: [EpollEntry::empty(); MAX_EPOLL_ENTRIES], count: 0 }
    }

    pub(crate) fn add(&mut self, fd: u32, events: u32, data: u64) -> bool {
        // Check if already exists (EPOLL_CTL_MOD behavior)
        for i in 0..self.count {
            if self.entries[i].fd == fd {
                self.entries[i].events = events;
                self.entries[i].data = data;
                return true;
            }
        }
        if self.count >= MAX_EPOLL_ENTRIES { return false; }
        self.entries[self.count] = EpollEntry { fd, events, data };
        self.count += 1;
        true
    }

    pub(crate) fn remove(&mut self, fd: u32) -> bool {
        for i in 0..self.count {
            if self.entries[i].fd == fd {
                self.entries[i] = self.entries[self.count - 1];
                self.count -= 1;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// MmapEntry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct MmapEntry {
    pub(crate) addr: u64,
    pub(crate) len: u64,
    pub(crate) pages: u32,
}

impl MmapEntry {
    pub(crate) const fn empty() -> Self {
        Self { addr: 0, len: 0, pages: 0 }
    }
}

// ---------------------------------------------------------------------------
// FD constants
// ---------------------------------------------------------------------------

pub(crate) const MAX_FDS: usize = 64;
pub(crate) const MAX_MMAPS: usize = 32;
pub(crate) const BRK_BASE: u64 = 0x2000000;
pub(crate) const BRK_LIMIT: u64 = 0x100000; // 1 MiB max heap (BRK_BASE..BRK_BASE+BRK_LIMIT)
pub(crate) const MMAP_BASE: u64 = 0x3000000;

// ---------------------------------------------------------------------------
// alloc_fd
// ---------------------------------------------------------------------------

/// Find the next free FD slot starting from `from`.
pub(crate) fn alloc_fd(fds: &[FdEntry; MAX_FDS], from: usize) -> Option<usize> {
    for i in from..MAX_FDS {
        if fds[i].kind == FdKind::Free {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// write_linux_stat
// ---------------------------------------------------------------------------

/// Write a Linux stat struct (144 bytes) into guest memory.
pub(crate) fn write_linux_stat(stat_ptr: u64, oid: u64, size: u64, is_dir: bool) {
    use sotos_common::linux_abi::{Stat, S_IFREG, S_IFDIR};
    let mut st = Stat::zeroed();
    st.st_ino = oid;
    st.st_nlink = 1;
    st.st_mode = if is_dir { S_IFDIR | 0o755 } else { S_IFREG | 0o644 };
    st.st_size = size as i64;
    st.st_blksize = 512;
    st.st_blocks = ((size + 511) / 512) as i64;
    unsafe { st.write_to(stat_ptr); }
}

// ---------------------------------------------------------------------------
// Per-group shared FD tables (protected by GRP_FD_LOCK spinlock).
// Each "group" corresponds to a thread group (process). Threads sharing
// CLONE_FILES point to the same group index.
// Uses `static mut` raw arrays for direct mutable reference compatibility
// with existing child_handler code. All mutations must hold the group lock.
// ---------------------------------------------------------------------------

pub(crate) const GRP_MAX_FDS: usize = 32;
pub(crate) const GRP_MAX_INITRD: usize = 8;
pub(crate) const GRP_MAX_VFS: usize = 8;

/// FD kind per slot: 0=free, 1=stdin, 2=stdout, 8=devnull, 9=devzero, 12=initrd, 13=vfs, 14=vfsdir.
pub(crate) static mut GRP_FDS: [[u8; GRP_MAX_FDS]; MAX_PROCS] = [[0; GRP_MAX_FDS]; MAX_PROCS];
/// Initrd file tracking per group: [data_vaddr, file_size, read_position, fd_index].
pub(crate) static mut GRP_INITRD: [[[u64; 4]; GRP_MAX_INITRD]; MAX_PROCS] = [[[0; 4]; GRP_MAX_INITRD]; MAX_PROCS];
/// VFS file tracking per group: [oid, size, position, fd_index].
pub(crate) static mut GRP_VFS: [[[u64; 4]; GRP_MAX_VFS]; MAX_PROCS] = [[[0; 4]; GRP_MAX_VFS]; MAX_PROCS];
/// Directory listing buffer per group.
pub(crate) static mut GRP_DIR_BUF: [[u8; 1024]; MAX_PROCS] = [[0; 1024]; MAX_PROCS];
/// Directory listing length per group.
pub(crate) static mut GRP_DIR_LEN: [usize; MAX_PROCS] = [0; MAX_PROCS];
/// Directory listing position per group.
pub(crate) static mut GRP_DIR_POS: [usize; MAX_PROCS] = [0; MAX_PROCS];

/// Spinlock per FD group (protects all GRP_ arrays for that group).
pub(crate) static GRP_FD_LOCK: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};

/// Shared brk state per memory group.
pub(crate) static mut GRP_BRK: [u64; MAX_PROCS] = [0; MAX_PROCS];
/// Shared mmap_next state per memory group.
pub(crate) static mut GRP_MMAP_NEXT: [u64; MAX_PROCS] = [0; MAX_PROCS];
/// Initrd file buf base per memory group.
pub(crate) static mut GRP_INITRD_BUF_BASE: [u64; MAX_PROCS] = [0; MAX_PROCS];

// ---------------------------------------------------------------------------
// FD group lock/unlock/init
// ---------------------------------------------------------------------------

/// Lock a FD group spinlock.
pub(crate) fn fd_grp_lock(g: usize) {
    while GRP_FD_LOCK[g].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
}

/// Unlock a FD group spinlock.
pub(crate) fn fd_grp_unlock(g: usize) {
    GRP_FD_LOCK[g].store(0, Ordering::Release);
}

/// Initialize a FD group with default stdin/stdout/stderr.
pub(crate) fn fd_grp_init(g: usize) {
    unsafe {
        GRP_FDS[g] = [0; GRP_MAX_FDS];
        GRP_FDS[g][0] = 1; // stdin
        GRP_FDS[g][1] = 2; // stdout
        GRP_FDS[g][2] = 2; // stderr
        GRP_INITRD[g] = [[0; 4]; GRP_MAX_INITRD];
        GRP_VFS[g] = [[0; 4]; GRP_MAX_VFS];
        GRP_DIR_BUF[g] = [0; 1024];
        GRP_DIR_LEN[g] = 0;
        GRP_DIR_POS[g] = 0;
    }
}
