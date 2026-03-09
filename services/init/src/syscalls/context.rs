// ---------------------------------------------------------------------------
// SyscallContext: groups all per-process mutable state for syscall handlers.
// ---------------------------------------------------------------------------

use crate::fd::*;

/// Aggregated mutable references to per-process state.
/// Created once per syscall dispatch in child_handler, passed to sub-handlers.
pub(crate) struct SyscallContext<'a> {
    pub pid: usize,
    pub ep_cap: u64,

    // Memory management
    pub current_brk: &'a mut u64,
    pub mmap_next: &'a mut u64,
    pub my_brk_base: u64,
    pub my_mmap_base: u64,

    // FD tables (shared via GRP_ arrays)
    pub child_fds: &'a mut [u8; GRP_MAX_FDS],
    pub initrd_files: &'a mut [[u64; 4]; GRP_MAX_INITRD],
    pub initrd_file_buf_base: u64,
    pub vfs_files: &'a mut [[u64; 4]; GRP_MAX_VFS],

    // Directory state
    pub dir_buf: &'a mut [u8; 4096],
    pub dir_len: &'a mut usize,
    pub dir_pos: &'a mut usize,
    pub cwd: &'a mut [u8; GRP_CWD_MAX],

    // Socket metadata (parallel arrays indexed by FD)
    pub sock_conn_id: &'a mut [u32; GRP_MAX_FDS],
    pub sock_udp_local_port: &'a mut [u16; GRP_MAX_FDS],
    pub sock_udp_remote_ip: &'a mut [u32; GRP_MAX_FDS],
    pub sock_udp_remote_port: &'a mut [u16; GRP_MAX_FDS],

    // eventfd state (kind=22)
    pub eventfd_counter: &'a mut [u64; MAX_EVENTFDS],
    pub eventfd_flags: &'a mut [u32; MAX_EVENTFDS],
    pub eventfd_slot_fd: &'a mut [usize; MAX_EVENTFDS],

    // timerfd state (kind=23)
    pub timerfd_interval_ns: &'a mut [u64; MAX_TIMERFDS],
    pub timerfd_expiry_tsc: &'a mut [u64; MAX_TIMERFDS],
    pub timerfd_slot_fd: &'a mut [usize; MAX_TIMERFDS],

    // memfd state (kind=25)
    pub memfd_base: &'a mut [u64; MAX_MEMFDS],
    pub memfd_size: &'a mut [u64; MAX_MEMFDS],
    pub memfd_cap: &'a mut [u64; MAX_MEMFDS],
    pub memfd_slot_fd: &'a mut [usize; MAX_MEMFDS],

    // epoll registration state
    pub epoll_reg_fd: &'a mut [i32; MAX_EPOLL_ENTRIES],
    pub epoll_reg_events: &'a mut [u32; MAX_EPOLL_ENTRIES],
    pub epoll_reg_data: &'a mut [u64; MAX_EPOLL_ENTRIES],
}

pub(crate) const MAX_EVENTFDS: usize = 16;
pub(crate) const MAX_TIMERFDS: usize = 8;
pub(crate) const MAX_MEMFDS: usize = 8;
pub(crate) const MAX_EPOLL_ENTRIES: usize = 64;
