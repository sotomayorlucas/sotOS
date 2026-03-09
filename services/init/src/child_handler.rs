// ---------------------------------------------------------------------------
// child_handler: Full-featured handler for child processes.
// Extracted from main.rs.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_common::linux_abi::*;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::framebuffer::{print, print_u64, fb_putchar, kb_has_char, kb_read_char};
use crate::exec::{reply_val, rdtsc, exec_from_initrd, exec_from_initrd_argv,
                  EXEC_LOCK, MAX_EXEC_ARG_LEN, MAX_EXEC_ARGS,
                  format_u64_into, copy_guest_path, starts_with,
                  format_uptime_into, format_proc_self_stat};
use crate::process::*;
use crate::fd::*;
use crate::net::{NET_CMD_TCP_CONNECT, NET_CMD_TCP_SEND, NET_CMD_TCP_RECV, NET_CMD_TCP_CLOSE,
                 NET_CMD_UDP_BIND, NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::syscall_log::{syscall_log_record, format_syslog_into};
use crate::vdso;
use crate::{NET_EP_CAP, vfs_lock, vfs_unlock, shared_store};

const MAP_WRITABLE: u64 = 2;

/// Open a virtual file (/etc/*, /proc/*, /sys/*). Returns Some(content_len) or None.
fn open_virtual_file(name: &[u8], dir_buf: &mut [u8]) -> Option<usize> {
    if starts_with(name, b"/etc/") {
        let gen_len: usize;
        if name == b"/etc/nanorc" {
            let c = b"set nohelp\nset nonewlines\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/resolv.conf" {
            let c = b"nameserver 10.0.2.3\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/hosts" {
            let c = b"127.0.0.1 localhost\n::1 localhost\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/nsswitch.conf" {
            let c = b"hosts: files dns\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/ld.so.cache" {
            return None;
        } else if name == b"/etc/ld.so.preload" {
            gen_len = 0;
        } else if name == b"/etc/passwd" {
            let c = b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/bin/nologin\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/group" {
            let c = b"root:x:0:\nnogroup:x:65534:\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/gai.conf" || name == b"/etc/host.conf"
               || name == b"/etc/services" || name == b"/etc/protocols"
               || name == b"/etc/shells" || name == b"/etc/inputrc"
               || name == b"/etc/terminfo" || name == b"/etc/mime.types"
               || name == b"/etc/localtime" || name == b"/etc/locale.alias" {
            gen_len = 0;
        } else {
            return None;
        }
        Some(gen_len)
    } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
        let gen_len: usize;
        if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
            let map_text = b"\
00400000-00500000 r-xp 00000000 00:00 0          [text]\n\
00e30000-00e34000 rw-p 00000000 00:00 0          [stack]\n\
07000000-07200000 rw-p 00000000 00:00 0          [heap]\n\
00b80000-00b81000 r-xp 00000000 00:00 0          [vdso]\n";
            let n = map_text.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&map_text[..n]);
            gen_len = n;
        } else if name == b"/proc/cpuinfo" {
            let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/meminfo" {
            let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/version" {
            let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/self/exe" {
            gen_len = 0;
        } else if name == b"/sys/devices/system/cpu/online" {
            let c = b"0\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else {
            return None;
        }
        Some(gen_len)
    } else {
        None
    }
}

/// CSPRNG: ChaCha20-based, seeded from RDTSC.
fn fill_random(buf: &mut [u8]) {
    use rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    static mut RNG: Option<ChaCha20Rng> = None;
    unsafe {
        if RNG.is_none() {
            let mut seed = [0u8; 32];
            let tsc = rdtsc();
            seed[0..8].copy_from_slice(&tsc.to_le_bytes());
            let tsc2 = rdtsc();
            seed[8..16].copy_from_slice(&tsc2.to_le_bytes());
            let tsc3 = rdtsc();
            seed[16..24].copy_from_slice(&tsc3.to_le_bytes());
            RNG = Some(ChaCha20Rng::from_seed(seed));
        }
        RNG.as_mut().unwrap().fill_bytes(buf);
    }
}

/// Trampoline for clone(CLONE_THREAD) child threads.
/// Stack layout set up by the handler: [fn_ptr, arg, tls_ptr] (growing upward from RSP).
/// Calls arch_prctl(SET_FS, tls) if tls != 0, then calls fn(arg), then exit.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn clone_child_trampoline() -> ! {
    core::arch::naked_asm!(
        "pop rsi",              // fn_ptr
        "pop rdi",              // arg
        "pop rdx",              // tls_ptr (0 if no CLONE_SETTLS)
        "test rdx, rdx",
        "jz 2f",
        // arch_prctl(ARCH_SET_FS, tls) — intercepted by kernel before redirect
        "push rsi",
        "push rdi",
        "mov rdi, 0x1002",      // ARCH_SET_FS
        "mov rsi, rdx",
        "mov rax, 158",         // SYS_arch_prctl
        "syscall",
        "pop rdi",
        "pop rsi",
        "2:",
        "xor ebp, ebp",
        "call rsi",             // fn(arg)
        "mov edi, eax",         // exit status = fn return value
        "mov eax, 60",          // SYS_exit
        "syscall",
        "ud2",
    );
}

/// Child process handler — full-featured handler for child processes.
/// Supports brk, mmap, munmap, FD table (shared via GRP_ tables),
/// file I/O, all musl-libc init syscalls, execve, clone(CLONE_THREAD), and futex.
pub(crate) extern "C" fn child_handler() -> ! {
    // Wait for parent to provide setup info
    while CHILD_SETUP_READY.load(Ordering::Acquire) != 1 {
        sys::yield_now();
    }
    let mut ep_cap = CHILD_SETUP_EP.load(Ordering::Acquire);
    let pid = CHILD_SETUP_PID.load(Ordering::Acquire) as usize;
    let parent_pid = PROC_PARENT[pid - 1].load(Ordering::Acquire);
    let clone_flags = CHILD_SETUP_FLAGS.load(Ordering::Acquire);
    // Signal that we consumed the setup
    CHILD_SETUP_READY.store(0, Ordering::Release);

    // Resolve group indices for this thread
    let fdg = PROC_FD_GROUP[pid - 1].load(Ordering::Acquire) as usize;
    let memg = PROC_MEM_GROUP[pid - 1].load(Ordering::Acquire) as usize;
    let _sigg = PROC_SIG_GROUP[pid - 1].load(Ordering::Acquire) as usize;

    // Per-child brk/mmap state. Each memory group gets its own region.
    const CHILD_REGION_SIZE: u64 = 0x4000000; // 64 MiB per child (brk + mmap)
    const CHILD_BRK_BASE: u64 = 0x7000000;
    const CHILD_MMAP_OFFSET: u64 = 0x1000000; // mmap starts 16 MiB into the region
    // Initrd file buffers: separate region well above brk/mmap
    // 16 children × 64 MiB = 1 GiB → ends at 0x47000000.
    // Virtual addresses: pages are demand-allocated from physical RAM.
    const INITRD_BUF_REGION: u64 = 0x48000000;
    const INITRD_BUF_PER_GROUP: u64 = 8 * 0x300000; // 24 MiB

    // Initialize memory group state if this is a new group (not CLONE_VM reuse)
    unsafe {
        if clone_flags & CLONE_VM == 0 || GRP_BRK[memg] == 0 {
            let my_brk_base = CHILD_BRK_BASE + ((memg as u64) % 16) * CHILD_REGION_SIZE;
            GRP_BRK[memg] = my_brk_base;
            GRP_MMAP_NEXT[memg] = my_brk_base + CHILD_MMAP_OFFSET;
            GRP_INITRD_BUF_BASE[memg] = INITRD_BUF_REGION + ((memg as u64) % 16) * INITRD_BUF_PER_GROUP;
        }
    }

    // Compute the brk base for this memory group (needed for limit checks).
    let my_brk_base = CHILD_BRK_BASE + ((memg as u64) % 16) * CHILD_REGION_SIZE;
    let my_mmap_base = my_brk_base + CHILD_MMAP_OFFSET;

    // Record brk/mmap base for this process (for cleanup on exit)
    if pid > 0 && pid <= MAX_PROCS {
        PROC_BRK_BASE[pid - 1].store(my_brk_base, Ordering::Release);
        PROC_BRK_CURRENT[pid - 1].store(my_brk_base, Ordering::Release);
        PROC_MMAP_BASE[pid - 1].store(my_mmap_base, Ordering::Release);
        PROC_MMAP_NEXT[pid - 1].store(my_mmap_base, Ordering::Release);
    }

    // Create local mutable references to the shared FD and memory state.
    // These are references into `static mut` arrays, protected by GRP_FD_LOCK[fdg].
    // This gives backward compatibility: existing code using child_fds[fd],
    // initrd_files[s][i], vfs_files[s][i], etc. works unchanged.
    const CHILD_MAX_FDS: usize = GRP_MAX_FDS;
    const MAX_INITRD_FILES: usize = GRP_MAX_INITRD;
    let child_fds: &mut [u8; GRP_MAX_FDS] = unsafe { &mut GRP_FDS[fdg] };
    let initrd_files: &mut [[u64; 4]; GRP_MAX_INITRD] = unsafe { &mut GRP_INITRD[fdg] };
    let initrd_file_buf_base: u64 = unsafe { GRP_INITRD_BUF_BASE[memg] };
    const MAX_VFS_FILES: usize = GRP_MAX_VFS;
    let vfs_files: &mut [[u64; 4]; GRP_MAX_VFS] = unsafe { &mut GRP_VFS[fdg] };
    let dir_buf: &mut [u8; 4096] = unsafe { &mut GRP_DIR_BUF[fdg] };
    let dir_len: &mut usize = unsafe { &mut GRP_DIR_LEN[fdg] };
    let dir_pos: &mut usize = unsafe { &mut GRP_DIR_POS[fdg] };
    // current_brk and mmap_next: mutable references into GRP_BRK/GRP_MMAP_NEXT
    let current_brk: &mut u64 = unsafe { &mut GRP_BRK[memg] };
    let mmap_next: &mut u64 = unsafe { &mut GRP_MMAP_NEXT[memg] };

    // Socket state (parallel arrays indexed by FD number)
    // FD kind 16=TCP socket, 17=UDP socket
    let mut sock_conn_id: [u32; GRP_MAX_FDS] = [0xFFFF; GRP_MAX_FDS];
    let mut sock_udp_local_port: [u16; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
    let mut sock_udp_remote_ip: [u32; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
    let mut sock_udp_remote_port: [u16; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
    static NEXT_UDP_PORT: AtomicU64 = AtomicU64::new(49152);

    // ─── Phase C: eventfd state (kind=22) ───
    const MAX_EVENTFDS: usize = 16;
    let mut eventfd_counter: [u64; MAX_EVENTFDS] = [0; MAX_EVENTFDS];
    let mut eventfd_flags: [u32; MAX_EVENTFDS] = [0; MAX_EVENTFDS];
    let mut eventfd_slot_fd: [usize; MAX_EVENTFDS] = [usize::MAX; MAX_EVENTFDS];

    // ─── Phase C: timerfd state (kind=23) ───
    const MAX_TIMERFDS: usize = 8;
    let mut timerfd_interval_ns: [u64; MAX_TIMERFDS] = [0; MAX_TIMERFDS];
    let mut timerfd_expiry_tsc: [u64; MAX_TIMERFDS] = [0; MAX_TIMERFDS];
    let mut timerfd_slot_fd: [usize; MAX_TIMERFDS] = [usize::MAX; MAX_TIMERFDS];

    // ─── Phase C: epoll state (kind=21, improved) ───
    const MAX_EPOLL_ENTRIES: usize = 64;
    let mut epoll_reg_fd: [i32; MAX_EPOLL_ENTRIES] = [-1; MAX_EPOLL_ENTRIES];
    let mut epoll_reg_events: [u32; MAX_EPOLL_ENTRIES] = [0; MAX_EPOLL_ENTRIES];
    let mut epoll_reg_data: [u64; MAX_EPOLL_ENTRIES] = [0; MAX_EPOLL_ENTRIES];

    // ─── Phase C: memfd state (kind=25) ───
    const MAX_MEMFDS: usize = 8;
    let mut memfd_base: [u64; MAX_MEMFDS] = [0; MAX_MEMFDS];
    let mut memfd_size: [u64; MAX_MEMFDS] = [0; MAX_MEMFDS];
    let mut memfd_cap: [u64; MAX_MEMFDS] = [0; MAX_MEMFDS];
    let mut memfd_slot_fd: [usize; MAX_MEMFDS] = [usize::MAX; MAX_MEMFDS];

    // ─── Phase B: sigaltstack ───
    let mut sigalt_sp: u64 = 0;
    let mut sigalt_size: u64 = 0;
    let mut sigalt_flags: u32 = 2; // SS_DISABLE

    loop {
        // Use recv_timeout (500 ticks = ~5s at 100Hz) to detect hung children.
        // A child stuck in an infinite fault loop will never make another syscall.
        let msg = match sys::recv_timeout(ep_cap, 500) {
            Ok(m) => m,
            Err(e) => {
                if e == sotos_common::SysError::Timeout as i64 {
                    // Child hasn't made a syscall in 5 seconds — hung.
                }
                break;
            },
        };

        // Cache the kernel thread ID for async signal injection
        let kernel_tid = msg.regs[6];
        if kernel_tid != 0 {
            PROC_KERNEL_TID[pid - 1].store(kernel_tid, Ordering::Release);
        }

        // Check for pending unblocked signals
        let sig = sig_dequeue(pid);
        if sig != 0 {
            let child_tid = kernel_tid;
            match sig_dispatch(pid, sig) {
                1 => break, // terminated
                2 => { reply_val(ep_cap, -EINTR); continue; } // -EINTR
                3 => {
                    // User handler registered — deliver signal via frame injection
                    if signal_deliver(ep_cap, pid, sig, child_tid, 0, false) {
                        continue; // signal_deliver already replied
                    }
                    // Delivery failed (no restorer, etc.) — fall through
                }
                _ => {} // ignored, continue
            }
        }

        let syscall_nr = msg.tag;
        // Phase 5: Syscall shadow logging (record every child syscall)
        syscall_log_record(pid as u16, syscall_nr as u16, msg.regs[0], 0);
        match syscall_nr {
            // SYS_read(fd, buf, len)
            SYS_READ => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF); // -EBADF
                    continue;
                }
                match child_fds[fd] {
                    1 => {
                        // stdin
                        if len == 0 { reply_val(ep_cap, 0); continue; }
                        loop {
                            let s = sig_dequeue(pid);
                            if s != 0 && sig_dispatch(pid, s) >= 1 {
                                reply_val(ep_cap, -EINTR); break; // -EINTR
                            }
                            match unsafe { kb_read_char() } {
                                Some(0x03) => { reply_val(ep_cap, -EINTR); break; }
                                Some(ch) => {
                                    unsafe { *(buf_ptr as *mut u8) = ch; }
                                    let reply = sotos_common::IpcMsg {
                                        tag: 0,
                                        regs: [1, ch as u64, 0, 0, 0, 0, 0, 0],
                                    };
                                    let _ = sys::send(ep_cap, &reply);
                                    break;
                                }
                                None => { sys::yield_now(); }
                            }
                        }
                    }
                    9 => {
                        // /dev/zero → fill buffer with zeros
                        let n = len.min(4096);
                        if n > 0 {
                            unsafe { core::ptr::write_bytes(buf_ptr as *mut u8, 0, n); }
                        }
                        reply_val(ep_cap, n as i64);
                    }
                    20 => {
                        // /dev/urandom → fill buffer with ChaCha20 CSPRNG
                        let n = len.min(4096);
                        if n > 0 {
                            let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                            fill_random(dst);
                        }
                        reply_val(ep_cap, n as i64);
                    }
                    8 => reply_val(ep_cap, 0), // /dev/null → EOF
                    22 => {
                        // eventfd read: return counter, reset to 0
                        if len < 8 { reply_val(ep_cap, -EINVAL); continue; }
                        if let Some(slot) = eventfd_slot_fd.iter().position(|&x| x == fd) {
                            let val = eventfd_counter[slot];
                            if val == 0 {
                                // Non-blocking: EAGAIN. Wine uses EFD_NONBLOCK.
                                reply_val(ep_cap, -EAGAIN);
                            } else {
                                unsafe { *(buf_ptr as *mut u64) = val; }
                                eventfd_counter[slot] = 0;
                                reply_val(ep_cap, 8);
                            }
                        } else { reply_val(ep_cap, -EBADF); }
                    }
                    23 => {
                        // timerfd read: return expiration count
                        if len < 8 { reply_val(ep_cap, -EINVAL); continue; }
                        if let Some(slot) = timerfd_slot_fd.iter().position(|&x| x == fd) {
                            let now = rdtsc();
                            let exp = timerfd_expiry_tsc[slot];
                            if exp != 0 && now >= exp {
                                unsafe { *(buf_ptr as *mut u64) = 1; }
                                // Re-arm if interval set
                                if timerfd_interval_ns[slot] != 0 {
                                    timerfd_expiry_tsc[slot] = now + timerfd_interval_ns[slot] * 2; // ~2GHz
                                } else {
                                    timerfd_expiry_tsc[slot] = 0; // one-shot, disarmed
                                }
                                reply_val(ep_cap, 8);
                            } else {
                                reply_val(ep_cap, -EAGAIN); // not expired
                            }
                        } else { reply_val(ep_cap, -EBADF); }
                    }
                    25 => {
                        // memfd read
                        if let Some(slot) = memfd_slot_fd.iter().position(|&x| x == fd) {
                            let base = memfd_base[slot];
                            let sz = memfd_size[slot];
                            // Use vfs_files for offset tracking
                            let mut offset = 0u64;
                            for s in 0..MAX_VFS_FILES {
                                if vfs_files[s][3] == fd as u64 && vfs_files[s][0] == 0xFEFD {
                                    offset = vfs_files[s][2];
                                    let avail = if offset < sz { sz - offset } else { 0 };
                                    let n = (len as u64).min(avail) as usize;
                                    if n > 0 {
                                        unsafe { core::ptr::copy_nonoverlapping((base + offset) as *const u8, buf_ptr as *mut u8, n); }
                                        vfs_files[s][2] += n as u64;
                                    }
                                    reply_val(ep_cap, n as i64);
                                    break;
                                }
                            }
                        } else { reply_val(ep_cap, -EBADF); }
                    }
                    12 => {
                        // Initrd file: find the slot for this FD
                        let mut found = false;
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                                let data_base = initrd_files[s][0];
                                let file_size = initrd_files[s][1];
                                let pos = initrd_files[s][2];
                                let avail = if pos < file_size { file_size - pos } else { 0 };
                                let to_read = (len as u64).min(avail) as usize;
                                if to_read > 0 {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (data_base + pos) as *const u8,
                                            buf_ptr as *mut u8,
                                            to_read,
                                        );
                                    }
                                    initrd_files[s][2] = pos + to_read as u64;
                                }
                                reply_val(ep_cap, to_read as i64);
                                found = true;
                                break;
                            }
                        }
                        if !found { reply_val(ep_cap, -EBADF); }
                    }
                    13 => {
                        // VFS file: read via shared ObjectStore
                        let mut found = false;
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                let oid = vfs_files[s][0];
                                let pos = vfs_files[s][2] as usize;
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                                vfs_lock();
                                let result = unsafe { shared_store() }
                                    .and_then(|store| store.read_obj_range(oid, pos, dst).ok());
                                vfs_unlock();
                                match result {
                                    Some(n) => {
                                        vfs_files[s][2] += n as u64;
                                        reply_val(ep_cap, n as i64);
                                    }
                                    None => reply_val(ep_cap, -EIO), // -EIO
                                }
                                found = true;
                                break;
                            }
                        }
                        if !found { reply_val(ep_cap, -EBADF); }
                    }
                    15 => {
                        // Procfs virtual file: read from dir_buf
                        let avail = if *dir_pos < *dir_len { *dir_len - *dir_pos } else { 0 };
                        let to_read = len.min(avail);
                        if to_read > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    dir_buf[*dir_pos..].as_ptr(),
                                    buf_ptr as *mut u8,
                                    to_read,
                                );
                            }
                            *dir_pos += to_read;
                        }
                        reply_val(ep_cap, to_read as i64);
                    }
                    16 => {
                        // TCP socket read → NET_CMD_TCP_RECV (retry up to 5000 times)
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = sock_conn_id[fd] as u64;
                        let recv_len = len.min(64);
                        let mut got = 0usize;
                        let mut tcp_retries = 0u32;
                        while tcp_retries < 5000 {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_RECV,
                                regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 200) {
                                Ok(resp) => {
                                    let n = resp.tag as usize; // tag = byte count
                                    if n > 0 && n <= recv_len {
                                        unsafe {
                                            let src = &resp.regs[0] as *const u64 as *const u8; // data at regs[0]
                                            core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                        }
                                        got = n;
                                        break;
                                    }
                                    // n==0: no data yet, retry
                                }
                                Err(_) => {} // timeout, retry
                            }
                            sys::yield_now();
                            tcp_retries += 1;
                        }
                        if got > 0 {
                            reply_val(ep_cap, got as i64);
                        } else {
                            reply_val(ep_cap, -EAGAIN); // -EAGAIN after exhausting retries
                        }
                    }
                    17 => {
                        // UDP socket read → NET_CMD_UDP_RECV
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let port = sock_udp_local_port[fd];
                        let recv_len = len.min(56);
                        if net_cap == 0 || port == 0 {
                            reply_val(ep_cap, -EBADF);
                        } else {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_RECV,
                                regs: [port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let n = resp.tag as usize; // tag = byte count
                                    if n > 0 && n <= recv_len {
                                        unsafe {
                                            let src = &resp.regs[0] as *const u64 as *const u8; // data at regs[0]
                                            core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                        }
                                    }
                                    reply_val(ep_cap, n as i64);
                                }
                                Err(_) => reply_val(ep_cap, 0),
                            }
                        }
                    }
                    _ => reply_val(ep_cap, -EBADF),
                }
            }

            // SYS_write(fd, buf, len)
            SYS_WRITE => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }
                match child_fds[fd] {
                    2 => {
                        // stdout/stderr
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                        for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                        reply_val(ep_cap, len as i64);
                    }
                    8 => reply_val(ep_cap, len as i64), // /dev/null → discard
                    22 => {
                        // eventfd write: add value to counter
                        if len < 8 { reply_val(ep_cap, -EINVAL); continue; }
                        if let Some(slot) = eventfd_slot_fd.iter().position(|&x| x == fd) {
                            let val = unsafe { *(buf_ptr as *const u64) };
                            eventfd_counter[slot] = eventfd_counter[slot].saturating_add(val);
                            reply_val(ep_cap, 8);
                        } else { reply_val(ep_cap, -EBADF); }
                    }
                    25 => {
                        // memfd write
                        if let Some(slot) = memfd_slot_fd.iter().position(|&x| x == fd) {
                            for s in 0..MAX_VFS_FILES {
                                if vfs_files[s][3] == fd as u64 && vfs_files[s][0] == 0xFEFD {
                                    let offset = vfs_files[s][2] as usize;
                                    let cap = memfd_cap[slot] as usize;
                                    let n = len.min(cap.saturating_sub(offset));
                                    if n > 0 {
                                        let base = memfd_base[slot];
                                        unsafe { core::ptr::copy_nonoverlapping(buf_ptr as *const u8, (base + offset as u64) as *mut u8, n); }
                                        vfs_files[s][2] += n as u64;
                                        let new_end = vfs_files[s][2];
                                        if new_end > memfd_size[slot] { memfd_size[slot] = new_end; }
                                    }
                                    reply_val(ep_cap, n as i64);
                                    break;
                                }
                            }
                        } else { reply_val(ep_cap, -EBADF); }
                    }
                    16 => {
                        // TCP socket write → NET_CMD_TCP_SEND (multi-chunk)
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = sock_conn_id[fd] as u64;
                        let mut total_sent = 0usize;
                        let mut off = 0usize;
                        while off < len {
                            let chunk = (len - off).min(40);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_SEND,
                                regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts((buf_ptr + off as u64) as *const u8, chunk) };
                            unsafe {
                                let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
                            }
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let n = resp.regs[0] as usize;
                                    total_sent += n;
                                    off += n;
                                    if n == 0 { break; }
                                }
                                Err(_) => { break; }
                            }
                        }
                        if total_sent > 0 {
                            reply_val(ep_cap, total_sent as i64);
                        } else {
                            reply_val(ep_cap, -EIO);
                        }
                    }
                    17 => {
                        // UDP socket write → NET_CMD_UDP_SENDTO with stored remote addr
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let remote_ip = sock_udp_remote_ip[fd];
                        let remote_port = sock_udp_remote_port[fd];
                        let src_port = sock_udp_local_port[fd];
                        if net_cap == 0 || remote_ip == 0 {
                            reply_val(ep_cap, -EDESTADDRREQ); // -EDESTADDRREQ
                        } else {
                            let send_len = len.min(32);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_SENDTO,
                                regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                            unsafe {
                                let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                            }
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                                Err(_) => reply_val(ep_cap, -EIO),
                            }
                        }
                    }
                    13 => {
                        // VFS file: write via shared ObjectStore
                        let mut found = false;
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                let oid = vfs_files[s][0];
                                let pos = vfs_files[s][2] as usize;
                                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                                vfs_lock();
                                let result = unsafe { shared_store() }
                                    .and_then(|store| store.write_obj_range(oid, pos, data).ok());
                                vfs_unlock();
                                match result {
                                    Some(_) => {
                                        vfs_files[s][2] += len as u64;
                                        // Update cached size if we extended the file
                                        let new_end = vfs_files[s][2];
                                        if new_end > vfs_files[s][1] { vfs_files[s][1] = new_end; }
                                        reply_val(ep_cap, len as i64);
                                    }
                                    None => reply_val(ep_cap, -EIO), // -EIO
                                }
                                found = true;
                                break;
                            }
                        }
                        if !found { reply_val(ep_cap, -EBADF); }
                    }
                    _ => reply_val(ep_cap, -EBADF),
                }
            }

            // SYS_close(fd)
            SYS_CLOSE => {
                let fd = msg.regs[0] as usize;
                if fd < CHILD_MAX_FDS && child_fds[fd] != 0 {
                    if child_fds[fd] == 12 {
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][3] == fd as u64 {
                                initrd_files[s][3] = u64::MAX; // mark FD closed but data alive
                                break;
                            }
                        }
                    } else if child_fds[fd] == 13 || child_fds[fd] == 14 {
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 { vfs_files[s] = [0; 4]; break; }
                        }
                    } else if child_fds[fd] == 22 {
                        // eventfd close
                        if let Some(slot) = eventfd_slot_fd.iter().position(|&x| x == fd) {
                            eventfd_slot_fd[slot] = usize::MAX;
                            eventfd_counter[slot] = 0;
                        }
                    } else if child_fds[fd] == 23 {
                        // timerfd close
                        if let Some(slot) = timerfd_slot_fd.iter().position(|&x| x == fd) {
                            timerfd_slot_fd[slot] = usize::MAX;
                            timerfd_expiry_tsc[slot] = 0;
                            timerfd_interval_ns[slot] = 0;
                        }
                    } else if child_fds[fd] == 25 {
                        // memfd close — free pages
                        if let Some(slot) = memfd_slot_fd.iter().position(|&x| x == fd) {
                            let cap_pages = (memfd_cap[slot] + 0xFFF) / 0x1000;
                            for p in 0..cap_pages { let _ = sys::unmap_free(memfd_base[slot] + p * 0x1000); }
                            memfd_slot_fd[slot] = usize::MAX;
                            memfd_base[slot] = 0;
                            memfd_size[slot] = 0;
                            memfd_cap[slot] = 0;
                        }
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] == 0xFEFD {
                                vfs_files[s] = [0; 4]; break;
                            }
                        }
                    } else if child_fds[fd] == 16 {
                        // TCP socket close → NET_CMD_TCP_CLOSE
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let cid = sock_conn_id[fd];
                        if net_cap != 0 && cid != 0xFFFF {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_CLOSE,
                                regs: [cid as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 500);
                        }
                        sock_conn_id[fd] = 0xFFFF;
                    }
                    child_fds[fd] = 0;
                }
                reply_val(ep_cap, 0);
            }

            // SYS_open(path, flags, mode) — used by musl dynamic linker + busybox
            SYS_OPEN => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                let kind = if name == b"/dev/null" { 8u8 }
                    else if name == b"/dev/zero" { 9u8 }
                    else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
                    else { 0u8 };

                if kind != 0 {
                    let mut fd = None;
                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                    if let Some(f) = fd {
                        child_fds[f] = kind;
                        reply_val(ep_cap, f as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                } else if starts_with(name, b"/etc/") || starts_with(name, b"/proc/")
                       || starts_with(name, b"/sys/") {
                    // Virtual files — same logic as SYS_OPENAT
                    let virt_len = open_virtual_file(name, dir_buf);
                    if let Some(gen_len) = virt_len {
                        *dir_len = gen_len;
                        *dir_pos = 0;
                        let mut fd = None;
                        for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            child_fds[f] = 15; // kind=15 = virtual file
                            reply_val(ep_cap, f as i64);
                        } else {
                            reply_val(ep_cap, -EMFILE);
                        }
                    } else {
                        reply_val(ep_cap, -ENOENT);
                    }
                } else if name == b"/" || name == b"/bin" || name == b"/lib"
                       || name == b"/lib64" || name == b"/sbin" || name == b"/tmp"
                       || name == b"/usr" || name == b"/etc" || name == b"/proc"
                       || name == b"." {
                    // Directory opens → resolve VFS OID + DirList fd (for getdents64)
                    let mut fd = None;
                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                    let mut vslot = None;
                    for s in 0..MAX_VFS_FILES { if vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                    if let (Some(f), Some(vs)) = (fd, vslot) {
                        // Resolve directory OID from VFS
                        let mut dir_oid = 0u64;
                        vfs_lock();
                        if let Some(store) = unsafe { shared_store() } {
                            use sotos_objstore::ROOT_OID;
                            if name == b"/" || name == b"." {
                                dir_oid = ROOT_OID;
                            } else {
                                if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                                    dir_oid = oid;
                                }
                            }
                        }
                        vfs_unlock();
                        if dir_oid == 0 { dir_oid = sotos_objstore::ROOT_OID; }
                        child_fds[f] = 14; // kind=14 = directory
                        vfs_files[vs] = [dir_oid, 0, 0, f as u64];
                        reply_val(ep_cap, f as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                } else {
                    // Try initrd — extract basename
                    let mut basename_start = 0usize;
                    for idx in 0..path_len {
                        if name[idx] == b'/' { basename_start = idx + 1; }
                    }
                    let basename = &name[basename_start..];

                    let mut slot = None;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][0] == 0 { slot = Some(s); break; }
                    }

                    if basename.is_empty() || slot.is_none() {
                        reply_val(ep_cap, -ENOENT);
                        continue;
                    }
                    let slot = slot.unwrap();

                    let file_buf = initrd_file_buf_base + (slot as u64) * 0x300000;
                    const FILE_BUF_PAGES_OPEN: u64 = 576; // 2.25 MiB (for libc.so.6 ~2.1 MB)
                    let mut buf_ok = true;
                    for p in 0..FILE_BUF_PAGES_OPEN {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                buf_ok = false; break;
                            }
                        } else { buf_ok = false; break; }
                    }
                    if !buf_ok {
                        reply_val(ep_cap, -ENOMEM);
                        continue;
                    }

                    match sys::initrd_read(
                        basename.as_ptr() as u64,
                        basename.len() as u64,
                        file_buf,
                        FILE_BUF_PAGES_OPEN * 0x1000,
                    ) {
                        Ok(sz) => {
                            let mut fd = None;
                            for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                            if let Some(f) = fd {
                                child_fds[f] = 12;
                                initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                reply_val(ep_cap, f as i64);
                            } else {
                                for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                reply_val(ep_cap, -EMFILE);
                            }
                        }
                        Err(_) => {
                            for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                            // Initrd failed — try VFS as fallback
                            let mut vfs_found = false;
                            vfs_lock();
                            let vfs_result = unsafe { shared_store() }.and_then(|store| {
                                use sotos_objstore::ROOT_OID;
                                let oid = store.resolve_path(name, ROOT_OID).ok()?;
                                let entry = store.stat(oid)?;
                                Some((oid, entry.size, entry.is_dir()))
                            });
                            vfs_unlock();
                            if let Some((oid, size, is_dir)) = vfs_result {
                                let mut vslot = None;
                                for s in 0..MAX_VFS_FILES { if vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                                let mut fd = None;
                                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                                if let (Some(vs), Some(f)) = (vslot, fd) {
                                    child_fds[f] = if is_dir { 14 } else { 13 };
                                    vfs_files[vs] = [oid, size, 0, f as u64];
                                    reply_val(ep_cap, f as i64);
                                    vfs_found = true;
                                }
                            }
                            if !vfs_found {
                                reply_val(ep_cap, -ENOENT);
                            }
                        }
                    }
                }
            }

            // SYS_fstat(fd, stat_buf)
            SYS_FSTAT => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF);
                } else if child_fds[fd] == 12 {
                    let mut size = 0u64;
                    let mut ino = 0u64;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            size = initrd_files[s][1];
                            ino = initrd_files[s][0]; // use buffer address as unique inode
                            break;
                        }
                    }
                    // dev=1 for initrd files (distinct from VFS dev=2)
                    write_linux_stat_dev(stat_ptr, 1, ino, size, false);
                    reply_val(ep_cap, 0);
                } else if child_fds[fd] == 13 || child_fds[fd] == 14 {
                    // VFS file (13) or VFS directory (14): get real size from store
                    let is_vfs_dir = child_fds[fd] == 14;
                    let mut size = 0u64;
                    let mut oid = 0u64;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            oid = vfs_files[s][0];
                            vfs_lock();
                            if let Some(store) = unsafe { shared_store() } {
                                if let Some(entry) = store.stat(oid) {
                                    size = entry.size;
                                }
                            }
                            vfs_unlock();
                            break;
                        }
                    }
                    // dev=2 for VFS files (distinct from initrd dev=1)
                    write_linux_stat_dev(stat_ptr, 2, oid, size, is_vfs_dir);
                    reply_val(ep_cap, 0);
                } else if child_fds[fd] == 15 {
                    // Procfs virtual file: report content length
                    write_linux_stat(stat_ptr, fd as u64, *dir_len as u64, false);
                    reply_val(ep_cap, 0);
                } else {
                    write_linux_stat(stat_ptr, fd as u64, 0, false);
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_stat(path, statbuf) — check if path exists (for terminfo etc.)
            SYS_STAT | SYS_LSTAT => {
                // SYS_stat(4) / SYS_lstat(6)
                let path_ptr = msg.regs[0];
                let stat_ptr = msg.regs[1];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // First try initrd by basename
                let mut basename_start = 0usize;
                for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                let basename = &name[basename_start..];
                if !basename.is_empty() {
                    if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                        write_linux_stat(stat_ptr, 0, sz, false);
                        reply_val(ep_cap, 0);
                        continue;
                    }
                }

                // Try VFS
                vfs_lock();
                let vfs_stat = unsafe { shared_store() }.and_then(|store| {
                    let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
                    let entry = store.stat(oid)?;
                    Some((oid, entry.size, entry.is_dir()))
                });
                vfs_unlock();

                if let Some((oid, size, is_dir)) = vfs_stat {
                    write_linux_stat(stat_ptr, oid, size, is_dir);
                    reply_val(ep_cap, 0);
                } else {
                    // Fall back to directory stubs
                    let is_dir = name == b"." || path_len == 0
                        || starts_with(name, b"/usr") || starts_with(name, b"/etc")
                        || starts_with(name, b"/lib") || starts_with(name, b"/lib64")
                        || name == b"/" || starts_with(name, b"/bin")
                        || starts_with(name, b"/sbin");
                    if is_dir {
                        write_linux_stat(stat_ptr, 0, 4096, true);
                        reply_val(ep_cap, 0);
                    } else {
                        reply_val(ep_cap, -ENOENT);
                    }
                }
            }

            // SYS_poll(fds, nfds, timeout)
            SYS_POLL => {
                let fds_ptr = msg.regs[0] as *mut u8;
                let nfds = msg.regs[1] as usize;
                let timeout = msg.regs[2] as i32;
                let mut ready = 0u32;
                // struct pollfd { int fd; short events; short revents; } = 8 bytes each
                for i in 0..nfds.min(16) {
                    let pfd = unsafe { fds_ptr.add(i * 8) };
                    let fd = unsafe { *(pfd as *const i32) };
                    let events = unsafe { *((pfd.add(4)) as *const i16) };
                    let mut revents: i16 = 0;
                    if fd >= 0 && (fd as usize) < CHILD_MAX_FDS && child_fds[fd as usize] != 0 {
                        // POLLIN = 1
                        if events & 1 != 0 {
                            if fd == 0 && child_fds[0] == 1 {
                                // stdin — check if char available
                                if unsafe { kb_has_char() } { revents |= 1; }
                            } else {
                                // Other readable FDs: always ready
                                revents |= 1;
                            }
                        }
                        // POLLOUT = 4
                        if events & 4 != 0 { revents |= 4; } // stdout always writable
                    } else if fd >= 0 {
                        revents = 0x20; // POLLNVAL
                    }
                    unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                    if revents != 0 { ready += 1; }
                }
                if ready > 0 || timeout == 0 {
                    reply_val(ep_cap, ready as i64);
                } else {
                    // Blocking poll — spin-wait (with yield) until input
                    let mut waited = 0u32;
                    let max_iters = if timeout > 0 { (timeout as u32) * 100 } else { u32::MAX };
                    let mut interrupted = false;
                    loop {
                        if unsafe { kb_has_char() } {
                            // Re-check all fds
                            ready = 0;
                            for i in 0..nfds.min(16) {
                                let pfd = unsafe { fds_ptr.add(i * 8) };
                                let fd = unsafe { *(pfd as *const i32) };
                                let events = unsafe { *((pfd.add(4)) as *const i16) };
                                let mut revents: i16 = 0;
                                if fd == 0 && (events & 1 != 0) { revents |= 1; }
                                if events & 4 != 0 { revents |= 4; }
                                unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                                if revents != 0 { ready += 1; }
                            }
                            break;
                        }
                        let s = sig_dequeue(pid);
                        if s != 0 && sig_dispatch(pid, s) >= 1 {
                            interrupted = true;
                            break;
                        }
                        sys::yield_now();
                        waited += 1;
                        if waited >= max_iters { break; }
                    }
                    if interrupted {
                        reply_val(ep_cap, -EINTR); // -EINTR
                    } else {
                        reply_val(ep_cap, ready as i64);
                    }
                }
            }

            // SYS_lseek(fd, offset, whence)
            SYS_LSEEK => {
                let fd = msg.regs[0] as usize;
                let offset_val = msg.regs[1] as i64;
                let whence = msg.regs[2] as u32;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else if child_fds[fd] == 12 {
                    let mut found = false;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            let file_size = initrd_files[s][1] as i64;
                            let cur_pos = initrd_files[s][2] as i64;
                            let new_pos = match whence {
                                0 => offset_val,                    // SEEK_SET
                                1 => cur_pos + offset_val,          // SEEK_CUR
                                2 => file_size + offset_val,        // SEEK_END
                                _ => { reply_val(ep_cap, -EINVAL); found = true; break; }
                            };
                            if new_pos < 0 {
                                reply_val(ep_cap, -EINVAL); // -EINVAL
                            } else {
                                initrd_files[s][2] = new_pos as u64;
                                reply_val(ep_cap, new_pos);
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -EBADF); }
                } else if child_fds[fd] == 13 || child_fds[fd] == 14 {
                    // VFS file or directory: seek
                    let mut found = false;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            let file_size = vfs_files[s][1] as i64;
                            let cur_pos = vfs_files[s][2] as i64;
                            let new_pos = match whence {
                                0 => offset_val,
                                1 => cur_pos + offset_val,
                                2 => file_size + offset_val,
                                _ => { reply_val(ep_cap, -EINVAL); found = true; break; }
                            };
                            if new_pos < 0 {
                                reply_val(ep_cap, -EINVAL);
                            } else {
                                vfs_files[s][2] = new_pos as u64;
                                reply_val(ep_cap, new_pos);
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -EBADF); }
                } else {
                    reply_val(ep_cap, -ESPIPE); // -ESPIPE (not seekable)
                }
            }

            // SYS_mmap(addr, len, prot, flags, fd, offset)
            SYS_MMAP => {
                let req_addr = msg.regs[0];
                let len = msg.regs[1];
                let prot = msg.regs[2]; // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
                let flags = msg.regs[3] as u32;
                let fd = msg.regs[4] as i64;
                let offset = msg.regs[5];

                let mflags = MFlags::from_bits_truncate(flags);
                let map_fixed = mflags.contains(MFlags::FIXED);
                let map_anon = mflags.contains(MFlags::ANONYMOUS);
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;

                // Determine base address
                let base = if map_fixed && req_addr != 0 {
                    // MAP_FIXED: use the exact requested address
                    // First unmap any existing pages at that range
                    for p in 0..pages {
                        let _ = sys::unmap_free(req_addr + p * 0x1000);
                    }
                    req_addr
                } else {
                    let b = *mmap_next;
                    *mmap_next += pages * 0x1000;
                    if pid > 0 && pid <= MAX_PROCS {
                        PROC_MMAP_NEXT[pid - 1].store(*mmap_next, Ordering::Release);
                    }
                    b
                };

                // Helper: apply final page permissions based on prot flags.
                // Pages were mapped writable for data copy; now fix permissions.
                // Must be a closure to capture base, pages, prot.
                let mmap_fixup_prot = |base: u64, pages: u64, prot: u64| {
                    if prot & 2 == 0 {
                        // Not writable — need to change from writable to read-only
                        let pflags = if prot & 4 != 0 { 0u64 } else { 1u64 << 63 }; // exec → 0; read-only → NX
                        for p in 0..pages {
                            let _ = sys::protect(base + p * 0x1000, pflags);
                        }
                    }
                    // If writable, kernel already set NX (W^X), nothing to do
                };

                if fd >= 0 && !map_anon {
                    // File-backed mmap: check initrd files first, then VFS files
                    let fdu = fd as usize;
                    let mut file_data: u64 = 0;
                    let mut file_size: u64 = 0;
                    let mut is_vfs = false;
                    let mut vfs_oid: u64 = 0;

                    if fdu < CHILD_MAX_FDS {
                        // Check initrd files (kind=12)
                        if child_fds[fdu] == 12 {
                            for s in 0..MAX_INITRD_FILES {
                                if initrd_files[s][0] != 0 && (initrd_files[s][3] == fdu as u64 || initrd_files[s][3] == u64::MAX) {
                                    file_data = initrd_files[s][0];
                                    file_size = initrd_files[s][1];
                                    break;
                                }
                            }
                        }
                        // Check VFS files (kind=13)
                        if file_data == 0 && child_fds[fdu] == 13 {
                            for s in 0..MAX_VFS_FILES {
                                if vfs_files[s][0] != 0 && vfs_files[s][3] == fdu as u64 {
                                    vfs_oid = vfs_files[s][0];
                                    file_size = vfs_files[s][1];
                                    is_vfs = true;
                                    break;
                                }
                            }
                        }
                    }

                    if file_data == 0 && !is_vfs {
                        reply_val(ep_cap, -EBADF); // -EBADF
                        continue;
                    }

                    // Map pages and copy file data
                    let mut ok = true;
                    for p in 0..pages {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                ok = false; break;
                            }
                        } else { ok = false; break; }
                    }
                    if ok {
                        let map_size = (pages * 0x1000) as usize;
                        unsafe { core::ptr::write_bytes(base as *mut u8, 0, map_size); }
                        let file_off = offset as usize;
                        let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
                        let to_copy = map_size.min(avail);

                        if is_vfs && to_copy > 0 {
                            // VFS file-backed mmap: read from ObjectStore
                            let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, to_copy) };
                            vfs_lock();
                            let read_result = unsafe { shared_store() }
                                .and_then(|store| store.read_obj_range(vfs_oid, file_off, dst).ok());
                            vfs_unlock();
                        } else if to_copy > 0 {
                            // Initrd file-backed mmap: direct memory copy
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    (file_data + file_off as u64) as *const u8,
                                    base as *mut u8,
                                    to_copy,
                                );
                            }
                        }
                        mmap_fixup_prot(base, pages, prot);
                        reply_val(ep_cap, base as i64);
                    } else {
                        reply_val(ep_cap, -ENOMEM);
                    }
                    continue;
                }

                // Anonymous mmap
                let mut ok = true;
                for p in 0..pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            ok = false; break;
                        }
                    } else { ok = false; break; }
                }
                if ok {
                    // Zero anonymous pages
                    unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 0x1000) as usize); }
                    mmap_fixup_prot(base, pages, prot);
                    reply_val(ep_cap, base as i64);
                } else {
                    reply_val(ep_cap, -ENOMEM);
                }
            }

            // SYS_mprotect(addr, len, prot) — change page permissions
            SYS_MPROTECT => {
                let addr = msg.regs[0] & !0xFFF;
                let len = msg.regs[1];
                let prot = msg.regs[2]; // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                // Convert Linux prot to kernel flags:
                // PROT_WRITE → MAP_WRITABLE (kernel sets NX for W^X)
                // PROT_EXEC without PROT_WRITE → flags=0 (read-only, executable)
                // PROT_READ only → PAGE_NO_EXECUTE (read-only, not executable)
                let flags = if prot & 2 != 0 {
                    MAP_WRITABLE // writable → kernel auto-sets NX (W^X)
                } else if prot & 4 != 0 {
                    0u64 // executable, not writable → no NX
                } else {
                    1u64 << 63 // PAGE_NO_EXECUTE: read-only, not executable
                };
                for p in 0..pages {
                    let _ = sys::protect(addr + p * 0x1000, flags);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_pread64(fd, buf, count, offset)
            SYS_PREAD64 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let count = msg.regs[2] as usize;
                let off = msg.regs[3];
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF);
                } else if child_fds[fd] == 12 {
                    let mut found = false;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            let data_base = initrd_files[s][0];
                            let file_size = initrd_files[s][1];
                            let avail = if off < file_size { (file_size - off) as usize } else { 0 };
                            let to_read = count.min(avail);
                            if to_read > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        (data_base + off) as *const u8,
                                        buf_ptr as *mut u8,
                                        to_read,
                                    );
                                }
                            }
                            reply_val(ep_cap, to_read as i64);
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -EBADF); }
                } else if child_fds[fd] == 13 {
                    // VFS file pread64
                    let mut found = false;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            let oid = vfs_files[s][0];
                            let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };
                            vfs_lock();
                            let result = unsafe { shared_store() }
                                .and_then(|store| store.read_obj_range(oid, off as usize, dst).ok());
                            vfs_unlock();
                            match result {
                                Some(n) => reply_val(ep_cap, n as i64),
                                None => reply_val(ep_cap, -EIO), // -EIO
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -EBADF); }
                } else {
                    reply_val(ep_cap, -EBADF);
                }
            }

            // SYS_munmap
            SYS_MUNMAP => {
                let addr = msg.regs[0];
                let len = msg.regs[1];
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                for p in 0..pages {
                    let _ = sys::unmap_free(addr + p * 0x1000);
                }
                // Reclaim mmap VA space if we just freed the tail
                let freed_end = addr + pages * 0x1000;
                if freed_end == *mmap_next {
                    *mmap_next = addr;
                }
                reply_val(ep_cap, 0);
            }

            // SYS_brk(addr)
            SYS_BRK => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= *current_brk {
                    reply_val(ep_cap, *current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let limit = my_brk_base + CHILD_MMAP_OFFSET; // don't overlap mmap region
                    if new_brk > limit {
                        reply_val(ep_cap, *current_brk as i64);
                        continue;
                    }
                    let mut ok = true;
                    let mut pg = (*current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                        pg += 0x1000;
                    }
                    if ok {
                        *current_brk = new_brk;
                        if pid > 0 && pid <= MAX_PROCS {
                            PROC_BRK_CURRENT[pid - 1].store(new_brk, Ordering::Release);
                        }
                    }
                    reply_val(ep_cap, *current_brk as i64);
                }
            }

            // SYS_rt_sigaction(sig, act, oldact, sigsetsize)
            SYS_RT_SIGACTION => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize;
                let ksa_size = (24 + sigsetsize).min(64);
                if signo == 0 || signo >= 32 || signo == 9 || signo == 19 {
                    // SIGKILL(9) and SIGSTOP(19) cannot be caught
                    if signo == 9 || signo == 19 { reply_val(ep_cap, -EINVAL); continue; }
                }
                let idx = pid - 1;
                // Write old handler to oldact
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let old_h = SIG_HANDLER[idx][signo].load(Ordering::Acquire);
                        let old_f = SIG_FLAGS[idx][signo].load(Ordering::Acquire);
                        let old_r = SIG_RESTORER[idx][signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&old_h.to_le_bytes());
                        buf[8..16].copy_from_slice(&old_f.to_le_bytes());
                        buf[16..24].copy_from_slice(&old_r.to_le_bytes());
                    }
                }
                // Install new handler from act
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    let restorer = unsafe { *((act_ptr + 16) as *const u64) };
                    SIG_HANDLER[idx][signo].store(handler, Ordering::Release);
                    SIG_FLAGS[idx][signo].store(flags, Ordering::Release);
                    SIG_RESTORER[idx][signo].store(restorer, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_rt_sigprocmask(how, set, oldset, sigsetsize)
            SYS_RT_SIGPROCMASK => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = pid - 1;
                let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
                // Write old mask
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur_mask; }
                }
                // Apply new mask
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    // Can't block SIGKILL or SIGSTOP
                    let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => SIG_BLOCKED[idx].store(cur_mask | safe_set, Ordering::Release),  // SIG_BLOCK
                        1 => SIG_BLOCKED[idx].store(cur_mask & !safe_set, Ordering::Release), // SIG_UNBLOCK
                        2 => SIG_BLOCKED[idx].store(safe_set, Ordering::Release),             // SIG_SETMASK
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_ioctl — terminal emulation
            SYS_IOCTL => {
                use sotos_common::linux_abi::*;
                let fd = msg.regs[0] as usize;
                let req = msg.regs[1] as u32;
                if fd <= 2 {
                    match req {
                        TCGETS => {
                            let buf = msg.regs[2] as *mut u8;
                            if !buf.is_null() {
                                // Kernel TCGETS writes struct __kernel_termios (36 bytes on x86_64).
                                // Layout: c_iflag(4) c_oflag(4) c_cflag(4) c_lflag(4) c_line(1) c_cc[19].
                                // glibc's struct termios is larger (60 bytes) but the kernel only fills 36.
                                unsafe { core::ptr::write_bytes(buf, 0, 36); }
                                let p = buf as *mut u32;
                                unsafe {
                                    *p = 0x0100 | 0x0400;           // c_iflag: ICRNL | IXON
                                    *p.add(1) = 0x0001 | 0x0004;   // c_oflag: OPOST | ONLCR
                                    *p.add(2) = 0x0030 | 0x0080 | 0x000F; // c_cflag: CS8|CREAD|B38400
                                    *p.add(3) = 0x0008 | 0x0010 | 0x0020 | 0x0002 | 0x0001 | 0x8000 | 0x0200 | 0x0800; // c_lflag
                                }
                                let cc = unsafe { buf.add(17) };
                                unsafe {
                                    *cc = 0x03;           // VINTR = Ctrl-C
                                    *cc.add(1) = 0x1C;   // VQUIT = Ctrl-backslash
                                    *cc.add(2) = 0x7F;   // VERASE = DEL
                                    *cc.add(3) = 0x15;   // VKILL = Ctrl-U
                                    *cc.add(4) = 0x04;   // VEOF = Ctrl-D
                                    *cc.add(6) = 0x01;   // VMIN = 1
                                    *cc.add(13) = 0x1A;  // VSUSP = Ctrl-Z
                                }
                            }
                            reply_val(ep_cap, 0);
                        }
                        TCSETS | TCSETSW | TCSETSF => reply_val(ep_cap, 0),
                        TIOCGWINSZ => {
                            let ws = Winsize::default_serial();
                            let buf = msg.regs[2] as *mut Winsize;
                            if !buf.is_null() { unsafe { *buf = ws; } }
                            reply_val(ep_cap, 0);
                        }
                        TIOCSWINSZ => reply_val(ep_cap, 0),
                        TIOCGPGRP | TIOCSPGRP => {
                            if req == TIOCGPGRP {
                                let buf = msg.regs[2] as *mut i32;
                                if !buf.is_null() { unsafe { *buf = pid as i32; } }
                            }
                            reply_val(ep_cap, 0);
                        }
                        FIONREAD => {
                            let buf = msg.regs[2] as *mut i32;
                            if !buf.is_null() {
                                let avail = if unsafe { kb_has_char() } { 1i32 } else { 0i32 };
                                unsafe { *buf = avail; }
                            }
                            reply_val(ep_cap, 0);
                        }
                        _ => reply_val(ep_cap, -ENOTTY), // -ENOTTY
                    }
                } else { reply_val(ep_cap, -EBADF); }
            }

            // SYS_readv(fd, iov, iovcnt) — scatter read
            SYS_READV => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else if child_fds[fd] == 1 {
                    // stdin readv: read one char into first iovec
                    if iovcnt > 0 && iov_ptr < 0x0000_8000_0000_0000 {
                        let base = unsafe { *(iov_ptr as *const u64) };
                        loop {
                            let s = sig_dequeue(pid);
                            if s != 0 && sig_dispatch(pid, s) >= 1 {
                                reply_val(ep_cap, -EINTR); break;
                            }
                            match unsafe { kb_read_char() } {
                                Some(ch) => {
                                    if base != 0 { unsafe { *(base as *mut u8) = ch; } }
                                    reply_val(ep_cap, 1); break;
                                }
                                None => { sys::yield_now(); }
                            }
                        }
                    } else {
                        reply_val(ep_cap, 0);
                    }
                } else if child_fds[fd] == 12 {
                    // Initrd file readv
                    let mut total: usize = 0;
                    let mut found = false;
                    for s_idx in 0..MAX_INITRD_FILES {
                        if initrd_files[s_idx][3] == fd as u64 && initrd_files[s_idx][0] != 0 {
                            let data_base = initrd_files[s_idx][0];
                            let file_size = initrd_files[s_idx][1];
                            let mut pos = initrd_files[s_idx][2];
                            let cnt = iovcnt.min(16);
                            for i in 0..cnt {
                                let entry = iov_ptr + (i as u64) * 16;
                                if entry + 16 > 0x0000_8000_0000_0000 { break; }
                                let base = unsafe { *(entry as *const u64) };
                                let len = unsafe { *((entry + 8) as *const u64) } as usize;
                                if base == 0 || len == 0 { continue; }
                                let avail = if pos < file_size { (file_size - pos) as usize } else { 0 };
                                let to_read = len.min(avail);
                                if to_read > 0 {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (data_base + pos) as *const u8,
                                            base as *mut u8,
                                            to_read,
                                        );
                                    }
                                    pos += to_read as u64;
                                    total += to_read;
                                }
                                if to_read < len { break; } // EOF mid-iovec
                            }
                            initrd_files[s_idx][2] = pos;
                            found = true;
                            break;
                        }
                    }
                    if found {
                        reply_val(ep_cap, total as i64);
                    } else {
                        reply_val(ep_cap, -EBADF);
                    }
                } else if child_fds[fd] == 13 {
                    // VFS file readv
                    let mut total: usize = 0;
                    let mut found = false;
                    for s_idx in 0..MAX_VFS_FILES {
                        if vfs_files[s_idx][3] == fd as u64 && vfs_files[s_idx][0] != 0 {
                            let oid = vfs_files[s_idx][0];
                            let mut pos = vfs_files[s_idx][2] as usize;
                            let cnt = iovcnt.min(16);
                            for i in 0..cnt {
                                let entry = iov_ptr + (i as u64) * 16;
                                if entry + 16 > 0x0000_8000_0000_0000 { break; }
                                let base = unsafe { *(entry as *const u64) };
                                let len = unsafe { *((entry + 8) as *const u64) } as usize;
                                if base == 0 || len == 0 { continue; }
                                let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
                                vfs_lock();
                                let n = unsafe { shared_store() }
                                    .and_then(|store| store.read_obj_range(oid, pos, dst).ok())
                                    .unwrap_or(0);
                                vfs_unlock();
                                pos += n;
                                total += n;
                                if n < len { break; } // EOF mid-iovec
                            }
                            vfs_files[s_idx][2] = pos as u64;
                            found = true;
                            break;
                        }
                    }
                    if found {
                        reply_val(ep_cap, total as i64);
                    } else {
                        reply_val(ep_cap, -EBADF);
                    }
                } else if child_fds[fd] == 16 {
                    // TCP socket readv → gather into iovecs via TCP_RECV
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let mut total = 0usize;
                    let cnt = iovcnt.min(16);
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let base = unsafe { *(entry as *const u64) };
                        let ilen = unsafe { *((entry + 8) as *const u64) } as usize;
                        if base == 0 || ilen == 0 { continue; }
                        // Fill this iovec with TCP data in 64-byte chunks
                        let mut off = 0usize;
                        while off < ilen {
                            let chunk = (ilen - off).min(64);
                            let mut got = 0usize;
                            for _ in 0..5000u32 {
                                let req = sotos_common::IpcMsg {
                                    tag: NET_CMD_TCP_RECV,
                                    regs: [conn_id, chunk as u64, 0, 0, 0, 0, 0, 0],
                                };
                                match sys::call_timeout(net_cap, &req, 200) {
                                    Ok(resp) => {
                                        let n = resp.tag as usize;
                                        if n > 0 && n <= chunk {
                                            unsafe {
                                                let src = &resp.regs[0] as *const u64 as *const u8;
                                                core::ptr::copy_nonoverlapping(src, (base + off as u64) as *mut u8, n);
                                            }
                                            got = n;
                                            break;
                                        }
                                    }
                                    Err(_) => {}
                                }
                                sys::yield_now();
                            }
                            if got == 0 { break; } // no more data
                            off += got;
                            total += got;
                            if got < chunk { break; } // short read, don't fill more
                        }
                        if off == 0 { break; } // no data for this iovec, stop
                    }
                    if total > 0 {
                        reply_val(ep_cap, total as i64);
                    } else {
                        reply_val(ep_cap, -EAGAIN);
                    }
                } else if child_fds[fd] == 2 {
                    // stdout/stderr readv → -EBADF (write-only)
                    reply_val(ep_cap, -EBADF);
                } else {
                    reply_val(ep_cap, 0); // other FD types: EOF
                }
            }

            // SYS_writev
            SYS_WRITEV => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd < CHILD_MAX_FDS && child_fds[fd] == 2 {
                    let mut total: usize = 0;
                    let cnt = iovcnt.min(16);
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let base = unsafe { *(entry as *const u64) };
                        let len = unsafe { *((entry + 8) as *const u64) } as usize;
                        if base == 0 || len == 0 { continue; }
                        let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                        for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                        total += len;
                    }
                    reply_val(ep_cap, total as i64);
                } else if fd < CHILD_MAX_FDS && child_fds[fd] == 8 {
                    // /dev/null: count bytes and discard
                    let mut total: usize = 0;
                    let cnt = iovcnt.min(16);
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let len = unsafe { *((entry + 8) as *const u64) } as usize;
                        total += len;
                    }
                    reply_val(ep_cap, total as i64);
                } else if fd < CHILD_MAX_FDS && child_fds[fd] == 16 {
                    // TCP socket writev — gather into single write
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let cnt = iovcnt.min(16);
                    let mut total_sent = 0usize;
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let base = unsafe { *(entry as *const u64) };
                        let ilen = unsafe { *((entry + 8) as *const u64) } as usize;
                        if base == 0 || ilen == 0 { continue; }
                        // Send in 40-byte chunks
                        let mut off = 0;
                        while off < ilen {
                            let chunk = (ilen - off).min(40);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_SEND,
                                regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts((base + off as u64) as *const u8, chunk) };
                            unsafe {
                                let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
                            }
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let n = resp.regs[0] as usize;
                                    total_sent += n;
                                    off += n;
                                    if n == 0 { break; }
                                }
                                Err(_) => { break; }
                            }
                        }
                    }
                    reply_val(ep_cap, total_sent as i64);
                } else {
                    reply_val(ep_cap, -EBADF);
                }
            }

            // SYS_access / SYS_faccessat — check file accessibility
            SYS_ACCESS | SYS_FACCESSAT => {
                let path_ptr = if syscall_nr == SYS_FACCESSAT { msg.regs[1] } else { msg.regs[0] };
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                // Directories
                let is_dir = name == b"." || name == b".."
                    || starts_with(name, b"/usr") || starts_with(name, b"/etc")
                    || starts_with(name, b"/lib") || starts_with(name, b"/lib64")
                    || name == b"/" || starts_with(name, b"/bin")
                    || starts_with(name, b"/sbin") || starts_with(name, b"/tmp")
                    || starts_with(name, b"/home") || starts_with(name, b"/var");
                if is_dir {
                    reply_val(ep_cap, 0);
                } else {
                    // Check initrd by basename
                    let mut basename_start = 0usize;
                    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                    let basename = &name[basename_start..];
                    if !basename.is_empty() {
                        match sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => {
                                // Try VFS
                                vfs_lock();
                                let found = unsafe { shared_store() }.and_then(|store| {
                                    store.resolve_path(name, sotos_objstore::ROOT_OID).ok()
                                }).is_some();
                                vfs_unlock();
                                reply_val(ep_cap, if found { 0 } else { -2 });
                            }
                        }
                    } else {
                        reply_val(ep_cap, -ENOENT);
                    }
                }
            }

            // SYS_pipe
            SYS_PIPE => {
                let pipefd = msg.regs[0] as *mut i32;
                // Allocate two FDs for pipe (read=PipeRead, write=PipeWrite)
                let mut r_fd = None;
                let mut w_fd = None;
                for i in 3..CHILD_MAX_FDS {
                    if child_fds[i] == 0 {
                        if r_fd.is_none() { r_fd = Some(i); }
                        else if w_fd.is_none() { w_fd = Some(i); break; }
                    }
                }
                if let (Some(r), Some(w)) = (r_fd, w_fd) {
                    child_fds[r] = 10; // pipe read end
                    child_fds[w] = 11; // pipe write end
                    unsafe { *pipefd = r as i32; *pipefd.add(1) = w as i32; }
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, -EMFILE); // -EMFILE
                }
            }

            // SYS_nanosleep
            SYS_NANOSLEEP => reply_val(ep_cap, 0),

            // SYS_getpid — returns tgid (thread group ID), not tid
            SYS_GETPID => {
                let tgid = PROC_TGID[pid - 1].load(Ordering::Acquire);
                reply_val(ep_cap, if tgid != 0 { tgid as i64 } else { pid as i64 });
            }

            // SYS_gettid — returns actual thread ID
            SYS_GETTID => reply_val(ep_cap, pid as i64),

            // SYS_dup(oldfd)
            SYS_DUP => {
                let oldfd = msg.regs[0] as usize;
                if oldfd >= CHILD_MAX_FDS || child_fds[oldfd] == 0 {
                    reply_val(ep_cap, -EBADF);
                } else {
                    let mut newfd = None;
                    for i in 0..CHILD_MAX_FDS {
                        if child_fds[i] == 0 { newfd = Some(i); break; }
                    }
                    if let Some(nfd) = newfd {
                        child_fds[nfd] = child_fds[oldfd];
                        reply_val(ep_cap, nfd as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                }
            }

            // SYS_dup2(oldfd, newfd)
            SYS_DUP2 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if oldfd >= CHILD_MAX_FDS || child_fds[oldfd] == 0 || newfd >= CHILD_MAX_FDS {
                    reply_val(ep_cap, -EBADF);
                } else {
                    child_fds[newfd] = child_fds[oldfd];
                    reply_val(ep_cap, newfd as i64);
                }
            }

            // SYS_execve(path, argv, envp) — generic: loads any ELF from initrd
            SYS_EXECVE => {
                let path_ptr = msg.regs[0];
                let argv_ptr = msg.regs[1];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                let bin_name = if path_len > 5 && starts_with(name, b"/bin/") { &name[5..] } else { name };

                let is_shell = bin_name == b"shell" || bin_name == b"sh";
                if is_shell {
                    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
                    let entry = boot_info.guest_entry;
                    if entry == 0 { reply_val(ep_cap, -ENOENT); continue; }
                    let stack_addr = NEXT_CHILD_STACK.fetch_add(0x2000, Ordering::SeqCst);
                    let guest_frame = match sys::frame_alloc() { Ok(f) => f, Err(_) => { reply_val(ep_cap, -ENOMEM); continue; } };
                    if sys::map(stack_addr, guest_frame, MAP_WRITABLE).is_err() { reply_val(ep_cap, -ENOMEM); continue; }
                    let new_ep = match sys::endpoint_create() { Ok(e) => e, Err(_) => { reply_val(ep_cap, -ENOMEM); continue; } };
                    let new_thread = match sys::thread_create_redirected(entry, stack_addr + 0x1000, new_ep) { Ok(t) => t, Err(_) => { reply_val(ep_cap, -ENOMEM); continue; } };
                    let _ = sys::signal_entry(new_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);
                    ep_cap = new_ep;
                    continue;
                }

                // Read argv from guest memory (shared address space)
                let mut exec_argv = [[0u8; MAX_EXEC_ARG_LEN]; MAX_EXEC_ARGS];
                let mut exec_argc: usize = 0;
                if argv_ptr != 0 {
                    let mut ap = argv_ptr;
                    while exec_argc < MAX_EXEC_ARGS {
                        let str_ptr = unsafe { *(ap as *const u64) };
                        if str_ptr == 0 { break; }
                        copy_guest_path(str_ptr, &mut exec_argv[exec_argc]);
                        exec_argc += 1;
                        ap += 8;
                    }
                }

                while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() { sys::yield_now(); }
                // Try initrd first, then VFS
                let result = if exec_argc > 0 {
                    exec_from_initrd_argv(bin_name, &exec_argv[..exec_argc])
                } else {
                    exec_from_initrd(bin_name)
                };
                let result = match result {
                    Ok(r) => Ok(r),
                    Err(_) => {
                        // Initrd failed — try VFS with full path
                        // Use bin_name if it's an absolute path (avoids /bin/ prefix duplication)
                        let vfs_path = if !bin_name.is_empty() && bin_name[0] == b'/' { bin_name } else { name };
                        if exec_argc > 0 {
                            crate::exec::exec_from_vfs_argv(vfs_path, &exec_argv[..exec_argc])
                        } else {
                            crate::exec::exec_from_vfs(vfs_path)
                        }
                    }
                };
                match result {
                    Ok((new_ep, _tc)) => {
                        // Record page info for cleanup on exit
                        if pid > 0 && pid <= MAX_PROCS {
                            use crate::exec::{LAST_EXEC_STACK_BASE, LAST_EXEC_STACK_PAGES,
                                              LAST_EXEC_ELF_LO, LAST_EXEC_ELF_HI, LAST_EXEC_HAS_INTERP};
                            PROC_STACK_BASE[pid - 1].store(LAST_EXEC_STACK_BASE.load(Ordering::Acquire), Ordering::Release);
                            PROC_STACK_PAGES[pid - 1].store(LAST_EXEC_STACK_PAGES.load(Ordering::Acquire), Ordering::Release);
                            PROC_ELF_LO[pid - 1].store(LAST_EXEC_ELF_LO.load(Ordering::Acquire), Ordering::Release);
                            PROC_ELF_HI[pid - 1].store(LAST_EXEC_ELF_HI.load(Ordering::Acquire), Ordering::Release);
                            PROC_HAS_INTERP[pid - 1].store(LAST_EXEC_HAS_INTERP.load(Ordering::Acquire), Ordering::Release);
                        }
                        EXEC_LOCK.store(0, Ordering::Release);
                        ep_cap = new_ep;
                        continue;
                    }
                    Err(errno) => { EXEC_LOCK.store(0, Ordering::Release); reply_val(ep_cap, errno); continue; }
                }
            }

            // SYS_exit(status)
            SYS_EXIT => {
                let status = msg.regs[0];
                if pid > 0 && pid <= MAX_PROCS {
                    // CLONE_CHILD_CLEARTID: write 0 to *clear_child_tid + futex_wake
                    let ctid_ptr = PROC_CLEAR_TID[pid - 1].load(Ordering::Acquire);
                    if ctid_ptr != 0 {
                        unsafe { core::ptr::write_volatile(ctid_ptr as *mut u32, 0); }
                        futex_wake(ctid_ptr, 1);
                    }
                    // Free initrd file buffer pages
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][0] != 0 {
                            let buf = initrd_files[s][0];
                            let sz = initrd_files[s][1];
                            let pages = (sz + 0xFFF) / 0x1000;
                            for p in 0..pages { let _ = sys::unmap_free(buf + p * 0x1000); }
                            initrd_files[s] = [0; 4];
                        }
                    }
                    // Free child stack pages
                    let sbase = PROC_STACK_BASE[pid - 1].load(Ordering::Acquire);
                    let spages = PROC_STACK_PAGES[pid - 1].load(Ordering::Acquire);
                    if sbase != 0 && spages != 0 {
                        for p in 0..spages { let _ = sys::unmap_free(sbase + p * 0x1000); }
                        PROC_STACK_BASE[pid - 1].store(0, Ordering::Release);
                        PROC_STACK_PAGES[pid - 1].store(0, Ordering::Release);
                    }
                    // Free ELF segment pages
                    let elf_lo = PROC_ELF_LO[pid - 1].load(Ordering::Acquire);
                    let elf_hi = PROC_ELF_HI[pid - 1].load(Ordering::Acquire);
                    if elf_lo < elf_hi {
                        let mut pg = elf_lo;
                        while pg < elf_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
                        PROC_ELF_LO[pid - 1].store(0, Ordering::Release);
                        PROC_ELF_HI[pid - 1].store(0, Ordering::Release);
                    }
                    // Free interpreter pages if dynamic binary
                    if PROC_HAS_INTERP[pid - 1].load(Ordering::Acquire) != 0 {
                        for pg in 0..0x110u64 {
                            let _ = sys::unmap_free(crate::exec::INTERP_LOAD_BASE + pg * 0x1000);
                        }
                        PROC_HAS_INTERP[pid - 1].store(0, Ordering::Release);
                    }
                    // Free pre-TLS page
                    let _ = sys::unmap_free(0xB70000);
                    // Free brk pages
                    let brk_lo = PROC_BRK_BASE[pid - 1].load(Ordering::Acquire);
                    let brk_hi = PROC_BRK_CURRENT[pid - 1].load(Ordering::Acquire);
                    if brk_lo != 0 && brk_hi > brk_lo {
                        let mut pg = brk_lo;
                        while pg < brk_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
                    }
                    // Free mmap pages
                    let mmap_lo = PROC_MMAP_BASE[pid - 1].load(Ordering::Acquire);
                    let mmap_hi = PROC_MMAP_NEXT[pid - 1].load(Ordering::Acquire);
                    if mmap_lo != 0 && mmap_hi > mmap_lo {
                        let mut pg = mmap_lo;
                        while pg < mmap_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
                    }
                    PROC_BRK_BASE[pid - 1].store(0, Ordering::Release);
                    PROC_BRK_CURRENT[pid - 1].store(0, Ordering::Release);
                    PROC_MMAP_BASE[pid - 1].store(0, Ordering::Release);
                    PROC_MMAP_NEXT[pid - 1].store(0, Ordering::Release);
                    // Reset brk/mmap state
                    unsafe { GRP_BRK[memg] = 0; GRP_MMAP_NEXT[memg] = 0; }
                    for f in 0..CHILD_MAX_FDS { child_fds[f] = 0; }
                    for s in 0..MAX_VFS_FILES { vfs_files[s] = [0; 4]; }
                    PROC_EXIT[pid - 1].store(status, Ordering::Release);
                    PROC_STATE[pid - 1].store(2, Ordering::Release);
                    // Deliver SIGCHLD to parent
                    let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire) as usize;
                    if ppid > 0 && ppid <= MAX_PROCS {
                        sig_send(ppid, SIGCHLD as u64);
                    }
                }
                break;
            }

            // SYS_kill(pid, sig)
            SYS_KILL => {
                let target = msg.regs[0] as usize;
                let sig = msg.regs[1];
                if target == 0 || target > MAX_PROCS || PROC_STATE[target - 1].load(Ordering::Acquire) == 0 {
                    reply_val(ep_cap, -ESRCH); // -ESRCH
                    continue;
                }
                sig_send(target, sig);
                reply_val(ep_cap, 0);
            }

            // SYS_clone(flags, child_stack, ptid, ctid, newtls) — create a thread
            SYS_CLONE => {
                let flags = msg.regs[0];
                let child_stack = msg.regs[1];
                let ptid_ptr = msg.regs[2];
                let ctid_ptr = msg.regs[3];
                let newtls = msg.regs[4];
                let fn_ptr = msg.regs[5]; // r9 = fn (from musl's __clone)

                // Allocate child PID
                let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
                if child_pid > MAX_PROCS {
                    reply_val(ep_cap, -ENOMEM); // -ENOMEM
                    continue;
                }

                // Initialize thread group state based on clone flags
                PROC_PARENT[child_pid - 1].store(pid as u64, Ordering::Release);
                proc_thread_init(child_pid, pid, flags);

                // CLONE_PARENT_SETTID: write child TID to *ptid
                if flags & CLONE_PARENT_SETTID != 0 && ptid_ptr != 0 {
                    unsafe { core::ptr::write_volatile(ptid_ptr as *mut u32, child_pid as u32); }
                }

                // CLONE_CHILD_CLEARTID: store ctid pointer for exit cleanup
                if flags & CLONE_CHILD_CLEARTID != 0 && ctid_ptr != 0 {
                    PROC_CLEAR_TID[child_pid - 1].store(ctid_ptr, Ordering::Release);
                }

                // Set up the child's stack for clone_child_trampoline:
                // Layout: [fn_ptr, arg, tls_ptr] (popped in order by trampoline)
                // musl __clone pushed arg at [child_stack], so read it first
                let arg = if child_stack != 0 {
                    unsafe { core::ptr::read_volatile(child_stack as *const u64) }
                } else {
                    0
                };
                let tls = if flags & CLONE_SETTLS != 0 { newtls } else { 0 };

                // Write trampoline setup below child_stack (stack grows down)
                let child_sp = child_stack - 24;
                unsafe {
                    core::ptr::write_volatile((child_sp) as *mut u64, fn_ptr);        // [rsp+0] → fn
                    core::ptr::write_volatile((child_sp + 8) as *mut u64, arg);       // [rsp+8] → arg
                    core::ptr::write_volatile((child_sp + 16) as *mut u64, tls);      // [rsp+16] → tls
                }

                // Allocate handler stack (4 pages)
                let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x4000, Ordering::SeqCst);
                let mut hok = true;
                for hp in 0..4u64 {
                    let hf = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => { hok = false; break; }
                    };
                    if sys::map(handler_stack_base + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
                        hok = false; break;
                    }
                }
                if !hok {
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Create child endpoint
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };

                // Pass setup info to child handler
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid as u64, Ordering::Release);
                CHILD_SETUP_FLAGS.store(flags, Ordering::Release);
                CHILD_SETUP_READY.store(1, Ordering::Release);

                // Spawn child handler thread
                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack_base + 0x4000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Wait for child handler to consume setup
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                // Spawn child guest thread at clone_child_trampoline, redirected to child handler
                let child_thread = match sys::thread_create_redirected(
                    clone_child_trampoline as *const () as u64,
                    child_sp,
                    child_ep,
                ) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

                // Mark child as running
                PROC_STATE[child_pid - 1].store(1, Ordering::Release);

                // Reply to parent with child TID
                reply_val(ep_cap, child_pid as i64);
            }

            // SYS_uname
            SYS_UNAME => {
                let buf_ptr = msg.regs[0];
                if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 390) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [b"Linux", b"sotos", b"6.1.0-sotOS", b"#1 SMP sotOS 0.1.0", b"x86_64"];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_fcntl
            SYS_FCNTL => {
                let fd = msg.regs[0] as usize;
                let cmd = msg.regs[1] as u32;
                match cmd {
                    0 => { // F_DUPFD
                        let min = msg.regs[2] as usize;
                        if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 { reply_val(ep_cap, -EBADF); }
                        else {
                            let mut nfd = None;
                            for i in min..CHILD_MAX_FDS { if child_fds[i] == 0 { nfd = Some(i); break; } }
                            if let Some(n) = nfd { child_fds[n] = child_fds[fd]; reply_val(ep_cap, n as i64); }
                            else { reply_val(ep_cap, -EMFILE); }
                        }
                    }
                    1 | 3 => reply_val(ep_cap, 0), // F_GETFD, F_GETFL
                    2 | 4 => reply_val(ep_cap, 0), // F_SETFD, F_SETFL
                    _ => reply_val(ep_cap, -EINVAL),
                }
            }

            // SYS_getcwd
            SYS_GETCWD => {
                let buf = msg.regs[0] as *mut u8;
                let size = msg.regs[1] as usize;
                if size >= 2 {
                    unsafe { *buf = b'/'; *buf.add(1) = 0; }
                    reply_val(ep_cap, buf as i64);
                } else {
                    reply_val(ep_cap, -ERANGE); // -ERANGE
                }
            }

            // SYS_fsync / SYS_fdatasync — flush (no-op, data is already persistent)
            SYS_FSYNC | SYS_FDATASYNC => reply_val(ep_cap, 0),

            // SYS_ftruncate(fd, length)
            SYS_FTRUNCATE => {
                let fd = msg.regs[0] as usize;
                let length = msg.regs[1] as usize;
                if fd < CHILD_MAX_FDS && child_fds[fd] == 13 {
                    let mut done = false;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            // Truncate: just update cached size (VFS doesn't truly truncate but writes handle offset)
                            vfs_files[s][1] = length as u64;
                            done = true;
                            break;
                        }
                    }
                    reply_val(ep_cap, if done { 0 } else { -9 });
                } else {
                    reply_val(ep_cap, -EBADF); // EBADF
                }
            }

            // SYS_rename(oldpath, newpath)
            SYS_RENAME => {
                let old_ptr = msg.regs[0];
                let new_ptr = msg.regs[1];
                let mut old_path = [0u8; 128];
                let mut new_path = [0u8; 128];
                let old_len = copy_guest_path(old_ptr, &mut old_path);
                let new_len = copy_guest_path(new_ptr, &mut new_path);
                let old_name = &old_path[..old_len];
                let new_name = &new_path[..new_len];

                vfs_lock();
                let result = unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    let old_oid = store.resolve_path(old_name, ROOT_OID).ok()?;
                    // Extract new basename and parent
                    let mut last_slash = None;
                    for (i, &b) in new_name.iter().enumerate() {
                        if b == b'/' { last_slash = Some(i); }
                    }
                    let (new_parent, new_basename) = match last_slash {
                        Some(pos) => {
                            let pp = &new_name[..pos];
                            let p = if pp.is_empty() { ROOT_OID }
                                else { store.resolve_path(pp, ROOT_OID).ok()? };
                            (p, &new_name[pos + 1..])
                        }
                        None => (ROOT_OID, new_name),
                    };
                    store.rename(old_oid, new_basename, new_parent).ok()
                });
                vfs_unlock();
                reply_val(ep_cap, if result.is_some() { 0 } else { -2 });
            }

            // SYS_gettimeofday (child_handler)
            SYS_GETTIMEOFDAY => {
                let tv = msg.regs[0] as *mut u64;
                if !tv.is_null() {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_us = if tsc > boot_tsc { (tsc - boot_tsc) / 2000 } else { 0 };
                    let total_secs = elapsed_us / 1_000_000 + UPTIME_OFFSET_SECS;
                    let usecs = elapsed_us % 1_000_000;
                    unsafe { *tv = total_secs; *tv.add(1) = usecs; }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_sysinfo (child_handler)
            SYS_SYSINFO => {
                let buf = msg.regs[0] as *mut u8;
                if !buf.is_null() {
                    unsafe { core::ptr::write_bytes(buf, 0, 128); }
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 };
                    unsafe { *(buf as *mut u64) = secs + UPTIME_OFFSET_SECS; } // uptime with offset
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getuid/geteuid/getgid/getegid
            SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID => reply_val(ep_cap, 0),

            // SYS_setpgid
            SYS_SETPGID => reply_val(ep_cap, 0),

            // SYS_getppid
            SYS_GETPPID => reply_val(ep_cap, parent_pid as i64),

            // SYS_getpgrp
            SYS_GETPGRP => reply_val(ep_cap, pid as i64),

            // SYS_setsid
            SYS_SETSID => reply_val(ep_cap, pid as i64),

            // SYS_setfsuid / SYS_setfsgid — return previous (0)
            SYS_SETFSUID | SYS_SETFSGID => reply_val(ep_cap, 0),

            // SYS_sigaltstack — stub
            SYS_SIGALTSTACK => {
                let old_ss = msg.regs[1];
                if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
                    for b in buf.iter_mut() { *b = 0; }
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_openat — /dev files + initrd files + VFS files
            SYS_OPENAT => {
                let path_ptr = msg.regs[1];
                let flags = msg.regs[2] as u32;
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                let kind = if name == b"/dev/null" { 8u8 }
                    else if name == b"/dev/zero" { 9u8 }
                    else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
                    else { 0u8 };

                if kind != 0 {
                    let mut fd = None;
                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                    if let Some(f) = fd {
                        child_fds[f] = kind;
                        reply_val(ep_cap, f as i64);
                    } else {
                        reply_val(ep_cap, -EMFILE);
                    }
                } else if starts_with(name, b"/etc/") {
                    // /etc virtual files — delegate to shared helper
                    let virt_len = open_virtual_file(name, dir_buf);
                    if let Some(gen_len) = virt_len {
                        *dir_len = gen_len;
                        *dir_pos = 0;
                        let mut fd = None;
                        for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            child_fds[f] = 15; // kind=15 = virtual file
                            reply_val(ep_cap, f as i64);
                        } else {
                            reply_val(ep_cap, -EMFILE);
                        }
                    } else {
                        reply_val(ep_cap, -ENOENT);
                    }
                } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
                    // Virtual procfs/sysfs files — generate content into dir_buf
                    let mut gen_len: usize = 0;
                    let mut handled = true;
                    if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
                        // Minimal memory map (approximate but enough for parsers)
                        let map_text = b"\
00400000-00500000 r-xp 00000000 00:00 0          [text]\n\
00e30000-00e34000 rw-p 00000000 00:00 0          [stack]\n\
07000000-07200000 rw-p 00000000 00:00 0          [heap]\n\
00b80000-00b81000 r-xp 00000000 00:00 0          [vdso]\n";
                        let n = map_text.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&map_text[..n]);
                        gen_len = n;
                    } else if name == b"/proc/self/status" {
                        gen_len = format_proc_status(dir_buf, pid);
                    } else if name == b"/proc/self/stat" {
                        gen_len = format_proc_self_stat(dir_buf, pid);
                    } else if name == b"/proc/cpuinfo" {
                        let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        gen_len = n;
                    } else if name == b"/proc/meminfo" {
                        let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        gen_len = n;
                    } else if name == b"/proc/uptime" {
                        let tsc = rdtsc();
                        let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                        let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 } + UPTIME_OFFSET_SECS;
                        gen_len = format_uptime_into(dir_buf, secs);
                    } else if name == b"/proc/version" {
                        let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        gen_len = n;
                    } else if name == b"/proc/loadavg" {
                        let info = b"0.01 0.05 0.10 1/32 42\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        gen_len = n;
                    } else if name == b"/proc/self/auxv" || name == b"/proc/self/environ" {
                        // Empty content — valid FD that reads EOF
                    } else if starts_with(name, b"/proc/syslog/") {
                        let rest = &path[13..path_len];
                        let (max_n, _) = parse_u64_from(rest);
                        let max_entries = if max_n == 0 { 10 } else { max_n as usize };
                        gen_len = format_syslog_into(dir_buf, max_entries);
                    } else if starts_with(name, b"/proc/netmirror/") {
                        let rest = &path[16..path_len];
                        let enable = rest == b"on" || rest == b"1";
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap != 0 {
                            let cmd_msg = sotos_common::IpcMsg {
                                tag: 12,
                                regs: [if enable { 1 } else { 0 }, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call(net_cap, &cmd_msg);
                        }
                        let msg = if enable { b"packet mirroring: ON\n" as &[u8] } else { b"packet mirroring: OFF\n" };
                        let n = msg.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&msg[..n]);
                        gen_len = n;
                    } else if starts_with(name, b"/proc/") {
                        // Other /proc paths — check for /proc/N/status
                        let rest = &path[6..path_len];
                        let (n, consumed) = parse_u64_from(rest);
                        if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64
                            && PROC_STATE[n as usize - 1].load(Ordering::Acquire) != 0
                        {
                            let after = &rest[consumed..];
                            if after == b"/status" || after.is_empty() {
                                gen_len = format_proc_status(dir_buf, n as usize);
                            } else {
                                handled = false;
                            }
                        } else {
                            handled = false;
                        }
                    } else if starts_with(name, b"/sys/") {
                        // Sysfs: return content for known paths, ENOENT otherwise
                        if name == b"/sys/devices/system/cpu/online" {
                            let info = b"0-0\n";
                            dir_buf[..info.len()].copy_from_slice(info);
                            gen_len = info.len();
                        } else if name == b"/sys/devices/system/cpu/possible" {
                            let info = b"0-0\n";
                            dir_buf[..info.len()].copy_from_slice(info);
                            gen_len = info.len();
                        } else if starts_with(name, b"/sys/devices/system/cpu/cpu0/") {
                            // glibc may probe individual CPU topology
                            gen_len = 0; // empty but valid
                        } else {
                            handled = false;
                        }
                    }

                    if !handled {
                        reply_val(ep_cap, -ENOENT); // -ENOENT
                    } else {
                        *dir_len = gen_len;
                        *dir_pos = 0;
                        let mut fd = None;
                        for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            child_fds[f] = 15; // procfs virtual file
                            reply_val(ep_cap, f as i64);
                        } else {
                            reply_val(ep_cap, -EMFILE); // -EMFILE
                        }
                    }
                } else {
                    // Try to open from initrd — extract basename from path
                    // For absolute paths under /lib/ or /usr/, try VFS first
                    // (initrd may have different versions of shared libraries)
                    let is_lib_path = starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/");
                    let mut basename_start = 0usize;
                    for idx in 0..path_len {
                        if name[idx] == b'/' { basename_start = idx + 1; }
                    }
                    let basename = &name[basename_start..];
                    let mut opened_initrd = false;

                    if !basename.is_empty() && !is_lib_path {
                        // Find a free initrd file slot
                        let mut slot = None;
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][0] == 0 { slot = Some(s); break; }
                        }
                        if let Some(slot) = slot {
                            let file_buf = initrd_file_buf_base + (slot as u64) * 0x300000;
                            const FILE_BUF_PAGES_OPEN: u64 = 576; // 2.25 MiB
                            let mut buf_ok = true;
                            for p in 0..FILE_BUF_PAGES_OPEN {
                                if let Ok(f) = sys::frame_alloc() {
                                    if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                        buf_ok = false; break;
                                    }
                                } else { buf_ok = false; break; }
                            }
                            if buf_ok {
                                if let Ok(sz) = sys::initrd_read(
                                    basename.as_ptr() as u64,
                                    basename.len() as u64,
                                    file_buf,
                                    FILE_BUF_PAGES_OPEN * 0x1000,
                                ) {
                                    let mut fd = None;
                                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                                    if let Some(f) = fd {
                                        child_fds[f] = 12;
                                        initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                        reply_val(ep_cap, f as i64);
                                        opened_initrd = true;
                                    } else {
                                        for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                        reply_val(ep_cap, -EMFILE);
                                        opened_initrd = true; // error already replied
                                    }
                                } else {
                                    for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                }
                            }
                        }
                    }

                    // Fall through to VFS if initrd didn't handle it
                    if !opened_initrd {
                        let oflags = OFlags::from_bits_truncate(flags as u32);
                        let has_creat = oflags.contains(OFlags::CREAT);
                        let has_trunc = oflags.contains(OFlags::TRUNC);
                        let has_dir = oflags.contains(OFlags::DIRECTORY);

                        vfs_lock();
                        // Returns (oid, size, is_dir)
                        let vfs_result = unsafe { shared_store() }.and_then(|store| {
                            use sotos_objstore::ROOT_OID;
                            match store.resolve_path(name, ROOT_OID) {
                                Ok(oid) => {
                                    let entry = store.stat(oid)?;
                                    if has_dir && !entry.is_dir() {
                                        return None; // O_DIRECTORY on non-dir → ENOTDIR
                                    }
                                    if has_trunc && !entry.is_dir() {
                                        let parent = entry.parent_oid;
                                        let fname = entry.name_as_str();
                                        let mut fname_buf = [0u8; 48];
                                        let flen = fname.len().min(48);
                                        fname_buf[..flen].copy_from_slice(&fname[..flen]);
                                        let _ = store.delete(oid);
                                        match store.create_in(&fname_buf[..flen], &[], parent) {
                                            Ok(new_oid) => Some((new_oid, 0u64, false)),
                                            Err(_) => None,
                                        }
                                    } else {
                                        Some((oid, entry.size, entry.is_dir()))
                                    }
                                }
                                Err(_) if has_creat => {
                                    let mut last_slash = None;
                                    for (i, &b) in name.iter().enumerate() {
                                        if b == b'/' { last_slash = Some(i); }
                                    }
                                    let (parent_oid, filename) = match last_slash {
                                        Some(pos) => {
                                            let parent_path = &name[..pos];
                                            let fname = &name[pos + 1..];
                                            let p = if parent_path.is_empty() {
                                                ROOT_OID
                                            } else {
                                                store.resolve_path(parent_path, ROOT_OID).ok()?
                                            };
                                            (p, fname)
                                        }
                                        None => (ROOT_OID, name),
                                    };
                                    match store.create_in(filename, &[], parent_oid) {
                                        Ok(oid) => Some((oid, 0u64, false)),
                                        Err(_) => None,
                                    }
                                }
                                Err(_) => None,
                            }
                        });
                        vfs_unlock();

                        match vfs_result {
                            Some((oid, size, is_dir)) => {
                                let mut vslot = None;
                                for s in 0..MAX_VFS_FILES {
                                    if vfs_files[s][0] == 0 { vslot = Some(s); break; }
                                }
                                let mut fd = None;
                                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                                if let (Some(vs), Some(f)) = (vslot, fd) {
                                    child_fds[f] = if is_dir { 14 } else { 13 }; // 14=VFS dir, 13=VFS file
                                    vfs_files[vs] = [oid, size, 0, f as u64];
                                    reply_val(ep_cap, f as i64);
                                } else {
                                    reply_val(ep_cap, -EMFILE); // -EMFILE
                                }
                            }
                            None => {
                                // Last resort: try initrd by basename (for .so files under /lib etc.)
                                let mut found_initrd = false;
                                if !basename.is_empty() {
                                    let mut slot = None;
                                    for s in 0..MAX_INITRD_FILES {
                                        if initrd_files[s][0] == 0 { slot = Some(s); break; }
                                    }
                                    if let Some(slot) = slot {
                                        let file_buf = initrd_file_buf_base + (slot as u64) * 0x300000;
                                        const FILE_BUF_PAGES_OPEN: u64 = 576; // 2.25 MiB
                                        let mut buf_ok = true;
                                        for p in 0..FILE_BUF_PAGES_OPEN {
                                            if let Ok(f) = sys::frame_alloc() {
                                                if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                                    buf_ok = false; break;
                                                }
                                            } else { buf_ok = false; break; }
                                        }
                                        if buf_ok {
                                            if let Ok(sz) = sys::initrd_read(
                                                basename.as_ptr() as u64,
                                                basename.len() as u64,
                                                file_buf,
                                                FILE_BUF_PAGES_OPEN * 0x1000,
                                            ) {
                                                let mut fd = None;
                                                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                                                if let Some(f) = fd {
                                                    child_fds[f] = 12;
                                                    initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                                    reply_val(ep_cap, f as i64);
                                                    found_initrd = true;
                                                } else {
                                                    for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                                    reply_val(ep_cap, -EMFILE);
                                                    found_initrd = true;
                                                }
                                            } else {
                                                for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                            }
                                        }
                                    }
                                }
                                if !found_initrd {
                                    reply_val(ep_cap, -ENOENT);
                                }
                            }
                        }
                    }
                }
            }

            // SYS_set_tid_address — store clear_child_tid pointer, return TID
            SYS_SET_TID_ADDRESS => {
                let tidptr = msg.regs[0];
                PROC_CLEAR_TID[pid - 1].store(tidptr, Ordering::Release);
                reply_val(ep_cap, pid as i64);
            }

            // SYS_clock_gettime (child_handler)
            SYS_CLOCK_GETTIME => {
                let tp_ptr = msg.regs[1];
                if tp_ptr != 0 && tp_ptr < 0x0000_8000_0000_0000 {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_ns = if tsc > boot_tsc { (tsc - boot_tsc) / 2 } else { 0 };
                    let total_ns = elapsed_ns + UPTIME_OFFSET_NS;
                    let tp = unsafe { core::slice::from_raw_parts_mut(tp_ptr as *mut u8, 16) };
                    tp[0..8].copy_from_slice(&((total_ns / 1_000_000_000) as i64).to_le_bytes());
                    tp[8..16].copy_from_slice(&((total_ns % 1_000_000_000) as i64).to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_exit_group
            SYS_EXIT_GROUP => {
                let status = msg.regs[0] as i32;
                // CLONE_CHILD_CLEARTID: write 0 to *clear_child_tid + futex_wake
                let ctid_ptr = PROC_CLEAR_TID[pid - 1].load(Ordering::Acquire);
                if ctid_ptr != 0 {
                    unsafe { core::ptr::write_volatile(ctid_ptr as *mut u32, 0); }
                    futex_wake(ctid_ptr, 1);
                }
                // Free initrd file buffer pages
                for s in 0..MAX_INITRD_FILES {
                    if initrd_files[s][0] != 0 {
                        let buf = initrd_files[s][0];
                        let sz = initrd_files[s][1];
                        let pages = (sz + 0xFFF) / 0x1000;
                        for p in 0..pages { let _ = sys::unmap_free(buf + p * 0x1000); }
                        initrd_files[s] = [0; 4];
                    }
                }
                // Free child stack pages
                let sbase = PROC_STACK_BASE[pid - 1].load(Ordering::Acquire);
                let spages = PROC_STACK_PAGES[pid - 1].load(Ordering::Acquire);
                if sbase != 0 && spages != 0 {
                    for p in 0..spages { let _ = sys::unmap_free(sbase + p * 0x1000); }
                    PROC_STACK_BASE[pid - 1].store(0, Ordering::Release);
                    PROC_STACK_PAGES[pid - 1].store(0, Ordering::Release);
                }
                // Free ELF segment pages
                let elf_lo = PROC_ELF_LO[pid - 1].load(Ordering::Acquire);
                let elf_hi = PROC_ELF_HI[pid - 1].load(Ordering::Acquire);
                if elf_lo < elf_hi {
                    let mut pg = elf_lo;
                    while pg < elf_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
                    PROC_ELF_LO[pid - 1].store(0, Ordering::Release);
                    PROC_ELF_HI[pid - 1].store(0, Ordering::Release);
                }
                // Free interpreter pages if dynamic binary
                if PROC_HAS_INTERP[pid - 1].load(Ordering::Acquire) != 0 {
                    for pg in 0..0x110u64 {
                        let _ = sys::unmap_free(crate::exec::INTERP_LOAD_BASE + pg * 0x1000);
                    }
                    PROC_HAS_INTERP[pid - 1].store(0, Ordering::Release);
                }
                // Free pre-TLS page
                let _ = sys::unmap_free(0xB70000);
                // Free brk pages
                let brk_lo = PROC_BRK_BASE[pid - 1].load(Ordering::Acquire);
                let brk_hi = PROC_BRK_CURRENT[pid - 1].load(Ordering::Acquire);
                if brk_lo != 0 && brk_hi > brk_lo {
                    let mut pg = brk_lo;
                    while pg < brk_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
                }
                // Free mmap pages
                let mmap_lo = PROC_MMAP_BASE[pid - 1].load(Ordering::Acquire);
                let mmap_hi = PROC_MMAP_NEXT[pid - 1].load(Ordering::Acquire);
                if mmap_lo != 0 && mmap_hi > mmap_lo {
                    let mut pg = mmap_lo;
                    while pg < mmap_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
                }
                PROC_BRK_BASE[pid - 1].store(0, Ordering::Release);
                PROC_BRK_CURRENT[pid - 1].store(0, Ordering::Release);
                PROC_MMAP_BASE[pid - 1].store(0, Ordering::Release);
                PROC_MMAP_NEXT[pid - 1].store(0, Ordering::Release);
                // Reset brk/mmap state so next child starts clean
                unsafe {
                    GRP_BRK[memg] = 0;
                    GRP_MMAP_NEXT[memg] = 0;
                }
                PROC_EXIT[pid - 1].store(status as u64, Ordering::Release);
                PROC_STATE[pid - 1].store(2, Ordering::Release);
                // Deliver SIGCHLD to parent
                let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire) as usize;
                if ppid > 0 && ppid <= MAX_PROCS {
                    sig_send(ppid, SIGCHLD as u64);
                }
                break;
            }

            // SYS_fstatat(dirfd, path, statbuf, flags)
            SYS_FSTATAT => {
                let dirfd = msg.regs[0] as i64;
                let path_ptr = msg.regs[1];
                let stat_ptr = msg.regs[2];
                let flags = msg.regs[3] as u32;
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // AT_EMPTY_PATH: use dirfd as the file descriptor (glibc fstat impl)
                if (flags & AT_EMPTY_PATH) != 0 && path_len == 0 {
                    let fd = dirfd as usize;
                    if fd < CHILD_MAX_FDS && child_fds[fd] != 0 {
                        if child_fds[fd] == 12 {
                            let mut size = 0u64;
                            let mut ino = 0u64;
                            for s in 0..MAX_INITRD_FILES {
                                if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                                    size = initrd_files[s][1];
                                    ino = initrd_files[s][0]; // buffer address = unique inode
                                    break;
                                }
                            }
                            write_linux_stat_dev(stat_ptr, 1, ino, size, false);
                        } else if child_fds[fd] == 13 || child_fds[fd] == 14 {
                            // VFS file (13) or VFS directory (14)
                            let is_vfs_dir = child_fds[fd] == 14;
                            let mut size = 0u64;
                            let mut oid = 0u64;
                            for s in 0..MAX_VFS_FILES {
                                if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                    oid = vfs_files[s][0];
                                    size = vfs_files[s][1];
                                    break;
                                }
                            }
                            write_linux_stat_dev(stat_ptr, 2, oid, size, is_vfs_dir);
                        } else {
                            write_linux_stat(stat_ptr, fd as u64, 0, false);
                        }
                        reply_val(ep_cap, 0);
                    } else {
                        reply_val(ep_cap, -EBADF); // -EBADF
                    }
                    continue;
                }

                // First try initrd by basename (files take priority)
                let mut basename_start = 0usize;
                for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                let basename = &name[basename_start..];
                if !basename.is_empty() {
                    if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                        write_linux_stat(stat_ptr, 0, sz, false);
                        reply_val(ep_cap, 0);
                        continue;
                    }
                }
                // Try VFS first (finds real files in /lib, /usr/lib, etc.)
                vfs_lock();
                let vfs_stat = unsafe { shared_store() }.and_then(|store| {
                    let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
                    let entry = store.stat(oid)?;
                    Some((entry.oid, entry.size, entry.is_dir()))
                });
                vfs_unlock();
                if let Some((oid, size, is_dir)) = vfs_stat {
                    write_linux_stat(stat_ptr, oid, size, is_dir);
                    reply_val(ep_cap, 0);
                } else {
                    // Fall back to directory stubs
                    let is_dir = name == b"." || path_len == 0
                        || starts_with(name, b"/usr") || starts_with(name, b"/etc")
                        || starts_with(name, b"/lib") || starts_with(name, b"/lib64")
                        || name == b"/" || starts_with(name, b"/bin")
                        || starts_with(name, b"/sbin");
                    if is_dir {
                        write_linux_stat(stat_ptr, 0, 4096, true);
                        reply_val(ep_cap, 0);
                    } else {
                        reply_val(ep_cap, -ENOENT);
                    }
                }
            }

            // SYS_readlinkat(dirfd, path, buf, bufsiz)
            SYS_READLINKAT => {
                let path_ptr = msg.regs[1];
                let out_buf = msg.regs[2];
                let bufsiz = msg.regs[3] as usize;
                let mut rpath = [0u8; 64];
                let rpath_len = copy_guest_path(path_ptr, &mut rpath);
                if rpath_len >= 14 && &rpath[..14] == b"/proc/self/exe" {
                    // Return a generic executable path
                    let exe = b"/bin/program";
                    let n = exe.len().min(bufsiz);
                    if out_buf != 0 && out_buf < 0x0000_8000_0000_0000 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                exe.as_ptr(), out_buf as *mut u8, n,
                            );
                        }
                    }
                    reply_val(ep_cap, n as i64);
                } else {
                    reply_val(ep_cap, -EINVAL); // -EINVAL
                }
            }

            // SYS_prlimit64
            SYS_PRLIMIT64 => {
                let new_limit = msg.regs[2];
                let old_limit = msg.regs[3];
                if old_limit != 0 && old_limit < 0x0000_8000_0000_0000 {
                    // Return generous limits
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_limit as *mut u8, 16) };
                    let big: u64 = 0x7FFF_FFFF_FFFF_FFFF;
                    buf[0..8].copy_from_slice(&big.to_le_bytes()); // rlim_cur
                    buf[8..16].copy_from_slice(&big.to_le_bytes()); // rlim_max
                }
                let _ = new_limit;
                reply_val(ep_cap, 0);
            }

            // SYS_getrandom — ChaCha20 CSPRNG
            SYS_GETRANDOM => {
                let buf_ptr = msg.regs[0] as *mut u8;
                let buflen = msg.regs[1] as usize;
                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr, buflen) };
                fill_random(dst);
                reply_val(ep_cap, buflen as i64);
            }

            // SYS_futex(uaddr, op, val, timeout, uaddr2, val3)
            SYS_FUTEX => {
                let uaddr = msg.regs[0];
                let op = (msg.regs[1] & 0x7F) as u32; // mask off FUTEX_PRIVATE_FLAG
                let val = msg.regs[2] as u32;
                match op {
                    0 => { // FUTEX_WAIT
                        let result = futex_wait(uaddr, val);
                        reply_val(ep_cap, result);
                    }
                    1 => { // FUTEX_WAKE
                        let result = futex_wake(uaddr, val);
                        reply_val(ep_cap, result);
                    }
                    _ => reply_val(ep_cap, 0), // other ops: stub
                }
            }

            // SYS_sched_getaffinity — return 1 CPU
            SYS_SCHED_GETAFFINITY => {
                let mask_ptr = msg.regs[2] as *mut u8;
                let len = msg.regs[1] as usize;
                if !mask_ptr.is_null() && len > 0 {
                    unsafe {
                        core::ptr::write_bytes(mask_ptr, 0, len.min(128));
                        *mask_ptr = 1; // CPU 0
                    }
                }
                reply_val(ep_cap, len.min(128) as i64);
            }

            // SYS_getdents64(fd, dirp, count)
            SYS_GETDENTS64 => {
                use sotos_common::linux_abi::{DT_REG, DT_DIR};
                let fd = msg.regs[0] as usize;
                let dirp = msg.regs[1];
                let count = msg.regs[2] as usize;

                if fd >= CHILD_MAX_FDS || child_fds[fd] != 14 {
                    // FD kind 14 = VFS directory (opened via openat with O_DIRECTORY)
                    // Also support kind 13 that turns out to be a dir
                    reply_val(ep_cap, -EBADF); // -EBADF
                } else {
                    // Use vfs_files[s][2] (offset) as "populated" flag: 0=not yet, 0xDEAD=done.
                    // Both SYS_OPEN and SYS_OPENAT set vfs_files[s][2] = 0 initially.
                    let mut need_populate = true;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            if vfs_files[s][2] == 0xDEAD { need_populate = false; }
                            break;
                        }
                    }
                    if need_populate {
                        *dir_len = 0;
                        *dir_pos = 0;
                        // Find the directory OID from vfs_files
                        let mut dir_oid = 0u64;
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                dir_oid = vfs_files[s][0];
                                break;
                            }
                        }
                        if dir_oid != 0 {
                            vfs_lock();
                            if let Some(store) = unsafe { shared_store() } {
                                // Iterate the store's dir array directly (no fixed buffer limit)
                                for entry in &store.dir {
                                    if entry.is_free() || entry.parent_oid != dir_oid || entry.oid == dir_oid {
                                        continue;
                                    }
                                    let ename = entry.name_as_str();
                                    let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                                    if *dir_len + reclen > dir_buf.len() { break; }
                                    let d = &mut dir_buf[*dir_len..*dir_len + reclen];
                                    for b in d.iter_mut() { *b = 0; }
                                    d[0..8].copy_from_slice(&entry.oid.to_le_bytes());
                                    d[8..16].copy_from_slice(&((*dir_len + reclen) as u64).to_le_bytes());
                                    d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                                    d[18] = if entry.is_dir() { DT_DIR } else { DT_REG };
                                    let nlen = ename.len().min(reclen - 19);
                                    d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                                    *dir_len += reclen;
                                }
                            }
                            vfs_unlock();
                        }
                        // Mark as populated so next call returns EOF
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                vfs_files[s][2] = 0xDEAD;
                                break;
                            }
                        }
                    }

                    let remaining = if *dir_pos < *dir_len { *dir_len - *dir_pos } else { 0 };
                    if remaining == 0 {
                        reply_val(ep_cap, 0); // EOF
                    } else {
                        let copy_len = remaining.min(count);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                dir_buf[*dir_pos..].as_ptr(),
                                dirp as *mut u8,
                                copy_len,
                            );
                        }
                        *dir_pos += copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    }
                }
            }

            // SYS_fadvise64 — stub
            SYS_FADVISE64 => reply_val(ep_cap, 0),

            // SYS_ppoll — like poll but with signal mask
            SYS_PPOLL => {
                // Treat exactly like poll for now
                let fds_ptr = msg.regs[0] as *mut u8;
                let nfds = msg.regs[1] as usize;
                let mut ready = 0u32;
                for i in 0..nfds.min(16) {
                    let pfd = unsafe { fds_ptr.add(i * 8) };
                    let fd = unsafe { *(pfd as *const i32) };
                    let events = unsafe { *((pfd.add(4)) as *const i16) };
                    let mut revents: i16 = 0;
                    if fd >= 0 && (fd as usize) < CHILD_MAX_FDS && child_fds[fd as usize] != 0 {
                        if events & 1 != 0 {
                            if fd == 0 && child_fds[0] == 1 {
                                if unsafe { kb_has_char() } { revents |= 1; }
                            } else { revents |= 1; }
                        }
                        if events & 4 != 0 { revents |= 4; }
                    } else if fd >= 0 { revents = 0x20; }
                    unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                    if revents != 0 { ready += 1; }
                }
                if ready > 0 {
                    reply_val(ep_cap, ready as i64);
                } else {
                    // Block waiting for input
                    let mut interrupted = false;
                    loop {
                        if unsafe { kb_has_char() } {
                            ready = 0;
                            for i in 0..nfds.min(16) {
                                let pfd = unsafe { fds_ptr.add(i * 8) };
                                let fd = unsafe { *(pfd as *const i32) };
                                let events = unsafe { *((pfd.add(4)) as *const i16) };
                                let mut revents: i16 = 0;
                                if fd == 0 && (events & 1 != 0) { revents |= 1; }
                                if events & 4 != 0 { revents |= 4; }
                                unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                                if revents != 0 { ready += 1; }
                            }
                            break;
                        }
                        let s = sig_dequeue(pid);
                        if s != 0 && sig_dispatch(pid, s) >= 1 {
                            interrupted = true;
                            break;
                        }
                        sys::yield_now();
                    }
                    if interrupted {
                        reply_val(ep_cap, -EINTR);
                    } else {
                        reply_val(ep_cap, ready as i64);
                    }
                }
            }

            // SYS_statx — not supported, force musl to fall back to fstatat
            SYS_STATX => reply_val(ep_cap, -ENOSYS), // -ENOSYS

            // SYS_rseq — restartable sequences (musl may use)
            SYS_RSEQ => reply_val(ep_cap, -ENOSYS), // -ENOSYS is fine

            // SYS_SIGNAL_TRAMPOLINE (0x7F00) — async signal delivery
            0x7F00 => {
                let child_tid = msg.regs[6];
                let sig = sig_dequeue(pid);
                if sig != 0 {
                    match sig_dispatch(pid, sig) {
                        1 => break, // terminated
                        3 => {
                            if signal_deliver(ep_cap, pid, sig, child_tid, 0, true) {
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                // No signal — resume with saved pre-interrupt state via rt_sigreturn
                let mut saved_regs = [0u64; 18];
                if sys::get_thread_regs(child_tid, &mut saved_regs).is_ok() {
                    let saved_rsp = saved_regs[15];
                    let frame_size = sotos_common::SIGNAL_FRAME_SIZE as u64;
                    let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;
                    let fp = new_rsp as *mut u64;
                    unsafe {
                        core::ptr::write_volatile(fp.add(0),  vdso::SIGRETURN_RESTORER_ADDR);
                        core::ptr::write_volatile(fp.add(1),  0);
                        core::ptr::write_volatile(fp.add(2),  saved_regs[0]);
                        core::ptr::write_volatile(fp.add(3),  saved_regs[1]);
                        core::ptr::write_volatile(fp.add(4),  saved_regs[2]);
                        core::ptr::write_volatile(fp.add(5),  saved_regs[3]);
                        core::ptr::write_volatile(fp.add(6),  saved_regs[4]);
                        core::ptr::write_volatile(fp.add(7),  saved_regs[5]);
                        core::ptr::write_volatile(fp.add(8),  saved_regs[6]);
                        core::ptr::write_volatile(fp.add(9),  saved_regs[7]);
                        core::ptr::write_volatile(fp.add(10), saved_regs[8]);
                        core::ptr::write_volatile(fp.add(11), saved_regs[9]);
                        core::ptr::write_volatile(fp.add(12), saved_regs[10]);
                        core::ptr::write_volatile(fp.add(13), saved_regs[11]);
                        core::ptr::write_volatile(fp.add(14), saved_regs[12]);
                        core::ptr::write_volatile(fp.add(15), saved_regs[13]);
                        core::ptr::write_volatile(fp.add(16), saved_regs[14]);
                        core::ptr::write_volatile(fp.add(17), saved_regs[2]);
                        core::ptr::write_volatile(fp.add(18), saved_rsp);
                        core::ptr::write_volatile(fp.add(19), saved_regs[10]);
                        core::ptr::write_volatile(fp.add(20), saved_regs[16]);
                        core::ptr::write_volatile(fp.add(21), 0);
                    }
                    let reply = sotos_common::IpcMsg {
                        tag: sotos_common::SIG_REDIRECT_TAG,
                        regs: [
                            vdso::SIGRETURN_RESTORER_ADDR, 0, 0, 0,
                            new_rsp, 0, 0, 0,
                        ],
                    };
                    let _ = sys::send(ep_cap, &reply);
                } else {
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_socket(domain, type, protocol) — child socket proxy
            SYS_SOCKET => {
                let domain = msg.regs[0] as u32;
                let sock_type = msg.regs[1] as u32;
                let base_type = sock_type & 0xFF;
                if domain == 2 && (base_type == 1 || base_type == 2 || base_type == 3) {
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 {
                        reply_val(ep_cap, -EADDRNOTAVAIL);
                    } else {
                        // Find free FD (start from 3)
                        let mut fd = None;
                        for f in 3..CHILD_MAX_FDS {
                            if child_fds[f] == 0 { fd = Some(f); break; }
                        }
                        match fd {
                            Some(f) => {
                                if base_type == 1 {
                                    child_fds[f] = 16; // TCP
                                    sock_conn_id[f] = 0xFFFF;
                                } else {
                                    child_fds[f] = 17; // UDP
                                    // Auto-bind ephemeral port
                                    let port = NEXT_UDP_PORT.fetch_add(1, Ordering::SeqCst) as u16;
                                    sock_udp_local_port[f] = port;
                                    // Tell net service to bind
                                    let bind_req = sotos_common::IpcMsg {
                                        tag: NET_CMD_UDP_BIND,
                                        regs: [port as u64, 0, 0, 0, 0, 0, 0, 0],
                                    };
                                    let _ = sys::call_timeout(net_cap, &bind_req, 500);
                                }
                                reply_val(ep_cap, f as i64);
                            }
                            None => reply_val(ep_cap, -EMFILE), // -EMFILE
                        }
                    }
                } else {
                    reply_val(ep_cap, -EAFNOSUPPORT); // -EAFNOSUPPORT
                }
            }

            // SYS_connect(fd, sockaddr_ptr, addrlen) — child socket proxy
            SYS_CONNECT => {
                let fd = msg.regs[0] as usize;
                let sockaddr_ptr = msg.regs[1];
                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -EBADF);
                } else {
                    let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
                    let port = u16::from_be_bytes([sa[2], sa[3]]);
                    let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

                    if child_fds[fd] == 17 {
                        // UDP: store remote address
                        sock_udp_remote_ip[fd] = ip;
                        sock_udp_remote_port[fd] = port;
                        reply_val(ep_cap, 0);
                    } else {
                        // TCP connect
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_CONNECT,
                            regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 5000) {
                            Ok(resp) => {
                                let conn_id = resp.regs[0];
                                if conn_id as i64 >= 0 {
                                    sock_conn_id[fd] = conn_id as u32;
                                    reply_val(ep_cap, 0);
                                } else {
                                    reply_val(ep_cap, -ECONNREFUSED);
                                }
                            }
                            Err(_) => reply_val(ep_cap, -ECONNREFUSED),
                        }
                    }
                }
            }

            // SYS_sendto / SYS_sendmsg — child socket proxy
            SYS_SENDTO => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let dest_ptr = msg.regs[4];

                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -EBADF);
                } else if child_fds[fd] == 17 {
                    // UDP sendto
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }
                    let (dst_ip, dst_port) = if dest_ptr != 0 {
                        let sa = unsafe { core::slice::from_raw_parts(dest_ptr as *const u8, 8) };
                        let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
                        let port = u16::from_be_bytes([sa[2], sa[3]]);
                        // Remember last sendto target for recvmsg src_addr fill
                        sock_udp_remote_ip[fd] = ip;
                        sock_udp_remote_port[fd] = port;
                        (ip, port)
                    } else {
                        (sock_udp_remote_ip[fd], sock_udp_remote_port[fd])
                    };
                    let src_port = sock_udp_local_port[fd];
                    let send_len = len.min(32); // max 32 bytes in regs[4..7]
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_SENDTO,
                        regs: [dst_ip as u64, dst_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -EIO),
                    }
                } else {
                    // TCP send
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_SEND,
                        regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -EIO),
                    }
                }
            }

            // SYS_sendmsg — msghdr-based send
            SYS_SENDMSG => {
                let fd = msg.regs[0] as usize;
                let msghdr_ptr = msg.regs[1];

                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }

                // Parse msghdr
                let (msg_name, _msg_namelen, msg_iov, msg_iovlen) = unsafe {
                    let p = msghdr_ptr as *const u64;
                    (*p, *p.add(1) as u32, *p.add(2), *p.add(3) as usize)
                };
                if msg_iovlen == 0 {
                    reply_val(ep_cap, 0);
                    continue;
                }
                let (iov_base, iov_len) = unsafe {
                    let iov = msg_iov as *const u64;
                    (*iov, *iov.add(1) as usize)
                };

                if child_fds[fd] == 17 {
                    // UDP sendmsg
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }
                    let (dst_ip, dst_port) = if msg_name != 0 {
                        let sa = unsafe { core::slice::from_raw_parts(msg_name as *const u8, 8) };
                        let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
                        let port = u16::from_be_bytes([sa[2], sa[3]]);
                        sock_udp_remote_ip[fd] = ip;
                        sock_udp_remote_port[fd] = port;
                        (ip, port)
                    } else {
                        (sock_udp_remote_ip[fd], sock_udp_remote_port[fd])
                    };
                    let src_port = sock_udp_local_port[fd];
                    let send_len = iov_len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_SENDTO,
                        regs: [dst_ip as u64, dst_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(iov_base as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -EIO),
                    }
                } else {
                    // TCP sendmsg
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let send_len = iov_len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_SEND,
                        regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(iov_base as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -EIO),
                    }
                }
            }

            // SYS_recvfrom — child socket proxy
            SYS_RECVFROM => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let src_addr_ptr = msg.regs[4];
                let addrlen_ptr = msg.regs[5];

                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -EBADF);
                } else if child_fds[fd] == 17 {
                    // UDP recvfrom — retry loop (DNS responses need time via SLIRP)
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }
                    let src_port = sock_udp_local_port[fd];
                    let recv_len = len.min(64); // max 64 bytes via IPC transport
                    let mut got = 0usize;
                    for _attempt in 0..50u32 {
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_UDP_RECV,
                            regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 5000) {
                            Ok(resp) => {
                                let n = resp.tag as usize;
                                if n > 0 && n <= recv_len {
                                    unsafe {
                                        let src = &resp.regs[0] as *const u64 as *const u8;
                                        core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                    }
                                    got = n;
                                    break;
                                }
                            }
                            Err(_) => {}
                        }
                        sys::yield_now();
                    }
                    if got > 0 {
                        // Fill src_addr if provided (musl validates DNS source)
                        if src_addr_ptr != 0 {
                            let remote_ip = sock_udp_remote_ip[fd];
                            let remote_port = sock_udp_remote_port[fd];
                            unsafe {
                                let sa = src_addr_ptr as *mut u8;
                                *sa.add(0) = 2; *sa.add(1) = 0; // AF_INET = 2
                                *sa.add(2) = (remote_port >> 8) as u8;
                                *sa.add(3) = (remote_port & 0xFF) as u8;
                                *sa.add(4) = ((remote_ip >> 24) & 0xFF) as u8;
                                *sa.add(5) = ((remote_ip >> 16) & 0xFF) as u8;
                                *sa.add(6) = ((remote_ip >> 8) & 0xFF) as u8;
                                *sa.add(7) = (remote_ip & 0xFF) as u8;
                                for i in 8..16 { *sa.add(i) = 0; }
                            }
                            if addrlen_ptr != 0 {
                                unsafe { *(addrlen_ptr as *mut u32) = 16; }
                            }
                        }
                        reply_val(ep_cap, got as i64);
                    } else {
                        reply_val(ep_cap, -EAGAIN);
                    }
                } else {
                    // TCP recvfrom — retry loop like SYS_READ
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let recv_len = len.min(64);
                    let mut got = 0usize;
                    for _ in 0..5000u32 {
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_RECV,
                            regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 200) {
                            Ok(resp) => {
                                let n = resp.tag as usize;
                                if n > 0 && n <= recv_len {
                                    unsafe {
                                        let src = &resp.regs[0] as *const u64 as *const u8;
                                        core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                    }
                                    got = n;
                                    break;
                                }
                            }
                            Err(_) => {}
                        }
                        sys::yield_now();
                    }
                    if got > 0 { reply_val(ep_cap, got as i64); }
                    else { reply_val(ep_cap, -EAGAIN); }
                }
            }

            // SYS_recvmsg — msghdr-based receive (used by musl DNS resolver)
            SYS_RECVMSG => {
                let fd = msg.regs[0] as usize;
                let msghdr_ptr = msg.regs[1];
                // flags in msg.regs[2] — ignored for now

                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -EBADF);
                    continue;
                }

                // Parse msghdr from guest memory:
                // struct msghdr {
                //   void         *msg_name;       // +0
                //   socklen_t     msg_namelen;     // +8
                //   struct iovec *msg_iov;         // +16
                //   size_t        msg_iovlen;      // +24
                //   void         *msg_control;     // +32
                //   size_t        msg_controllen;  // +40
                //   int           msg_flags;       // +48
                // };
                let (msg_name, msg_namelen, msg_iov, msg_iovlen) = unsafe {
                    let p = msghdr_ptr as *const u64;
                    (
                        *p,                          // msg_name
                        *p.add(1) as u32,            // msg_namelen
                        *p.add(2),                   // msg_iov
                        *p.add(3) as usize,          // msg_iovlen
                    )
                };

                // Get first iovec entry: { iov_base: *void, iov_len: usize }
                if msg_iovlen == 0 {
                    reply_val(ep_cap, 0);
                    continue;
                }
                let (iov_base, iov_len) = unsafe {
                    let iov = msg_iov as *const u64;
                    (*iov, *iov.add(1) as usize)
                };

                if child_fds[fd] == 17 {
                    // UDP recvmsg — retry loop for DNS responses
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); continue; }
                    let src_port = sock_udp_local_port[fd];
                    let recv_len = iov_len.min(64); // max 64 bytes via IPC regs
                    // Retry up to 50 times with 5000-tick IPC timeout
                    let mut total_n = 0usize;
                    for _attempt in 0..50u32 {
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_UDP_RECV,
                            regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 5000) {
                            Ok(resp) => {
                                let n = resp.tag as usize; // tag = byte count
                                if n > 0 && n <= recv_len {
                                    unsafe {
                                        let src = &resp.regs[0] as *const u64 as *const u8; // data at regs[0]
                                        core::ptr::copy_nonoverlapping(src, iov_base as *mut u8, n);
                                    }
                                    total_n = n;
                                    break;
                                }
                                // n == 0: no data yet, retry
                            }
                            Err(_) => {} // timeout, retry
                        }
                    }
                    if total_n > 0 {
                        // Fill msg_name with source address (musl DNS validates this)
                        if msg_name != 0 && msg_namelen >= 16 {
                            let remote_ip = sock_udp_remote_ip[fd];
                            let remote_port = sock_udp_remote_port[fd];
                            unsafe {
                                let sa = msg_name as *mut u8;
                                *sa.add(0) = 2; *sa.add(1) = 0; // AF_INET
                                *sa.add(2) = (remote_port >> 8) as u8;
                                *sa.add(3) = (remote_port & 0xFF) as u8;
                                *sa.add(4) = ((remote_ip >> 24) & 0xFF) as u8;
                                *sa.add(5) = ((remote_ip >> 16) & 0xFF) as u8;
                                *sa.add(6) = ((remote_ip >> 8) & 0xFF) as u8;
                                *sa.add(7) = (remote_ip & 0xFF) as u8;
                                for i in 8..16 { *sa.add(i) = 0; }
                            }
                            unsafe { *((msghdr_ptr + 8) as *mut u32) = 16; }
                        }
                        unsafe {
                            *((msghdr_ptr + 40) as *mut u64) = 0;
                            *((msghdr_ptr + 48) as *mut i32) = 0;
                        }
                        reply_val(ep_cap, total_n as i64);
                    } else {
                        // No data after retries — return EAGAIN
                        reply_val(ep_cap, -EAGAIN);
                    }
                } else {
                    // TCP recvmsg — retry loop
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let recv_len = iov_len.min(64);
                    let mut got = 0usize;
                    for _ in 0..5000u32 {
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_RECV,
                            regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 200) {
                            Ok(resp) => {
                                let n = resp.tag as usize;
                                if n > 0 && n <= recv_len {
                                    unsafe {
                                        let src = &resp.regs[0] as *const u64 as *const u8;
                                        core::ptr::copy_nonoverlapping(src, iov_base as *mut u8, n);
                                    }
                                    got = n;
                                    break;
                                }
                            }
                            Err(_) => {}
                        }
                        sys::yield_now();
                    }
                    unsafe {
                        *((msghdr_ptr + 40) as *mut u64) = 0;
                        *((msghdr_ptr + 48) as *mut i32) = 0;
                    }
                    if got > 0 { reply_val(ep_cap, got as i64); }
                    else { reply_val(ep_cap, -EAGAIN); }
                }
            }

            // SYS_bind(49), SYS_listen(50), SYS_setsockopt(54) — stubs
            SYS_BIND | SYS_LISTEN | SYS_SETSOCKOPT => reply_val(ep_cap, 0),

            // SYS_getsockname(51) / SYS_getpeername(52)
            SYS_GETSOCKNAME | SYS_GETPEERNAME => {
                let sockaddr_ptr = msg.regs[1];
                let addrlen_ptr = msg.regs[2];
                if sockaddr_ptr != 0 {
                    let fd = msg.regs[0] as usize;
                    let sa = sockaddr_ptr as *mut u8;
                    unsafe {
                        core::ptr::write_bytes(sa, 0, 16);
                        *(sa as *mut u16) = 2; // AF_INET
                        if syscall_nr == SYS_GETSOCKNAME {
                            // Return local addr: 10.0.2.15
                            *sa.add(4) = 10; *sa.add(5) = 0; *sa.add(6) = 2; *sa.add(7) = 15;
                        } else if fd < CHILD_MAX_FDS && child_fds[fd] == 16 {
                            // Return stored remote addr from connect
                            // (not stored in child_handler, just return zeros)
                        }
                    }
                }
                if addrlen_ptr != 0 {
                    unsafe { *(addrlen_ptr as *mut u32) = 16; }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getsockopt(fd, level, optname, optval, optlen) — return 0 for SO_ERROR
            SYS_GETSOCKOPT => {
                let optval_ptr = msg.regs[3];
                let optlen_ptr = msg.regs[4];
                if optval_ptr != 0 {
                    unsafe { *(optval_ptr as *mut i32) = 0; } // no error
                }
                if optlen_ptr != 0 {
                    unsafe { *(optlen_ptr as *mut u32) = 4; }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_shutdown(48)
            SYS_SHUTDOWN => {
                reply_val(ep_cap, 0);
            }

            // SYS_mkdir(83), SYS_chmod(90) — stubs: pretend success
            SYS_MKDIR | SYS_CHMOD => {
                reply_val(ep_cap, 0);
            }

            // SYS_select(23) / SYS_pselect6(270) — check readability/writability
            SYS_SELECT | SYS_PSELECT6 => {
                let nfds = (msg.regs[0] as usize).min(CHILD_MAX_FDS);
                let readfds_ptr = msg.regs[1];
                let writefds_ptr = msg.regs[2];
                let exceptfds_ptr = msg.regs[3];
                // timeout: regs[4] for select (timeval*), pselect6 (timespec*)
                let timeout_ptr = msg.regs[4];

                // Parse timeout (in milliseconds, 0 = poll, -1 = infinite)
                let timeout_ms: i64 = if timeout_ptr == 0 {
                    -1 // infinite
                } else if syscall_nr == SYS_SELECT {
                    // timeval: { tv_sec: i64, tv_usec: i64 }
                    let sec = unsafe { *(timeout_ptr as *const i64) };
                    let usec = unsafe { *((timeout_ptr + 8) as *const i64) };
                    sec * 1000 + usec / 1000
                } else {
                    // timespec: { tv_sec: i64, tv_nsec: i64 }
                    let sec = unsafe { *(timeout_ptr as *const i64) };
                    let nsec = unsafe { *((timeout_ptr + 8) as *const i64) };
                    sec * 1000 + nsec / 1_000_000
                };

                // Clear exceptfds
                if exceptfds_ptr != 0 { unsafe { *(exceptfds_ptr as *mut u64) = 0; } }

                let rfds_in = if readfds_ptr != 0 { unsafe { *(readfds_ptr as *const u64) } } else { 0 };
                let wfds_in = if writefds_ptr != 0 { unsafe { *(writefds_ptr as *const u64) } } else { 0 };

                let check_select = |rfds_in: u64, wfds_in: u64| -> (u64, u64, u32) {
                    let mut rfds_out: u64 = 0;
                    let mut wfds_out: u64 = 0;
                    let mut ready: u32 = 0;
                    for fd in 0..nfds {
                        let bit = 1u64 << fd;
                        if fd < CHILD_MAX_FDS && child_fds[fd] != 0 {
                            if rfds_in & bit != 0 {
                                let is_ready = match child_fds[fd] {
                                    1 => unsafe { kb_has_char() }, // stdin
                                    16 => true, // TCP socket — report ready, read will block/return
                                    17 => true, // UDP socket
                                    12 | 13 | 15 => true, // files always readable
                                    _ => true,
                                };
                                if is_ready { rfds_out |= bit; ready += 1; }
                            }
                            if wfds_in & bit != 0 {
                                // All open fds are writable
                                wfds_out |= bit; ready += 1;
                            }
                        }
                    }
                    (rfds_out, wfds_out, ready)
                };

                let (mut rfds_out, mut wfds_out, mut ready) = check_select(rfds_in, wfds_in);

                if ready == 0 && timeout_ms != 0 {
                    // Block with yield, respecting timeout
                    let max_iters = if timeout_ms > 0 { (timeout_ms as u32).saturating_mul(100) } else { 500_000 };
                    let mut waited = 0u32;
                    loop {
                        sys::yield_now();
                        waited += 1;
                        let (ro, wo, r) = check_select(rfds_in, wfds_in);
                        rfds_out = ro; wfds_out = wo; ready = r;
                        if ready > 0 || waited >= max_iters { break; }
                        let s = sig_dequeue(pid);
                        if s != 0 { break; }
                    }
                }

                if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = rfds_out; } }
                if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = wfds_out; } }
                reply_val(ep_cap, ready as i64);
            }

            // SYS_epoll_create1(291) — stub: return a fake FD
            SYS_EPOLL_CREATE1 => {
                // Find a free FD slot and mark it as epoll
                let mut efd: i64 = -24; // -EMFILE
                for f in 3..CHILD_MAX_FDS {
                    if child_fds[f] == 0 {
                        child_fds[f] = 21; // kind 21 = epoll
                        efd = f as i64;
                        break;
                    }
                }
                reply_val(ep_cap, efd);
            }

            // SYS_epoll_ctl(233) — stub: always succeed
            SYS_EPOLL_CTL => {
                let _epfd = msg.regs[0] as usize;
                let op = msg.regs[1] as u32;
                let fd = msg.regs[2] as i32;
                let event_ptr = msg.regs[3];
                let (events, data) = if event_ptr != 0 {
                    let ev = unsafe { *(event_ptr as *const u32) };
                    let d = unsafe { *((event_ptr + 4) as *const u64) };
                    (ev, d)
                } else { (0, 0) };
                match op {
                    1 => { // EPOLL_CTL_ADD
                        if let Some(i) = epoll_reg_fd.iter().position(|&x| x == -1) {
                            epoll_reg_fd[i] = fd;
                            epoll_reg_events[i] = events;
                            epoll_reg_data[i] = data;
                        }
                        reply_val(ep_cap, 0);
                    }
                    2 => { // EPOLL_CTL_DEL
                        if let Some(i) = epoll_reg_fd.iter().position(|&x| x == fd) {
                            epoll_reg_fd[i] = -1;
                        }
                        reply_val(ep_cap, 0);
                    }
                    3 => { // EPOLL_CTL_MOD
                        if let Some(i) = epoll_reg_fd.iter().position(|&x| x == fd) {
                            epoll_reg_events[i] = events;
                            epoll_reg_data[i] = data;
                        }
                        reply_val(ep_cap, 0);
                    }
                    _ => reply_val(ep_cap, -EINVAL),
                }
            }

            // SYS_epoll_wait(232), SYS_epoll_pwait(281) — real fd tracking
            SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => {
                let events_ptr = msg.regs[1];
                let max_events = (msg.regs[2] as usize).min(32);
                let timeout = msg.regs[3] as i32;
                let mut ready_count = 0usize;
                // Check all registered fds for readiness
                for i in 0..MAX_EPOLL_ENTRIES {
                    if epoll_reg_fd[i] < 0 { continue; }
                    if ready_count >= max_events { break; }
                    let rfd = epoll_reg_fd[i] as usize;
                    let wanted = epoll_reg_events[i];
                    let mut revents = 0u32;
                    if rfd < CHILD_MAX_FDS {
                        let kind = child_fds[rfd];
                        if kind == 0 {
                            revents |= 0x10; // EPOLLHUP
                        } else {
                            // Check readable (EPOLLIN = 1)
                            if wanted & 1 != 0 {
                                if kind == 1 { // stdin
                                    if unsafe { kb_has_char() } { revents |= 1; }
                                } else if kind == 22 { // eventfd
                                    if let Some(s) = eventfd_slot_fd.iter().position(|&x| x == rfd) {
                                        if eventfd_counter[s] > 0 { revents |= 1; }
                                    }
                                } else if kind == 23 { // timerfd
                                    if let Some(s) = timerfd_slot_fd.iter().position(|&x| x == rfd) {
                                        let exp = timerfd_expiry_tsc[s];
                                        if exp != 0 && rdtsc() >= exp { revents |= 1; }
                                    }
                                } else if kind == 10 { // pipe read
                                    revents |= 1; // pipes always readable (may return 0)
                                } else if kind == 13 || kind == 12 || kind == 15 {
                                    revents |= 1; // regular files always readable
                                } else if kind == 16 { // TCP socket
                                    revents |= 1; // assume readable
                                }
                            }
                            // Check writable (EPOLLOUT = 4)
                            if wanted & 4 != 0 {
                                if kind == 2 || kind == 8 || kind == 11 || kind == 16 || kind == 17 || kind == 22 {
                                    revents |= 4;
                                }
                            }
                        }
                    }
                    if revents != 0 {
                        let ep = events_ptr + (ready_count as u64) * 12;
                        unsafe {
                            *(ep as *mut u32) = revents;
                            *((ep + 4) as *mut u64) = epoll_reg_data[i];
                        }
                        ready_count += 1;
                    }
                }
                if ready_count > 0 || timeout == 0 {
                    reply_val(ep_cap, ready_count as i64);
                } else {
                    // Block: poll in a loop with yield, up to ~timeout ms
                    let deadline = rdtsc() + (timeout as u64).min(30000) * 2_000_000;
                    loop {
                        // Re-check registered fds
                        let mut found = false;
                        for i in 0..MAX_EPOLL_ENTRIES {
                            if epoll_reg_fd[i] < 0 { continue; }
                            let rfd = epoll_reg_fd[i] as usize;
                            let wanted = epoll_reg_events[i];
                            if rfd < CHILD_MAX_FDS {
                                let kind = child_fds[rfd];
                                let mut rev = 0u32;
                                if wanted & 1 != 0 && kind == 1 && unsafe { kb_has_char() } { rev |= 1; }
                                if wanted & 1 != 0 && kind == 22 {
                                    if let Some(s) = eventfd_slot_fd.iter().position(|&x| x == rfd) {
                                        if eventfd_counter[s] > 0 { rev |= 1; }
                                    }
                                }
                                if wanted & 1 != 0 && kind == 23 {
                                    if let Some(s) = timerfd_slot_fd.iter().position(|&x| x == rfd) {
                                        if timerfd_expiry_tsc[s] != 0 && rdtsc() >= timerfd_expiry_tsc[s] { rev |= 1; }
                                    }
                                }
                                if rev != 0 {
                                    let ep = events_ptr + (ready_count as u64) * 12;
                                    unsafe {
                                        *(ep as *mut u32) = rev;
                                        *((ep + 4) as *mut u64) = epoll_reg_data[i];
                                    }
                                    ready_count += 1;
                                    found = true;
                                    if ready_count >= max_events { break; }
                                }
                            }
                        }
                        if found || rdtsc() >= deadline { break; }
                        sys::yield_now();
                    }
                    reply_val(ep_cap, ready_count as i64);
                }
            }

            // SYS_epoll_create(213) — old API, same as epoll_create1
            SYS_EPOLL_CREATE => {
                let mut efd: i64 = -24;
                for f in 3..CHILD_MAX_FDS {
                    if child_fds[f] == 0 {
                        child_fds[f] = 21;
                        efd = f as i64;
                        break;
                    }
                }
                reply_val(ep_cap, efd);
            }

            // SYS_pidfd_open(293) — stub: not supported
            SYS_PIPE2 => {
                reply_val(ep_cap, -ENOSYS); // -ENOSYS
            }

            // --- glibc compatibility stubs ---

            // SYS_set_robust_list(273) — glibc pthread robust mutex tracking
            SYS_SET_ROBUST_LIST => reply_val(ep_cap, 0),

            // SYS_get_robust_list(274)
            SYS_GET_ROBUST_LIST => reply_val(ep_cap, -ENOSYS),

            // SYS_madvise(28) — memory advisory (glibc malloc)
            SYS_MADVISE => reply_val(ep_cap, 0),

            // SYS_sched_setaffinity(203) — stub
            SYS_SCHED_SETAFFINITY => reply_val(ep_cap, 0),

            // SYS_sysinfo(99) — already handled above but add memory info
            // (already in match)

            // SYS_getrlimit(97) / SYS_setrlimit(160) — resource limits
            SYS_GETRLIMIT => {
                let rlim_ptr = msg.regs[1];
                if rlim_ptr != 0 {
                    // Return generous limits: rlim_cur = rlim_max = large value
                    unsafe {
                        *(rlim_ptr as *mut u64) = 0x7FFF_FFFF_FFFF_FFFF; // rlim_cur
                        *((rlim_ptr + 8) as *mut u64) = 0x7FFF_FFFF_FFFF_FFFF; // rlim_max
                    }
                }
                reply_val(ep_cap, 0);
            }
            SYS_SETRLIMIT => reply_val(ep_cap, 0), // setrlimit: pretend success


            // SYS_prctl(157) — process control
            SYS_PRCTL => {
                let option = msg.regs[0] as u32;
                match option {
                    15 => { // PR_SET_NAME: ignore
                        reply_val(ep_cap, 0);
                    }
                    16 => { // PR_GET_NAME: return "program"
                        let buf = msg.regs[1];
                        if buf != 0 {
                            let name = b"program\0\0\0\0\0\0\0\0\0";
                            unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), buf as *mut u8, 16); }
                        }
                        reply_val(ep_cap, 0);
                    }
                    38 => reply_val(ep_cap, 0), // PR_SET_NO_NEW_PRIVS
                    _ => reply_val(ep_cap, -EINVAL), // -EINVAL
                }
            }


            // SYS_mremap(25) — glibc realloc sometimes uses this
            SYS_MREMAP => {
                let old_addr = msg.regs[0];
                let old_size = msg.regs[1];
                let new_size = msg.regs[2];
                let flags = msg.regs[3] as u32;
                let mremap_maymove = (flags & 1) != 0;

                if new_size <= old_size {
                    // Shrink: unmap excess pages
                    let old_pages = ((old_size + 0xFFF) & !0xFFF) / 0x1000;
                    let new_pages = ((new_size + 0xFFF) & !0xFFF) / 0x1000;
                    for p in new_pages..old_pages {
                        let _ = sys::unmap_free(old_addr + p * 0x1000);
                    }
                    // Reclaim VA space if we freed the tail
                    let freed_end = old_addr + old_pages * 0x1000;
                    if freed_end == *mmap_next {
                        *mmap_next = old_addr + new_pages * 0x1000;
                    }
                    reply_val(ep_cap, old_addr as i64);
                } else if mremap_maymove {
                    let old_pages = ((old_size + 0xFFF) & !0xFFF) / 0x1000;
                    let new_pages = ((new_size + 0xFFF) & !0xFFF) / 0x1000;
                    let old_end = old_addr + old_pages * 0x1000;

                    // Try in-place growth if old region is at end of mmap space
                    if old_end == *mmap_next {
                        let extra_pages = new_pages - old_pages;
                        let mut ok = true;
                        for p in 0..extra_pages {
                            if let Ok(f) = sys::frame_alloc() {
                                if sys::map(*mmap_next + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                            } else { ok = false; break; }
                        }
                        if ok {
                            unsafe { core::ptr::write_bytes(*mmap_next as *mut u8, 0, (extra_pages * 0x1000) as usize); }
                            *mmap_next += extra_pages * 0x1000;
                            if pid > 0 && pid <= MAX_PROCS {
                                PROC_MMAP_NEXT[pid - 1].store(*mmap_next, Ordering::Release);
                            }
                            reply_val(ep_cap, old_addr as i64);
                        } else {
                            reply_val(ep_cap, -ENOMEM);
                        }
                    } else {
                        // Allocate new region, copy, unmap old
                        let new_base = *mmap_next;
                        *mmap_next += new_pages * 0x1000;
                        let mut ok = true;
                        for p in 0..new_pages {
                            if let Ok(f) = sys::frame_alloc() {
                                if sys::map(new_base + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                            } else { ok = false; break; }
                        }
                        if ok {
                            let copy_size = old_size.min(new_size) as usize;
                            unsafe {
                                core::ptr::write_bytes(new_base as *mut u8, 0, (new_pages * 0x1000) as usize);
                                core::ptr::copy_nonoverlapping(old_addr as *const u8, new_base as *mut u8, copy_size);
                            }
                            for p in 0..old_pages { let _ = sys::unmap_free(old_addr + p * 0x1000); }
                            if pid > 0 && pid <= MAX_PROCS {
                                PROC_MMAP_NEXT[pid - 1].store(*mmap_next, Ordering::Release);
                            }
                            reply_val(ep_cap, new_base as i64);
                        } else {
                            reply_val(ep_cap, -ENOMEM);
                        }
                    }
                } else {
                    reply_val(ep_cap, -ENOMEM); // ENOMEM: can't expand in-place
                }
            }

            // ═══════════════════════════════════════════════════════════
            // Phase A–C: comprehensive Linux ABI for distro binaries + Wine
            // ═══════════════════════════════════════════════════════════

            // ─── Phase A: File operations ────────────────────────────

            // SYS_pwrite64(18) — write at offset (VFS)
            SYS_PWRITE64 => {
                let fd = msg.regs[0] as usize;
                let buf = msg.regs[1];
                let count = msg.regs[2] as usize;
                let offset = msg.regs[3] as usize;
                if fd < CHILD_MAX_FDS && child_fds[fd] == 13 {
                    let mut done = false;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            let oid = vfs_files[s][0];
                            let data = unsafe { core::slice::from_raw_parts(buf as *const u8, count.min(4096)) };
                            vfs_lock();
                            let ok = unsafe { shared_store() }
                                .and_then(|store| store.write_obj_range(oid, offset, data).ok())
                                .is_some();
                            vfs_unlock();
                            if ok {
                                let new_end = (offset + data.len()) as u64;
                                if new_end > vfs_files[s][1] { vfs_files[s][1] = new_end; }
                                reply_val(ep_cap, data.len() as i64);
                            } else { reply_val(ep_cap, -EIO); }
                            done = true; break;
                        }
                    }
                    if !done { reply_val(ep_cap, -EBADF); }
                } else { reply_val(ep_cap, -EBADF); }
            }

            // SYS_readlink(89) — /proc/self/exe → /bin/program
            SYS_READLINK => {
                let path_ptr = msg.regs[0];
                let buf = msg.regs[1];
                let bufsiz = msg.regs[2] as usize;
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                if name == b"/proc/self/exe" {
                    let target = b"/bin/program";
                    let n = target.len().min(bufsiz);
                    unsafe { core::ptr::copy_nonoverlapping(target.as_ptr(), buf as *mut u8, n); }
                    reply_val(ep_cap, n as i64);
                } else { reply_val(ep_cap, -EINVAL); }
            }

            // SYS_pipe2(293) — pipe with flags
            SYS_PIPE2 => {
                let pipefd_ptr = msg.regs[0];
                // Allocate two FDs: read end (kind=10) and write end (kind=11)
                let mut rfd = None;
                let mut wfd = None;
                for i in 3..CHILD_MAX_FDS {
                    if child_fds[i] == 0 {
                        if rfd.is_none() { rfd = Some(i); }
                        else if wfd.is_none() { wfd = Some(i); break; }
                    }
                }
                if let (Some(r), Some(w)) = (rfd, wfd) {
                    child_fds[r] = 10; // pipe read
                    child_fds[w] = 11; // pipe write
                    unsafe {
                        *(pipefd_ptr as *mut i32) = r as i32;
                        *((pipefd_ptr + 4) as *mut i32) = w as i32;
                    }
                    reply_val(ep_cap, 0);
                } else { reply_val(ep_cap, -EMFILE); }
            }

            // SYS_dup3(292) — dup with O_CLOEXEC
            SYS_DUP3 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if oldfd >= CHILD_MAX_FDS || child_fds[oldfd] == 0 || newfd >= CHILD_MAX_FDS {
                    reply_val(ep_cap, -EBADF);
                } else if oldfd == newfd {
                    reply_val(ep_cap, -EINVAL);
                } else {
                    if child_fds[newfd] != 0 { child_fds[newfd] = 0; } // close newfd
                    child_fds[newfd] = child_fds[oldfd];
                    reply_val(ep_cap, newfd as i64);
                }
            }

            // SYS_statfs(137) / SYS_fstatfs(138) — filesystem info
            SYS_STATFS | SYS_FSTATFS => {
                let buf = if syscall_nr == SYS_STATFS { msg.regs[1] } else { msg.regs[1] };
                if buf != 0 {
                    // struct statfs is 120 bytes on x86_64
                    unsafe { core::ptr::write_bytes(buf as *mut u8, 0, 120); }
                    unsafe {
                        let p = buf as *mut u64;
                        *p = 0xEF53; // f_type = EXT4_SUPER_MAGIC
                        *p.add(1) = 4096; // f_bsize
                        *p.add(2) = 1024 * 1024; // f_blocks
                        *p.add(3) = 512 * 1024; // f_bfree
                        *p.add(4) = 512 * 1024; // f_bavail
                        *p.add(5) = 65536; // f_files
                        *p.add(6) = 32768; // f_ffree
                        // f_fsid = 0 (already zeroed)
                        *p.add(9) = 255; // f_namelen
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_creat(85) — redirect to open with O_CREAT|O_WRONLY|O_TRUNC
            SYS_CREAT => {
                // Treat as open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
                // Just return -ENOENT for now; programs should use openat
                reply_val(ep_cap, -ENOENT);
            }

            // SYS_unlinkat(263) — unlink with dirfd
            SYS_UNLINKAT => {
                let path_ptr = msg.regs[1];
                let flags = msg.regs[2] as u32;
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                if flags & 0x200 != 0 {
                    // AT_REMOVEDIR → rmdir
                    reply_val(ep_cap, 0);
                } else {
                    vfs_lock();
                    let result = unsafe { shared_store() }.and_then(|store| {
                        use sotos_objstore::ROOT_OID;
                        store.resolve_path(name, ROOT_OID).ok()
                            .and_then(|oid| store.delete(oid).ok())
                    });
                    vfs_unlock();
                    reply_val(ep_cap, if result.is_some() { 0 } else { -ENOENT });
                }
            }

            // SYS_renameat(264) / SYS_renameat2(316) — rename with dirfd
            SYS_RENAMEAT | SYS_RENAMEAT2 => {
                let oldpath_ptr = msg.regs[1];
                let newpath_ptr = msg.regs[3];
                let mut oldpath = [0u8; 128];
                let mut newpath = [0u8; 128];
                let olen = copy_guest_path(oldpath_ptr, &mut oldpath);
                let nlen = copy_guest_path(newpath_ptr, &mut newpath);
                vfs_lock();
                let result = unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    let oid = store.resolve_path(&oldpath[..olen], ROOT_OID).ok()?;
                    // Find new parent and filename
                    let mut last_slash = None;
                    for (i, &b) in newpath[..nlen].iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
                    let (parent, fname) = match last_slash {
                        Some(pos) => {
                            let p = if pos == 0 { ROOT_OID } else { store.resolve_path(&newpath[..pos], ROOT_OID).ok()? };
                            (p, &newpath[pos+1..nlen])
                        }
                        None => (ROOT_OID, &newpath[..nlen]),
                    };
                    store.rename(oid, fname, parent).ok()
                });
                vfs_unlock();
                reply_val(ep_cap, if result.is_some() { 0 } else { -ENOENT });
            }

            // SYS_mkdirat(258) — mkdir with dirfd
            SYS_MKDIRAT => {
                let path_ptr = msg.regs[1];
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                vfs_lock();
                let result = unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    let mut last_slash = None;
                    for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
                    let (parent, dname) = match last_slash {
                        Some(pos) => {
                            let p = if pos == 0 { ROOT_OID } else { store.resolve_path(&name[..pos], ROOT_OID).ok()? };
                            (p, &name[pos+1..plen])
                        }
                        None => (ROOT_OID, name),
                    };
                    store.mkdir(dname, parent).ok()
                });
                vfs_unlock();
                reply_val(ep_cap, if result.is_some() { 0 } else { -ENOSPC });
            }

            // SYS_preadv(295) — scatter read at offset
            SYS_PREADV => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let offset = msg.regs[3];
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF); continue;
                }
                let mut total = 0i64;
                for i in 0..iovcnt.min(16) {
                    let iov = unsafe { iov_ptr.wrapping_add((i * 16) as u64) };
                    let base = unsafe { *(iov as *const u64) };
                    let len = unsafe { *((iov + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    // Read from VFS at offset + total
                    if child_fds[fd] == 13 {
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                let oid = vfs_files[s][0];
                                let pos = (offset as usize) + (total as usize);
                                let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
                                vfs_lock();
                                let n = unsafe { shared_store() }
                                    .and_then(|store| store.read_obj_range(oid, pos, dst).ok())
                                    .unwrap_or(0);
                                vfs_unlock();
                                total += n as i64;
                                break;
                            }
                        }
                    }
                }
                reply_val(ep_cap, total);
            }

            // SYS_pwritev(296) — scatter write at offset
            SYS_PWRITEV => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let offset = msg.regs[3];
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -EBADF); continue;
                }
                let mut total = 0i64;
                for i in 0..iovcnt.min(16) {
                    let iov = unsafe { iov_ptr.wrapping_add((i * 16) as u64) };
                    let base = unsafe { *(iov as *const u64) };
                    let len = unsafe { *((iov + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    if child_fds[fd] == 13 {
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                let oid = vfs_files[s][0];
                                let pos = (offset as usize) + (total as usize);
                                let data = unsafe { core::slice::from_raw_parts(base as *const u8, len.min(4096)) };
                                vfs_lock();
                                let ok = unsafe { shared_store() }
                                    .and_then(|store| store.write_obj_range(oid, pos, data).ok())
                                    .is_some();
                                vfs_unlock();
                                if ok { total += data.len() as i64; }
                                break;
                            }
                        }
                    }
                }
                reply_val(ep_cap, total);
            }

            // SYS_copy_file_range(326) — copy between file descriptors
            SYS_COPY_FILE_RANGE => {
                // Stub: report unsupported, libc falls back to read+write
                reply_val(ep_cap, -ENOSYS);
            }

            // SYS_sendfile(40) — send file data to socket/fd
            SYS_SENDFILE => {
                // Stub: report unsupported for now
                reply_val(ep_cap, -ENOSYS);
            }

            // File metadata stubs — return 0 (pretend success)
            SYS_LINK | SYS_SYMLINK | SYS_FCHMOD | SYS_FCHOWN | SYS_LCHOWN
            | SYS_FLOCK | SYS_FALLOCATE | SYS_UTIMES
            | SYS_LINKAT | SYS_SYMLINKAT | SYS_FCHMODAT | SYS_FCHOWNAT
            | SYS_UTIMENSAT | SYS_FUTIMESAT | SYS_MKNOD | SYS_MKNODAT
            => reply_val(ep_cap, 0),

            // SYS_umask(95)
            SYS_UMASK => reply_val(ep_cap, 0o022),

            // SYS_faccessat2(439) — like faccessat
            SYS_FACCESSAT2 => {
                // Delegate to same logic as faccessat: check VFS/virtual paths
                let path_ptr = msg.regs[1];
                let mut path = [0u8; 128];
                let plen = copy_guest_path(path_ptr, &mut path);
                let name = &path[..plen];
                if name.is_empty() || name == b"." || name == b"/" || starts_with(name, b"/bin")
                    || starts_with(name, b"/lib") || starts_with(name, b"/usr")
                    || starts_with(name, b"/etc") || starts_with(name, b"/proc")
                    || starts_with(name, b"/tmp") || starts_with(name, b"/sbin")
                {
                    reply_val(ep_cap, 0);
                } else {
                    vfs_lock();
                    let exists = unsafe { shared_store() }
                        .and_then(|store| store.resolve_path(name, sotos_objstore::ROOT_OID).ok())
                        .is_some();
                    vfs_unlock();
                    reply_val(ep_cap, if exists { 0 } else { -ENOENT });
                }
            }

            // ─── Phase B: Process management & signals ───────────────

            // SYS_sched_yield(24)
            SYS_SCHED_YIELD => { sys::yield_now(); reply_val(ep_cap, 0); }

            // SYS_vfork(58) — treat like fork
            SYS_VFORK => {
                // Same fake fork: return child_pid to parent immediately
                reply_val(ep_cap, (pid + 1) as i64);
            }

            // SYS_waitid(247) — like wait4
            SYS_WAITID => {
                // Stub: return immediately with no child
                reply_val(ep_cap, -ECHILD);
            }

            // SYS_getpgid(121) / SYS_getsid(124)
            SYS_GETPGID | SYS_GETSID => {
                let target = msg.regs[0] as usize;
                reply_val(ep_cap, if target == 0 { pid as i64 } else { target as i64 });
            }

            // SYS_tgkill(234)
            SYS_TGKILL => {
                let _tgid = msg.regs[0];
                let tid = msg.regs[1] as usize;
                let sig = msg.regs[2] as u8;
                if sig > 0 && sig <= 64 && tid >= 1 && tid <= MAX_PROCS {
                    sig_send(tid, sig as u64);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_sigaltstack(131)
            SYS_SIGALTSTACK => {
                let ss_ptr = msg.regs[0];
                let old_ss_ptr = msg.regs[1];
                // Return old stack
                if old_ss_ptr != 0 {
                    unsafe {
                        *(old_ss_ptr as *mut u64) = sigalt_sp;
                        *((old_ss_ptr + 8) as *mut u32) = sigalt_flags;
                        *((old_ss_ptr + 16) as *mut u64) = sigalt_size;
                    }
                }
                // Set new stack
                if ss_ptr != 0 {
                    sigalt_sp = unsafe { *(ss_ptr as *const u64) };
                    sigalt_flags = unsafe { *((ss_ptr + 8) as *const u32) };
                    sigalt_size = unsafe { *((ss_ptr + 16) as *const u64) };
                }
                reply_val(ep_cap, 0);
            }

            // SYS_clock_getres(229)
            SYS_CLOCK_GETRES => {
                let tp = msg.regs[1];
                if tp != 0 {
                    unsafe {
                        *(tp as *mut u64) = 0;       // tv_sec = 0
                        *((tp + 8) as *mut u64) = 1;  // tv_nsec = 1 (1ns resolution)
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_clock_nanosleep(230) — sleep stub
            SYS_CLOCK_NANOSLEEP => {
                // Yield a few times to simulate brief sleep
                for _ in 0..10 { sys::yield_now(); }
                reply_val(ep_cap, 0);
            }

            // SYS_getrusage(98)
            SYS_GETRUSAGE => {
                let buf = msg.regs[1];
                if buf != 0 {
                    // struct rusage = 144 bytes, zero everything
                    unsafe { core::ptr::write_bytes(buf as *mut u8, 0, 144); }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_times(100)
            SYS_TIMES => {
                let buf = msg.regs[0];
                if buf != 0 {
                    // struct tms = 4 * i64 = 32 bytes (clock_t = i64 on x86_64)
                    unsafe { core::ptr::write_bytes(buf as *mut u8, 0, 32); }
                }
                // Return clock ticks since boot
                let tsc = rdtsc();
                reply_val(ep_cap, (tsc / 20_000_000) as i64); // ~100 Hz ticks
            }

            // SYS_rt_sigpending(127)
            SYS_RT_SIGPENDING => {
                let set_ptr = msg.regs[0];
                if set_ptr != 0 {
                    unsafe { *(set_ptr as *mut u64) = 0; } // empty pending set
                }
                reply_val(ep_cap, 0);
            }

            // SYS_rt_sigtimedwait(128)
            SYS_RT_SIGTIMEDWAIT => reply_val(ep_cap, -EAGAIN),

            // SYS_rt_sigsuspend(130)
            SYS_RT_SIGSUSPEND => reply_val(ep_cap, -EINTR),

            // SYS_rt_sigqueueinfo(129)
            SYS_RT_SIGQUEUEINFO => reply_val(ep_cap, 0),

            // Identity stubs
            SYS_PERSONALITY => reply_val(ep_cap, 0), // PER_LINUX
            SYS_ALARM => reply_val(ep_cap, 0),
            SYS_PAUSE => reply_val(ep_cap, -EINTR),
            SYS_SETUID | SYS_SETGID | SYS_SETREUID | SYS_SETREGID
            | SYS_SETRESUID | SYS_SETRESGID | SYS_SETGROUPS
            | SYS_CAPSET | SYS_UNSHARE | SYS_SETPRIORITY
            => reply_val(ep_cap, 0),

            SYS_GETPRIORITY => reply_val(ep_cap, 20), // nice=0 encoded as 20
            SYS_GETGROUPS => reply_val(ep_cap, 0), // no supplementary groups

            SYS_GETRESUID => {
                let (r, e, s) = (msg.regs[0], msg.regs[1], msg.regs[2]);
                if r != 0 { unsafe { *(r as *mut u32) = 0; } }
                if e != 0 { unsafe { *(e as *mut u32) = 0; } }
                if s != 0 { unsafe { *(s as *mut u32) = 0; } }
                reply_val(ep_cap, 0);
            }
            SYS_GETRESGID => {
                let (r, e, s) = (msg.regs[0], msg.regs[1], msg.regs[2]);
                if r != 0 { unsafe { *(r as *mut u32) = 0; } }
                if e != 0 { unsafe { *(e as *mut u32) = 0; } }
                if s != 0 { unsafe { *(s as *mut u32) = 0; } }
                reply_val(ep_cap, 0);
            }
            SYS_CAPGET => {
                // Zero out the data structure (no capabilities)
                let data = msg.regs[1];
                if data != 0 {
                    unsafe { core::ptr::write_bytes(data as *mut u8, 0, 24); } // 3 * u32 * 2
                }
                reply_val(ep_cap, 0);
            }

            // Scheduler stubs
            SYS_SCHED_GETPARAM => {
                let buf = msg.regs[1];
                if buf != 0 { unsafe { *(buf as *mut i32) = 0; } } // sched_priority = 0
                reply_val(ep_cap, 0);
            }
            SYS_SCHED_SETSCHEDULER => reply_val(ep_cap, 0),
            SYS_SCHED_GETSCHEDULER => reply_val(ep_cap, 0), // SCHED_OTHER
            SYS_SCHED_GET_PRIORITY_MAX => reply_val(ep_cap, 99),
            SYS_SCHED_GET_PRIORITY_MIN => reply_val(ep_cap, 0),

            // Timer stubs
            SYS_GETITIMER => {
                let buf = msg.regs[1];
                if buf != 0 { unsafe { core::ptr::write_bytes(buf as *mut u8, 0, 32); } }
                reply_val(ep_cap, 0);
            }
            SYS_SETITIMER => {
                let old = msg.regs[2];
                if old != 0 { unsafe { core::ptr::write_bytes(old as *mut u8, 0, 32); } }
                reply_val(ep_cap, 0);
            }

            // Memory stubs
            SYS_MSYNC => reply_val(ep_cap, 0),
            SYS_MINCORE => reply_val(ep_cap, -ENOMEM), // report pages not resident

            // Shared memory stubs (SysV IPC)
            SYS_SHMGET => reply_val(ep_cap, -ENOSYS),
            SYS_SHMAT => reply_val(ep_cap, -ENOSYS),
            SYS_SHMCTL => reply_val(ep_cap, -ENOSYS),

            // SYS_chdir(80)
            SYS_CHDIR => reply_val(ep_cap, 0), // pretend success, cwd always "/"

            // ─── Phase C: Event subsystems (epoll, eventfd, timerfd) ─

            // SYS_eventfd(284) / SYS_eventfd2(290)
            SYS_EVENTFD | SYS_EVENTFD2 => {
                let initval = msg.regs[0];
                let flags = if syscall_nr == SYS_EVENTFD2 { msg.regs[1] as u32 } else { 0 };
                // Allocate fd + slot
                let mut fd = None;
                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                let mut slot = None;
                for i in 0..MAX_EVENTFDS { if eventfd_slot_fd[i] == usize::MAX { slot = Some(i); break; } }
                if let (Some(f), Some(s)) = (fd, slot) {
                    child_fds[f] = 22;
                    eventfd_slot_fd[s] = f;
                    eventfd_counter[s] = initval;
                    eventfd_flags[s] = flags;
                    reply_val(ep_cap, f as i64);
                } else { reply_val(ep_cap, -EMFILE); }
            }

            // SYS_timerfd_create(283)
            SYS_TIMERFD_CREATE => {
                let mut fd = None;
                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                let mut slot = None;
                for i in 0..MAX_TIMERFDS { if timerfd_slot_fd[i] == usize::MAX { slot = Some(i); break; } }
                if let (Some(f), Some(s)) = (fd, slot) {
                    child_fds[f] = 23;
                    timerfd_slot_fd[s] = f;
                    timerfd_expiry_tsc[s] = 0;
                    timerfd_interval_ns[s] = 0;
                    reply_val(ep_cap, f as i64);
                } else { reply_val(ep_cap, -EMFILE); }
            }

            // SYS_timerfd_settime(286)
            SYS_TIMERFD_SETTIME => {
                let fd = msg.regs[0] as usize;
                let _flags = msg.regs[1] as u32;
                let new_value_ptr = msg.regs[2];
                let old_value_ptr = msg.regs[3];
                if fd < CHILD_MAX_FDS && child_fds[fd] == 23 {
                    if let Some(slot) = timerfd_slot_fd.iter().position(|&x| x == fd) {
                        // Return old value
                        if old_value_ptr != 0 {
                            unsafe { core::ptr::write_bytes(old_value_ptr as *mut u8, 0, 32); }
                        }
                        // Read new_value: struct itimerspec { interval, value } each = struct timespec { sec, nsec }
                        if new_value_ptr != 0 {
                            let int_sec = unsafe { *(new_value_ptr as *const u64) };
                            let int_ns = unsafe { *((new_value_ptr + 8) as *const u64) };
                            let val_sec = unsafe { *((new_value_ptr + 16) as *const u64) };
                            let val_ns = unsafe { *((new_value_ptr + 24) as *const u64) };
                            let interval_ns = int_sec * 1_000_000_000 + int_ns;
                            let value_ns = val_sec * 1_000_000_000 + val_ns;
                            timerfd_interval_ns[slot] = interval_ns;
                            if value_ns == 0 {
                                timerfd_expiry_tsc[slot] = 0; // disarm
                            } else {
                                timerfd_expiry_tsc[slot] = rdtsc() + value_ns * 2; // ~2GHz TSC
                            }
                        }
                        reply_val(ep_cap, 0);
                    } else { reply_val(ep_cap, -EBADF); }
                } else { reply_val(ep_cap, -EBADF); }
            }

            // SYS_timerfd_gettime(287)
            SYS_TIMERFD_GETTIME => {
                let fd = msg.regs[0] as usize;
                let buf = msg.regs[1];
                if fd < CHILD_MAX_FDS && child_fds[fd] == 23 {
                    if let Some(slot) = timerfd_slot_fd.iter().position(|&x| x == fd) {
                        if buf != 0 {
                            unsafe { core::ptr::write_bytes(buf as *mut u8, 0, 32); }
                            let now = rdtsc();
                            let exp = timerfd_expiry_tsc[slot];
                            if exp > now {
                                let remaining_ns = (exp - now) / 2;
                                unsafe {
                                    *((buf + 16) as *mut u64) = remaining_ns / 1_000_000_000;
                                    *((buf + 24) as *mut u64) = remaining_ns % 1_000_000_000;
                                }
                            }
                            let int_ns = timerfd_interval_ns[slot];
                            if int_ns != 0 {
                                unsafe {
                                    *(buf as *mut u64) = int_ns / 1_000_000_000;
                                    *((buf + 8) as *mut u64) = int_ns % 1_000_000_000;
                                }
                            }
                        }
                        reply_val(ep_cap, 0);
                    } else { reply_val(ep_cap, -EBADF); }
                } else { reply_val(ep_cap, -EBADF); }
            }

            // Improved epoll: SYS_epoll_create/create1 (213/291) — already handled above
            // but now with proper fd tracking in epoll_reg_*

            // SYS_epoll_ctl(233) — register/modify/delete fd interest
            // (override the stub above)

            // SYS_epoll_wait(232) / SYS_epoll_pwait(281) — poll registered fds
            // (override the stub above)

            // SYS_socketpair(53) — create connected AF_UNIX pair
            SYS_SOCKETPAIR => {
                let _domain = msg.regs[0]; // AF_UNIX
                let _type = msg.regs[1];   // SOCK_STREAM | SOCK_CLOEXEC
                let sv_ptr = msg.regs[3];
                // Create two connected pipe endpoints
                let mut fd1 = None;
                let mut fd2 = None;
                for i in 3..CHILD_MAX_FDS {
                    if child_fds[i] == 0 {
                        if fd1.is_none() { fd1 = Some(i); }
                        else if fd2.is_none() { fd2 = Some(i); break; }
                    }
                }
                if let (Some(f1), Some(f2)) = (fd1, fd2) {
                    // Both ends are read/write pipes (kind=10 for convenience)
                    // Wine typically uses socketpair for simple data passing
                    child_fds[f1] = 10; // pipe-like
                    child_fds[f2] = 11; // pipe-like
                    if sv_ptr != 0 {
                        unsafe {
                            *(sv_ptr as *mut i32) = f1 as i32;
                            *((sv_ptr + 4) as *mut i32) = f2 as i32;
                        }
                    }
                    reply_val(ep_cap, 0);
                } else { reply_val(ep_cap, -EMFILE); }
            }

            // SYS_accept(43) / SYS_accept4(288)
            SYS_ACCEPT | SYS_ACCEPT4 => reply_val(ep_cap, -EAGAIN),

            // SYS_memfd_create(319)
            SYS_MEMFD_CREATE => {
                let mut fd = None;
                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                let mut slot = None;
                for i in 0..MAX_MEMFDS { if memfd_slot_fd[i] == usize::MAX { slot = Some(i); break; } }
                let mut vslot = None;
                for s in 0..MAX_VFS_FILES { if vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                if let (Some(f), Some(s), Some(vs)) = (fd, slot, vslot) {
                    // Allocate 64 KiB initially
                    const MEMFD_INIT_PAGES: u64 = 16;
                    let base = *mmap_next;
                    *mmap_next += MEMFD_INIT_PAGES * 0x1000;
                    let mut ok = true;
                    for p in 0..MEMFD_INIT_PAGES {
                        if let Ok(frame) = sys::frame_alloc() {
                            if sys::map(base + p * 0x1000, frame, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                    }
                    if ok {
                        unsafe { core::ptr::write_bytes(base as *mut u8, 0, (MEMFD_INIT_PAGES * 0x1000) as usize); }
                        child_fds[f] = 25;
                        memfd_slot_fd[s] = f;
                        memfd_base[s] = base;
                        memfd_size[s] = 0;
                        memfd_cap[s] = MEMFD_INIT_PAGES * 0x1000;
                        vfs_files[vs] = [0xFEFD, 0, 0, f as u64]; // sentinel OID, offset tracking
                        reply_val(ep_cap, f as i64);
                    } else { reply_val(ep_cap, -ENOMEM); }
                } else { reply_val(ep_cap, -EMFILE); }
            }

            // SYS_splice(275) / SYS_tee(276)
            SYS_SPLICE | SYS_TEE => reply_val(ep_cap, -ENOSYS),

            // SYS_inotify_init1(294) / SYS_inotify_add_watch(254) / SYS_inotify_rm_watch(255)
            SYS_INOTIFY_INIT1 => {
                // Return a fake fd — Wine checks for ENOSYS
                let mut fd = None;
                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                if let Some(f) = fd {
                    child_fds[f] = 8; // /dev/null-like (reads return 0)
                    reply_val(ep_cap, f as i64);
                } else { reply_val(ep_cap, -EMFILE); }
            }
            SYS_INOTIFY_ADD_WATCH => reply_val(ep_cap, 1), // fake watch descriptor
            SYS_INOTIFY_RM_WATCH => reply_val(ep_cap, 0),

            // SYS_signalfd(282) / SYS_signalfd4(289)
            SYS_SIGNALFD | SYS_SIGNALFD4 => {
                let mut fd = None;
                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                if let Some(f) = fd {
                    child_fds[f] = 8; // dummy fd
                    reply_val(ep_cap, f as i64);
                } else { reply_val(ep_cap, -EMFILE); }
            }

            // SYS_clone3(435) — modern clone
            SYS_CLONE3 => {
                // Return -ENOSYS to force fallback to clone(56)
                reply_val(ep_cap, -ENOSYS);
            }

            // Unknown → -ENOSYS (with logging)
            _ => {
                print(b"LUCAS child: unhandled syscall ");
                print_u64(syscall_nr);
                print(b" regs=[");
                print_u64(msg.regs[0]);
                print(b",");
                print_u64(msg.regs[1]);
                print(b",");
                print_u64(msg.regs[2]);
                print(b"]\n");
                reply_val(ep_cap, -ENOSYS);
            }
        }
    }

    // Child handler exiting (timeout or error). Clean up and mark as zombie.
    if pid > 0 && pid <= MAX_PROCS {
        // Free child stack pages
        let sbase = PROC_STACK_BASE[pid - 1].load(Ordering::Acquire);
        let spages = PROC_STACK_PAGES[pid - 1].load(Ordering::Acquire);
        if sbase != 0 && spages != 0 {
            for p in 0..spages { let _ = sys::unmap_free(sbase + p * 0x1000); }
            PROC_STACK_BASE[pid - 1].store(0, Ordering::Release);
            PROC_STACK_PAGES[pid - 1].store(0, Ordering::Release);
        }
        // Free ELF segment pages
        let elf_lo = PROC_ELF_LO[pid - 1].load(Ordering::Acquire);
        let elf_hi = PROC_ELF_HI[pid - 1].load(Ordering::Acquire);
        if elf_lo < elf_hi {
            let mut pg = elf_lo;
            while pg < elf_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
            PROC_ELF_LO[pid - 1].store(0, Ordering::Release);
            PROC_ELF_HI[pid - 1].store(0, Ordering::Release);
        }
        // Free interpreter pages if dynamic binary
        if PROC_HAS_INTERP[pid - 1].load(Ordering::Acquire) != 0 {
            for pg in 0..0x110u64 {
                let _ = sys::unmap_free(crate::exec::INTERP_LOAD_BASE + pg * 0x1000);
            }
            PROC_HAS_INTERP[pid - 1].store(0, Ordering::Release);
        }
        // Free pre-TLS page
        let _ = sys::unmap_free(0xB70000);
        // Free brk pages
        let brk_lo = PROC_BRK_BASE[pid - 1].load(Ordering::Acquire);
        let brk_hi = PROC_BRK_CURRENT[pid - 1].load(Ordering::Acquire);
        if brk_lo != 0 && brk_hi > brk_lo {
            let mut pg = brk_lo;
            while pg < brk_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
        }
        // Free mmap pages
        let mmap_lo = PROC_MMAP_BASE[pid - 1].load(Ordering::Acquire);
        let mmap_hi = PROC_MMAP_NEXT[pid - 1].load(Ordering::Acquire);
        if mmap_lo != 0 && mmap_hi > mmap_lo {
            let mut pg = mmap_lo;
            while pg < mmap_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
        }
        PROC_BRK_BASE[pid - 1].store(0, Ordering::Release);
        PROC_BRK_CURRENT[pid - 1].store(0, Ordering::Release);
        PROC_MMAP_BASE[pid - 1].store(0, Ordering::Release);
        PROC_MMAP_NEXT[pid - 1].store(0, Ordering::Release);
        // Reset group state
        unsafe { GRP_BRK[memg] = 0; GRP_MMAP_NEXT[memg] = 0; }
        // Mark as killed by SIGKILL (status 9)
        PROC_EXIT[pid - 1].store(9, Ordering::Release);
        PROC_STATE[pid - 1].store(2, Ordering::Release);
        // Deliver SIGCHLD to parent
        let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire) as usize;
        if ppid > 0 && ppid <= MAX_PROCS {
            sig_send(ppid, SIGCHLD as u64);
        }
    }
    sys::thread_exit();
}
