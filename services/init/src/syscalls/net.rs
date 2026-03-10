// ---------------------------------------------------------------------------
// Network + poll/select/epoll syscalls
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::exec::{reply_val, rdtsc};
use crate::process::{sig_dequeue, sig_dispatch};
use crate::fd::*;
use crate::NET_EP_CAP;
use crate::child_handler::mark_pipe_retry;
use crate::net::{NET_CMD_TCP_CONNECT, NET_CMD_TCP_SEND, NET_CMD_TCP_RECV,
                 NET_CMD_UDP_BIND, NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::framebuffer::{print, print_u64, kb_has_char};
use super::context::{SyscallContext, MAX_EPOLL_ENTRIES};

static NEXT_UDP_PORT: AtomicU64 = AtomicU64::new(49152);

/// Check if an fd is poll-readable (has data or is at EOF).
fn poll_fd_readable(ctx: &SyscallContext, fd: usize) -> bool {
    let kind = ctx.child_fds[fd];
    match kind {
        1 => unsafe { kb_has_char() }, // stdin
        10 => {
            // Pipe read: check if buffer has data OR writer is closed (EOF)
            let pipe_id = ctx.sock_conn_id[fd] as usize;
            pipe_has_data(pipe_id) || pipe_writer_closed(pipe_id)
        }
        2 | 8 | 12 | 13 | 14 | 15 | 16 | 22 | 23 | 25 => true, // always "ready"
        _ => true, // default: report readable
    }
}

pub(crate) fn sys_poll(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pid = ctx.pid;
    let ep_cap = ctx.ep_cap;
    let fds_ptr = msg.regs[0] as *mut u8;
    let nfds = msg.regs[1] as usize;
    let timeout = msg.regs[2] as i32;
    let mut ready = 0u32;
    for i in 0..nfds.min(16) {
        let pfd = unsafe { fds_ptr.add(i * 8) };
        let fd = unsafe { *(pfd as *const i32) };
        let events = unsafe { *((pfd.add(4)) as *const i16) };
        let mut revents: i16 = 0;
        if fd >= 0 && (fd as usize) < GRP_MAX_FDS && ctx.child_fds[fd as usize] != 0 {
            if events & 1 != 0 { // POLLIN
                if poll_fd_readable(ctx, fd as usize) { revents |= 1; }
            }
            if events & 4 != 0 { revents |= 4; } // POLLOUT: always writable
        } else if fd >= 0 {
            revents = 0x20; // POLLNVAL
        }
        unsafe { *((pfd.add(6)) as *mut i16) = revents; }
        if revents != 0 { ready += 1; }
    }
    if ready > 0 || timeout == 0 {
        reply_val(ep_cap, ready as i64);
    } else {
        // No fds ready — use PIPE_RETRY_TAG to let kernel retry after
        // yielding. This avoids blocking init (which stalls all children).
        mark_pipe_retry(ctx.pid);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

pub(crate) fn sys_ppoll(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fds_ptr = msg.regs[0] as *mut u8;
    let nfds = msg.regs[1] as usize;
    let mut ready = 0u32;
    for i in 0..nfds.min(16) {
        let pfd = unsafe { fds_ptr.add(i * 8) };
        let fd = unsafe { *(pfd as *const i32) };
        let events = unsafe { *((pfd.add(4)) as *const i16) };
        let mut revents: i16 = 0;
        if fd >= 0 && (fd as usize) < GRP_MAX_FDS && ctx.child_fds[fd as usize] != 0 {
            if events & 1 != 0 {
                if poll_fd_readable(ctx, fd as usize) { revents |= 1; }
            }
            if events & 4 != 0 { revents |= 4; }
        } else if fd >= 0 { revents = 0x20; }
        unsafe { *((pfd.add(6)) as *mut i16) = revents; }
        if revents != 0 { ready += 1; }
    }
    if ready > 0 {
        reply_val(ep_cap, ready as i64);
    } else {
        // No fds ready — use PIPE_RETRY_TAG for kernel-side retry
        mark_pipe_retry(ctx.pid);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

pub(crate) fn sys_socket(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let domain = msg.regs[0] as u32;
    let sock_type = msg.regs[1] as u32;
    let base_type = sock_type & 0xFF;
    if domain == 2 && (base_type == 1 || base_type == 2 || base_type == 3) {
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 {
            reply_val(ep_cap, -EADDRNOTAVAIL);
        } else {
            let mut fd = None;
            for f in 3..GRP_MAX_FDS {
                if ctx.child_fds[f] == 0 { fd = Some(f); break; }
            }
            match fd {
                Some(f) => {
                    if base_type == 1 {
                        ctx.child_fds[f] = 16; // TCP
                        ctx.sock_conn_id[f] = 0xFFFF;
                    } else {
                        ctx.child_fds[f] = 17; // UDP
                        let port = NEXT_UDP_PORT.fetch_add(1, Ordering::SeqCst) as u16;
                        ctx.sock_udp_local_port[f] = port;
                        let bind_req = IpcMsg {
                            tag: NET_CMD_UDP_BIND,
                            regs: [port as u64, 0, 0, 0, 0, 0, 0, 0],
                        };
                        let _ = sys::call_timeout(net_cap, &bind_req, 500);
                    }
                    reply_val(ep_cap, f as i64);
                }
                None => reply_val(ep_cap, -EMFILE),
            }
        }
    } else {
        reply_val(ep_cap, -EAFNOSUPPORT);
    }
}

pub(crate) fn sys_connect(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let pid = ctx.pid;
    let fd = msg.regs[0] as usize;
    let sockaddr_ptr = msg.regs[1];
    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17) {
        reply_val(ep_cap, -EBADF);
    } else {
        let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
        let port = u16::from_be_bytes([sa[2], sa[3]]);
        let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

        if ctx.child_fds[fd] == 17 {
            ctx.sock_udp_remote_ip[fd] = ip;
            ctx.sock_udp_remote_port[fd] = port;
            reply_val(ep_cap, 0);
        } else {
            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
            if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
            let req = IpcMsg {
                tag: NET_CMD_TCP_CONNECT,
                regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 20000) {
                Ok(resp) => {
                    let conn_id = resp.regs[0];
                    if conn_id as i64 >= 0 {
                        ctx.sock_conn_id[fd] = conn_id as u32;
                        if pid > 1 {
                            print(b"TCP-CONN: fd=");
                            print_u64(fd as u64);
                            print(b" conn=");
                            print_u64(conn_id);
                            print(b" ip=");
                            print_u64(ip as u64);
                            print(b":"); print_u64(port as u64);
                            print(b"\n");
                        }
                        reply_val(ep_cap, 0);
                    } else {
                        if pid > 1 {
                            print(b"TCP-CONN-REFUSED ip=");
                            print_u64(ip as u64);
                            print(b":"); print_u64(port as u64);
                            print(b"\n");
                        }
                        reply_val(ep_cap, -ECONNREFUSED);
                    }
                }
                Err(_) => {
                    if pid > 1 {
                        print(b"TCP-CONN-TIMEOUT ip=");
                        print_u64(ip as u64);
                        print(b":"); print_u64(port as u64);
                        print(b"\n");
                    }
                    reply_val(ep_cap, -ETIMEDOUT);
                }
            }
        }
    }
}

pub(crate) fn sys_sendto(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    let dest_ptr = msg.regs[4];

    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17) {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 17 {
        // UDP sendto
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let (dst_ip, dst_port) = if dest_ptr != 0 {
            let sa = unsafe { core::slice::from_raw_parts(dest_ptr as *const u8, 8) };
            let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
            let port = u16::from_be_bytes([sa[2], sa[3]]);
            ctx.sock_udp_remote_ip[fd] = ip;
            ctx.sock_udp_remote_port[fd] = port;
            (ip, port)
        } else {
            (ctx.sock_udp_remote_ip[fd], ctx.sock_udp_remote_port[fd])
        };
        let src_port = ctx.sock_udp_local_port[fd];
        let send_len = len.min(32);
        let mut req = IpcMsg {
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
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let send_len = len.min(40);
        let mut req = IpcMsg {
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

pub(crate) fn sys_sendmsg(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let msghdr_ptr = msg.regs[1];

    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17) {
        reply_val(ep_cap, -EBADF);
        return;
    }

    let (msg_name, _msg_namelen, msg_iov, msg_iovlen) = unsafe {
        let p = msghdr_ptr as *const u64;
        (*p, *p.add(1) as u32, *p.add(2), *p.add(3) as usize)
    };
    if msg_iovlen == 0 {
        reply_val(ep_cap, 0);
        return;
    }
    let (iov_base, iov_len) = unsafe {
        let iov = msg_iov as *const u64;
        (*iov, *iov.add(1) as usize)
    };

    if ctx.child_fds[fd] == 17 {
        // UDP sendmsg
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let (dst_ip, dst_port) = if msg_name != 0 {
            let sa = unsafe { core::slice::from_raw_parts(msg_name as *const u8, 8) };
            let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);
            let port = u16::from_be_bytes([sa[2], sa[3]]);
            ctx.sock_udp_remote_ip[fd] = ip;
            ctx.sock_udp_remote_port[fd] = port;
            (ip, port)
        } else {
            (ctx.sock_udp_remote_ip[fd], ctx.sock_udp_remote_port[fd])
        };
        let src_port = ctx.sock_udp_local_port[fd];
        let send_len = iov_len.min(40);
        let mut req = IpcMsg {
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
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let send_len = iov_len.min(40);
        let mut req = IpcMsg {
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

pub(crate) fn sys_recvfrom(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let len = msg.regs[2] as usize;
    let src_addr_ptr = msg.regs[4];
    let addrlen_ptr = msg.regs[5];

    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17) {
        reply_val(ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 17 {
        // UDP recvfrom
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let src_port = ctx.sock_udp_local_port[fd];
        let recv_len = len.min(64);
        let mut got = 0usize;
        for _attempt in 0..50u32 {
            let req = IpcMsg {
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
            if src_addr_ptr != 0 {
                let remote_ip = ctx.sock_udp_remote_ip[fd];
                let remote_port = ctx.sock_udp_remote_port[fd];
                unsafe {
                    let sa = src_addr_ptr as *mut u8;
                    *sa.add(0) = 2; *sa.add(1) = 0;
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
        // TCP recvfrom
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let recv_len = len.min(64);
        let mut got = 0usize;
        for _ in 0..5000u32 {
            let req = IpcMsg {
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

pub(crate) fn sys_recvmsg(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let fd = msg.regs[0] as usize;
    let msghdr_ptr = msg.regs[1];

    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 16 && ctx.child_fds[fd] != 17) {
        reply_val(ep_cap, -EBADF);
        return;
    }

    let (msg_name, msg_namelen, msg_iov, msg_iovlen) = unsafe {
        let p = msghdr_ptr as *const u64;
        (
            *p,
            *p.add(1) as u32,
            *p.add(2),
            *p.add(3) as usize,
        )
    };

    if msg_iovlen == 0 {
        reply_val(ep_cap, 0);
        return;
    }
    let (iov_base, iov_len) = unsafe {
        let iov = msg_iov as *const u64;
        (*iov, *iov.add(1) as usize)
    };

    if ctx.child_fds[fd] == 17 {
        // UDP recvmsg
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        if net_cap == 0 { reply_val(ep_cap, -EADDRNOTAVAIL); return; }
        let src_port = ctx.sock_udp_local_port[fd];
        let recv_len = iov_len.min(64);
        let mut total_n = 0usize;
        for _attempt in 0..50u32 {
            let req = IpcMsg {
                tag: NET_CMD_UDP_RECV,
                regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 5000) {
                Ok(resp) => {
                    let n = resp.tag as usize;
                    if n > 0 && n <= recv_len {
                        unsafe {
                            let src = &resp.regs[0] as *const u64 as *const u8;
                            core::ptr::copy_nonoverlapping(src, iov_base as *mut u8, n);
                        }
                        total_n = n;
                        break;
                    }
                }
                Err(_) => {}
            }
        }
        if total_n > 0 {
            if msg_name != 0 && msg_namelen >= 16 {
                let remote_ip = ctx.sock_udp_remote_ip[fd];
                let remote_port = ctx.sock_udp_remote_port[fd];
                unsafe {
                    let sa = msg_name as *mut u8;
                    *sa.add(0) = 2; *sa.add(1) = 0;
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
            reply_val(ep_cap, -EAGAIN);
        }
    } else {
        // TCP recvmsg
        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
        let conn_id = ctx.sock_conn_id[fd] as u64;
        let recv_len = iov_len.min(64);
        let mut got = 0usize;
        for _ in 0..5000u32 {
            let req = IpcMsg {
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

pub(crate) fn sys_bind_listen_setsockopt(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

pub(crate) fn sys_getsockname(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let ep_cap = ctx.ep_cap;
    let sockaddr_ptr = msg.regs[1];
    let addrlen_ptr = msg.regs[2];
    if sockaddr_ptr != 0 {
        let fd = msg.regs[0] as usize;
        let sa = sockaddr_ptr as *mut u8;
        unsafe {
            core::ptr::write_bytes(sa, 0, 16);
            *(sa as *mut u16) = 2; // AF_INET
            if syscall_nr == SYS_GETSOCKNAME {
                *sa.add(4) = 10; *sa.add(5) = 0; *sa.add(6) = 2; *sa.add(7) = 15;
            } else if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 16 {
                // Return stored remote addr (zeros for now)
            }
        }
    }
    if addrlen_ptr != 0 {
        unsafe { *(addrlen_ptr as *mut u32) = 16; }
    }
    reply_val(ep_cap, 0);
}

pub(crate) fn sys_getsockopt(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let optval_ptr = msg.regs[3];
    let optlen_ptr = msg.regs[4];
    if optval_ptr != 0 {
        unsafe { *(optval_ptr as *mut i32) = 0; }
    }
    if optlen_ptr != 0 {
        unsafe { *(optlen_ptr as *mut u32) = 4; }
    }
    reply_val(ep_cap, 0);
}

pub(crate) fn sys_shutdown(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

pub(crate) fn sys_select(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let pid = ctx.pid;
    let ep_cap = ctx.ep_cap;
    let nfds = (msg.regs[0] as usize).min(GRP_MAX_FDS);
    let readfds_ptr = msg.regs[1];
    let writefds_ptr = msg.regs[2];
    let exceptfds_ptr = msg.regs[3];
    let timeout_ptr = msg.regs[4];

    let timeout_ms: i64 = if timeout_ptr == 0 {
        -1
    } else if syscall_nr == SYS_SELECT {
        let sec = unsafe { *(timeout_ptr as *const i64) };
        let usec = unsafe { *((timeout_ptr + 8) as *const i64) };
        sec * 1000 + usec / 1000
    } else {
        let sec = unsafe { *(timeout_ptr as *const i64) };
        let nsec = unsafe { *((timeout_ptr + 8) as *const i64) };
        sec * 1000 + nsec / 1_000_000
    };

    if exceptfds_ptr != 0 { unsafe { *(exceptfds_ptr as *mut u64) = 0; } }

    let rfds_in = if readfds_ptr != 0 { unsafe { *(readfds_ptr as *const u64) } } else { 0 };
    let wfds_in = if writefds_ptr != 0 { unsafe { *(writefds_ptr as *const u64) } } else { 0 };

    let mut rfds_out: u64 = 0;
    let mut wfds_out: u64 = 0;
    let mut ready: u32 = 0;
    for fd in 0..nfds {
        let bit = 1u64 << fd;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            if rfds_in & bit != 0 {
                if poll_fd_readable(ctx, fd) { rfds_out |= bit; ready += 1; }
            }
            if wfds_in & bit != 0 {
                wfds_out |= bit; ready += 1;
            }
        }
    }

    if ready > 0 || timeout_ms == 0 {
        if readfds_ptr != 0 { unsafe { *(readfds_ptr as *mut u64) = rfds_out; } }
        if writefds_ptr != 0 { unsafe { *(writefds_ptr as *mut u64) = wfds_out; } }
        reply_val(ep_cap, ready as i64);
    } else {
        // No fds ready — use PIPE_RETRY_TAG for kernel-side retry
        mark_pipe_retry(ctx.pid);
        let reply = sotos_common::IpcMsg {
            tag: sotos_common::PIPE_RETRY_TAG,
            regs: [0; 8],
        };
        let _ = sys::send(ep_cap, &reply);
    }
}

pub(crate) fn sys_epoll_create(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let mut efd: i64 = -24; // -EMFILE
    for f in 3..GRP_MAX_FDS {
        if ctx.child_fds[f] == 0 {
            ctx.child_fds[f] = 21; // kind 21 = epoll
            efd = f as i64;
            break;
        }
    }
    reply_val(ep_cap, efd);
}

pub(crate) fn sys_epoll_ctl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
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
            if let Some(i) = ctx.epoll_reg_fd.iter().position(|&x| x == -1) {
                ctx.epoll_reg_fd[i] = fd;
                ctx.epoll_reg_events[i] = events;
                ctx.epoll_reg_data[i] = data;
            }
            reply_val(ep_cap, 0);
        }
        2 => { // EPOLL_CTL_DEL
            if let Some(i) = ctx.epoll_reg_fd.iter().position(|&x| x == fd) {
                ctx.epoll_reg_fd[i] = -1;
            }
            reply_val(ep_cap, 0);
        }
        3 => { // EPOLL_CTL_MOD
            if let Some(i) = ctx.epoll_reg_fd.iter().position(|&x| x == fd) {
                ctx.epoll_reg_events[i] = events;
                ctx.epoll_reg_data[i] = data;
            }
            reply_val(ep_cap, 0);
        }
        _ => reply_val(ep_cap, -EINVAL),
    }
}

pub(crate) fn sys_epoll_wait(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let events_ptr = msg.regs[1];
    let max_events = (msg.regs[2] as usize).min(32);
    let timeout = msg.regs[3] as i32;
    let mut ready_count = 0usize;
    for i in 0..MAX_EPOLL_ENTRIES {
        if ctx.epoll_reg_fd[i] < 0 { continue; }
        if ready_count >= max_events { break; }
        let rfd = ctx.epoll_reg_fd[i] as usize;
        let wanted = ctx.epoll_reg_events[i];
        let mut revents = 0u32;
        if rfd < GRP_MAX_FDS {
            let kind = ctx.child_fds[rfd];
            if kind == 0 {
                revents |= 0x10; // EPOLLHUP
            } else {
                if wanted & 1 != 0 {
                    if kind == 1 {
                        if unsafe { kb_has_char() } { revents |= 1; }
                    } else if kind == 22 {
                        if let Some(s) = ctx.eventfd_slot_fd.iter().position(|&x| x == rfd) {
                            if ctx.eventfd_counter[s] > 0 { revents |= 1; }
                        }
                    } else if kind == 23 {
                        if let Some(s) = ctx.timerfd_slot_fd.iter().position(|&x| x == rfd) {
                            let exp = ctx.timerfd_expiry_tsc[s];
                            if exp != 0 && rdtsc() >= exp { revents |= 1; }
                        }
                    } else if kind == 10 {
                        revents |= 1;
                    } else if kind == 13 || kind == 12 || kind == 15 {
                        revents |= 1;
                    } else if kind == 16 {
                        revents |= 1;
                    }
                }
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
                *((ep + 4) as *mut u64) = ctx.epoll_reg_data[i];
            }
            ready_count += 1;
        }
    }
    if ready_count > 0 || timeout == 0 {
        reply_val(ep_cap, ready_count as i64);
    } else {
        let deadline = rdtsc() + (timeout as u64).min(30000) * 2_000_000;
        loop {
            let mut found = false;
            for i in 0..MAX_EPOLL_ENTRIES {
                if ctx.epoll_reg_fd[i] < 0 { continue; }
                let rfd = ctx.epoll_reg_fd[i] as usize;
                let wanted = ctx.epoll_reg_events[i];
                if rfd < GRP_MAX_FDS {
                    let kind = ctx.child_fds[rfd];
                    let mut rev = 0u32;
                    if wanted & 1 != 0 && kind == 1 && unsafe { kb_has_char() } { rev |= 1; }
                    if wanted & 1 != 0 && kind == 22 {
                        if let Some(s) = ctx.eventfd_slot_fd.iter().position(|&x| x == rfd) {
                            if ctx.eventfd_counter[s] > 0 { rev |= 1; }
                        }
                    }
                    if wanted & 1 != 0 && kind == 23 {
                        if let Some(s) = ctx.timerfd_slot_fd.iter().position(|&x| x == rfd) {
                            if ctx.timerfd_expiry_tsc[s] != 0 && rdtsc() >= ctx.timerfd_expiry_tsc[s] { rev |= 1; }
                        }
                    }
                    if rev != 0 {
                        let ep = events_ptr + (ready_count as u64) * 12;
                        unsafe {
                            *(ep as *mut u32) = rev;
                            *((ep + 4) as *mut u64) = ctx.epoll_reg_data[i];
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

pub(crate) fn sys_socketpair(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let ep_cap = ctx.ep_cap;
    let _domain = msg.regs[0];
    let _type = msg.regs[1];
    let sv_ptr = msg.regs[3];
    let mut fd1 = None;
    let mut fd2 = None;
    for i in 3..GRP_MAX_FDS {
        if ctx.child_fds[i] == 0 {
            if fd1.is_none() { fd1 = Some(i); }
            else if fd2.is_none() { fd2 = Some(i); break; }
        }
    }
    if let (Some(f1), Some(f2)) = (fd1, fd2) {
        ctx.child_fds[f1] = 10;
        ctx.child_fds[f2] = 11;
        if sv_ptr != 0 {
            unsafe {
                *(sv_ptr as *mut i32) = f1 as i32;
                *((sv_ptr + 4) as *mut i32) = f2 as i32;
            }
        }
        reply_val(ep_cap, 0);
    } else { reply_val(ep_cap, -EMFILE); }
}

pub(crate) fn sys_accept(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -EAGAIN);
}
