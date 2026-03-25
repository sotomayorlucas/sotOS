// ---------------------------------------------------------------------------
// fs_vfs.rs — VFS file operations: open, openat, read/write/close for VFS
//             files (kind=13/14), stat, fstat, fstatat, lseek, pread64,
//             pwrite64, readv/writev for VFS, ftruncate, fsync, access,
//             rename, statfs, creat, copy_file_range, sendfile, fadvise64,
//             readlink, readlinkat, proc_self_exe, file metadata stubs, umask
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::{reply_val, rdtsc, starts_with,
                  format_uptime_into, format_proc_self_stat};
use crate::process::*;
use crate::fd::*;
use crate::child_handler::open_virtual_file;
use crate::{NET_EP_CAP, vfs_lock, vfs_unlock, shared_store};
use crate::net::{NET_CMD_TCP_SEND, NET_CMD_TCP_RECV, NET_CMD_TCP_CLOSE,
                 NET_CMD_UDP_SENDTO, NET_CMD_UDP_RECV};
use crate::framebuffer::{print, print_u64};
use crate::syscall_log::format_syslog_into;
use crate::syscalls::context::SyscallContext;
use super::dir_store_path;

const MAP_WRITABLE: u64 = 2;

/// Handle sys_read for VFS file (kind=13).
pub(crate) fn read_vfs(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let mut found = false;
    for s in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
            let oid = ctx.vfs_files[s][0];
            let pos = ctx.vfs_files[s][2] as usize;
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            let dst = &mut local_buf[..safe_len];
            vfs_lock();
            let result = unsafe { shared_store() }
                .and_then(|store| store.read_obj_range(oid, pos, dst).ok());
            vfs_unlock();
            match result {
                Some(n) => {
                    ctx.guest_write(buf_ptr, &local_buf[..n]);
                    ctx.vfs_files[s][2] += n as u64;
                    reply_val(ctx.ep_cap, n as i64);
                }
                None => reply_val(ctx.ep_cap, -EIO),
            }
            found = true;
            break;
        }
    }
    if !found { reply_val(ctx.ep_cap, -EBADF); }
}

/// Handle sys_read for virtual/procfs file (kind=15).
pub(crate) fn read_virtual(ctx: &mut SyscallContext, buf_ptr: u64, len: usize) {
    let avail = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
    let to_read = len.min(avail);
    if to_read > 0 {
        ctx.guest_write(buf_ptr, &ctx.dir_buf[*ctx.dir_pos..*ctx.dir_pos + to_read]);
        *ctx.dir_pos += to_read;
    }
    reply_val(ctx.ep_cap, to_read as i64);
}

/// Handle sys_read for TCP socket (kind=16).
pub(crate) fn read_tcp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let max_read = len.min(32768);
    let mut total = 0usize;
    let mut empty_retries = 0u32;
    let mut saw_eof = false;

    while total < max_read && empty_retries < 50000 {
        let want = (max_read - total).min(4096) as u64;
        let req = IpcMsg {
            tag: NET_CMD_TCP_RECV,
            regs: [conn_id, 64, 0, want, 0, 0, 0, 0],
        };
        match sys::call_timeout(net_cap, &req, 200) {
            Ok(resp) => {
                let first_n = resp.tag as usize;
                if first_n == 0xFFFE {
                    saw_eof = true; break;
                }
                if first_n == 0 {
                    if total > 0 {
                        break;
                    }
                    empty_retries += 1;
                    sys::yield_now();
                    continue;
                }
                let actual_first = first_n.min(64);
                let src = unsafe {
                    core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, actual_first)
                };
                ctx.guest_write(buf_ptr + total as u64, src);
                total += actual_first;
                empty_retries = 0;

                let mut buf_offset = actual_first;
                while total < max_read && buf_offset < 4096 {
                    let cont_req = IpcMsg {
                        tag: NET_CMD_TCP_RECV,
                        regs: [conn_id, 64, buf_offset as u64, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &cont_req, 100) {
                        Ok(cont_resp) => {
                            let cn = cont_resp.tag as usize;
                            if cn == 0 || cn == 0xFFFE { break; }
                            let actual_cn = cn.min(64);
                            let cont_src = unsafe {
                                core::slice::from_raw_parts(&cont_resp.regs[0] as *const u64 as *const u8, actual_cn)
                            };
                            ctx.guest_write(buf_ptr + total as u64, cont_src);
                            total += actual_cn;
                            buf_offset += actual_cn;
                            if actual_cn < 64 { break; }
                        }
                        Err(_) => break,
                    }
                }
                if first_n < 64 { break; }
            }
            Err(_) => {
                if total > 0 { break; }
                empty_retries += 1;
                sys::yield_now();
            }
        }
    }
    if total > 0 {
        reply_val(ctx.ep_cap, total as i64);
    } else if saw_eof {
        reply_val(ctx.ep_cap, 0);
    } else {
        reply_val(ctx.ep_cap, -EAGAIN);
    }
}

/// Handle sys_read for UDP socket (kind=17).
pub(crate) fn read_udp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let port = ctx.sock_udp_local_port[fd];
    let recv_len = len.min(56);
    if net_cap == 0 || port == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else {
        let req = IpcMsg {
            tag: NET_CMD_UDP_RECV,
            regs: [port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
        };
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => {
                let n = resp.tag as usize;
                if n > 0 && n <= recv_len {
                    let src = unsafe {
                        core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, n)
                    };
                    ctx.guest_write(buf_ptr, src);
                }
                reply_val(ctx.ep_cap, n as i64);
            }
            Err(_) => reply_val(ctx.ep_cap, 0),
        }
    }
}

/// Handle sys_write for VFS file (kind=13).
pub(crate) fn write_vfs(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let mut found = false;
    for s in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
            let oid = ctx.vfs_files[s][0];
            let pos = ctx.vfs_files[s][2] as usize;
            let safe_len = len.min(4096);
            let mut local_buf = [0u8; 4096];
            ctx.guest_read(buf_ptr, &mut local_buf[..safe_len]);
            let data = &local_buf[..safe_len];
            vfs_lock();
            let result = unsafe { shared_store() }
                .and_then(|store| store.write_obj_range(oid, pos, data).ok());
            vfs_unlock();
            match result {
                Some(_) => {
                    ctx.vfs_files[s][2] += safe_len as u64;
                    let new_end = ctx.vfs_files[s][2];
                    if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                    if ctx.pid >= 5 {
                        print(b"VFS-W P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(fd as u64);
                        print(b" oid=0x"); crate::framebuffer::print_hex64(oid);
                        print(b" pos="); print_u64(pos as u64);
                        print(b" len="); print_u64(safe_len as u64);
                        print(b"\n");
                    }
                    reply_val(ctx.ep_cap, safe_len as i64);
                }
                None => {
                    if ctx.pid >= 5 {
                        print(b"VFS-W-FAIL P"); print_u64(ctx.pid as u64);
                        print(b" fd="); print_u64(fd as u64);
                        print(b" oid=0x"); crate::framebuffer::print_hex64(oid);
                        print(b"\n");
                    }
                    reply_val(ctx.ep_cap, -EIO);
                }
            }
            found = true;
            break;
        }
    }
    if !found {
        if ctx.pid >= 5 {
            print(b"VFS-W-NOFD P"); print_u64(ctx.pid as u64);
            print(b" fd="); print_u64(fd as u64);
            print(b"\n");
        }
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Handle sys_write for TCP socket (kind=16).
pub(crate) fn write_tcp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let mut total_sent = 0usize;
    let mut off = 0usize;
    while off < len {
        let chunk = (len - off).min(40);
        let mut req = sotos_common::IpcMsg {
            tag: NET_CMD_TCP_SEND,
            regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
        };
        let mut data = [0u8; 40];
        ctx.guest_read(buf_ptr + off as u64, &mut data[..chunk]);
        unsafe {
            let dst = &mut req.regs[3] as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, chunk);
        }
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => {
                let n = resp.regs[0] as i64;
                if n <= 0 {
                    if ctx.pid > 1 && total_sent == 0 {
                        print(b"TCP-SEND-FAIL fd=");
                        print_u64(fd as u64);
                        print(b" conn=");
                        print_u64(conn_id);
                        print(b" n=");
                        print_u64(resp.regs[0]);
                        print(b"\n");
                    }
                    break;
                }
                let n = n as usize;
                total_sent += n;
                off += n;
            }
            Err(_) => {
                if ctx.pid > 1 && total_sent == 0 {
                    print(b"TCP-SEND-IPC-ERR conn=");
                    print_u64(conn_id);
                    print(b"\n");
                }
                break;
            }
        }
    }
    if total_sent > 0 {
        reply_val(ctx.ep_cap, total_sent as i64);
    } else {
        reply_val(ctx.ep_cap, -EIO);
    }
}

/// Handle sys_write for UDP socket (kind=17).
pub(crate) fn write_udp(ctx: &mut SyscallContext, fd: usize, buf_ptr: u64, len: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let remote_ip = ctx.sock_udp_remote_ip[fd];
    let remote_port = ctx.sock_udp_remote_port[fd];
    let src_port = ctx.sock_udp_local_port[fd];
    if net_cap == 0 || remote_ip == 0 {
        reply_val(ctx.ep_cap, -EDESTADDRREQ);
    } else {
        let send_len = len.min(56);
        let packed_tag = NET_CMD_UDP_SENDTO | ((send_len as u64) << 16);
        let packed_r0 = (remote_ip as u64)
            | ((remote_port as u64) << 32)
            | ((src_port as u64) << 48);
        let mut req = sotos_common::IpcMsg {
            tag: packed_tag,
            regs: [packed_r0, 0, 0, 0, 0, 0, 0, 0],
        };
        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
        unsafe {
            let dst = &mut req.regs[1] as *mut u64 as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
        }
        match sys::call_timeout(net_cap, &req, 500) {
            Ok(resp) => reply_val(ctx.ep_cap, resp.regs[0] as i64),
            Err(_) => reply_val(ctx.ep_cap, -EIO),
        }
    }
}

/// Handle close for VFS file (kind=13) or directory (kind=14).
pub(crate) fn close_vfs(ctx: &mut SyscallContext, fd: usize) {
    for s in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s][3] == fd as u64 { ctx.vfs_files[s] = [0; 4]; break; }
    }
}

/// Handle close for TCP socket (kind=16).
pub(crate) fn close_tcp(ctx: &mut SyscallContext, fd: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let cid = ctx.sock_conn_id[fd];
    if net_cap != 0 && cid != 0xFFFF {
        let req = sotos_common::IpcMsg {
            tag: NET_CMD_TCP_CLOSE,
            regs: [cid as u64, 0, 0, 0, 0, 0, 0, 0],
        };
        let _ = sys::call_timeout(net_cap, &req, 500);
    }
    ctx.sock_conn_id[fd] = 0xFFFF;
}

/// SYS_FSTAT (5): fstat on an open fd.
pub(crate) fn sys_fstat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let stat_ptr = msg.regs[1];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        let mut size = 0u64;
        let mut ino = 0u64;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                size = ctx.initrd_files[s][1];
                ino = ctx.initrd_files[s][0];
                break;
            }
        }
        let buf = build_linux_stat_dev(1, ino, size, false);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        let is_vfs_dir = ctx.child_fds[fd] == 14;
        let mut size = 0u64;
        let mut oid = 0u64;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                oid = ctx.vfs_files[s][0];
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
        let buf = build_linux_stat_dev(2, oid, size, is_vfs_dir);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 15 {
        let buf = build_linux_stat(fd as u64, *ctx.dir_len as u64, false);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 30 {
        // DRM device: report as S_IFCHR with major 226
        crate::drm::drm_fstat(ctx, stat_ptr);
        reply_val(ctx.ep_cap, 0);
    } else if ctx.child_fds[fd] == 31 || ctx.child_fds[fd] == 32 {
        // evdev input device: S_IFCHR, major=13 (INPUT_MAJOR), minor=64/65
        let minor: u64 = if ctx.child_fds[fd] == 31 { 64 } else { 65 };
        let mut st = [0u8; 144];
        st[8..16].copy_from_slice(&(minor + 1).to_le_bytes()); // st_ino
        st[16..20].copy_from_slice(&1u32.to_le_bytes()); // st_nlink
        let mode: u32 = 0o020000 | 0o660; // S_IFCHR | 0660
        st[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
        let rdev: u64 = (13u64 << 8) | minor; // makedev(13, minor)
        st[40..48].copy_from_slice(&rdev.to_le_bytes()); // st_rdev
        st[56..60].copy_from_slice(&4096i32.to_le_bytes()); // st_blksize
        ctx.guest_write(stat_ptr, &st);
        reply_val(ctx.ep_cap, 0);
    } else {
        let buf = build_linux_stat(fd as u64, 0, false);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    }
}

/// SYS_STAT (4) / SYS_LSTAT (6): stat a path.
pub(crate) fn sys_stat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let stat_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    if ctx.pid >= 2 {
        print(b"STAT P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]\n");
    }
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    // Resolve symlinks
    let (path, path_len) = {
        let mut resolved = [0u8; 256];
        let rlen = crate::fd::symlink_resolve(&path[..path_len], &mut resolved);
        let mut out = [0u8; 128];
        let n = rlen.min(127);
        out[..n].copy_from_slice(&resolved[..n]);
        (out, n)
    };
    let name = &path[..path_len];

    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            let buf = build_linux_stat(0, sz, false);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }

    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();

    if let Some((oid, size, is_dir)) = vfs_stat {
        let buf = build_linux_stat_dev(2, oid, size, is_dir);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else {
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/share/terminfo"
            || name == b"/usr/share/terminfo/x"
            || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
            || starts_with(name, b"/usr/share/X11/xkb/")
            || name == b"/usr/libexec"
            || name == b"/usr/libexec/git-core"
            || name == b"/usr/local" || name == b"/usr/local/bin"
            || starts_with(name, b"/dev/")
            || crate::udev::is_sys_drm_dir(name);
        // DRM and evdev device files should be reported as character devices, not dirs.
        let is_dev_char = name == b"/dev/dri/card0"
            || name == b"/dev/input/event0"
            || name == b"/dev/input/event1";
        if is_dev_char {
            crate::drm::drm_fstat(ctx, stat_ptr);
            reply_val(ctx.ep_cap, 0);
        } else if is_known_dir {
            if ctx.pid == 2 && starts_with(name, b"/usr/share/X11") {
                print(b"STAT-DIR-OK ["); for &b in name { sys::debug_print(b); } print(b"]\n");
            }
            let buf = build_linux_stat(0, 4096, true);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
        } else {
            if ctx.pid == 2 && starts_with(name, b"/usr/share/X11") {
                print(b"STAT-ENOENT ["); for &b in name { sys::debug_print(b); } print(b"]\n");
            }
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_LSEEK (8): seek on an open fd.
pub(crate) fn sys_lseek(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let offset_val = msg.regs[1] as i64;
    let whence = msg.regs[2] as u32;
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        let mut found = false;
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                let file_size = ctx.initrd_files[s][1] as i64;
                let cur_pos = ctx.initrd_files[s][2] as i64;
                let new_pos = match whence {
                    0 => offset_val,
                    1 => cur_pos + offset_val,
                    2 => file_size + offset_val,
                    _ => { reply_val(ctx.ep_cap, -EINVAL); found = true; break; }
                };
                if new_pos < 0 {
                    reply_val(ctx.ep_cap, -EINVAL);
                } else {
                    ctx.initrd_files[s][2] = new_pos as u64;
                    reply_val(ctx.ep_cap, new_pos);
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
        let mut found = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let file_size = ctx.vfs_files[s][1] as i64;
                let cur_pos = ctx.vfs_files[s][2] as i64;
                let new_pos = match whence {
                    0 => offset_val,
                    1 => cur_pos + offset_val,
                    2 => file_size + offset_val,
                    _ => { reply_val(ctx.ep_cap, -EINVAL); found = true; break; }
                };
                if new_pos < 0 {
                    reply_val(ctx.ep_cap, -EINVAL);
                } else {
                    ctx.vfs_files[s][2] = new_pos as u64;
                    reply_val(ctx.ep_cap, new_pos);
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else if ctx.child_fds[fd] == 15 {
        let file_size = *ctx.dir_len as i64;
        let cur_pos = *ctx.dir_pos as i64;
        let new_pos = match whence {
            0 => offset_val,
            1 => cur_pos + offset_val,
            2 => file_size + offset_val,
            _ => { reply_val(ctx.ep_cap, -EINVAL); return; }
        };
        if new_pos < 0 {
            reply_val(ctx.ep_cap, -EINVAL);
        } else {
            *ctx.dir_pos = new_pos as usize;
            reply_val(ctx.ep_cap, new_pos);
        }
    } else {
        reply_val(ctx.ep_cap, -ESPIPE);
    }
}

/// SYS_PREAD64 (17): pread at offset.
pub(crate) fn sys_pread64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf_ptr = msg.regs[1];
    let count = msg.regs[2] as usize;
    let off = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 12 {
        super::fs_initrd::pread64_initrd(ctx, fd, buf_ptr, count, off);
    } else if ctx.child_fds[fd] == 13 {
        let mut found = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let safe_count = count.min(4096);
                let mut local_buf = [0u8; 4096];
                let dst = &mut local_buf[..safe_count];
                vfs_lock();
                let result = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(oid, off as usize, dst).ok());
                vfs_unlock();
                match result {
                    Some(n) => {
                        ctx.guest_write(buf_ptr, &local_buf[..n]);
                        reply_val(ctx.ep_cap, n as i64);
                    }
                    None => reply_val(ctx.ep_cap, -EIO),
                }
                found = true;
                break;
            }
        }
        if !found { reply_val(ctx.ep_cap, -EBADF); }
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// SYS_OPEN (2): open file by path.
pub(crate) fn sys_open(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let flags = msg.regs[1] as u32;
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    if ctx.pid >= 3 {
        print(b"OPEN P"); print_u64(ctx.pid as u64);
        print(b" fl="); print_u64(flags as u64);
        print(b" ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]\n");
    }
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    // Synthetic directory open: /dev/dri/, /dev/input/
    if name == b"/dev/dri" || name == b"/dev/dri/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD01;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    if name == b"/dev/input" || name == b"/dev/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD02;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    let kind = if name == b"/dev/null" { 8u8 }
        else if name == b"/dev/zero" { 9u8 }
        else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
        else if name == b"/dev/dri/card0" { 30u8 }
        else if name == b"/dev/input/event0" { 31u8 }
        else if name == b"/dev/input/event1" { 32u8 }
        else { 0u8 };

    if kind != 0 {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = kind;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if false && crate::xkb::xkb_initrd_name(name).is_some() {
        // XKB files: DISABLED — served via VFS (kind=13) instead of dir_buf (kind=15)
        // VFS supports arbitrary file sizes and per-fd tracking
        unreachable!();
    } else if name == b"/sys/class" || name == b"/sys/class/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD05;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/drm" || name == b"/sys/class/drm/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD03;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/input" || name == b"/sys/class/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD04;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if starts_with(name, b"/etc/") || starts_with(name, b"/proc/")
           || starts_with(name, b"/sys/")
           || starts_with(name, b"/usr/share/")
           || starts_with(name, b"/run/udev/") {
        let virt_len = open_virtual_file(name, ctx.dir_buf);
        if let Some(gen_len) = virt_len {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        } else {
            vfs_lock();
            let vfs_found = unsafe { shared_store() }.and_then(|store| {
                use sotos_objstore::ROOT_OID;
                if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                    let entry = store.stat(oid)?;
                    Some((oid, entry.size, entry.is_dir()))
                } else { None }
            });
            vfs_unlock();
            if let Some((oid, size, is_dir)) = vfs_found {
                let mut vslot = None;
                for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                let mut fd = None;
                for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                if let (Some(vs), Some(f)) = (vslot, fd) {
                    ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                    ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                    ctx.fd_flags[f] = flags;
                    reply_val(ctx.ep_cap, f as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            } else {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    } else if name == b"/proc" {
        use sotos_common::linux_abi::{DT_REG, DT_DIR};
        let mut fd_slot = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd_slot = Some(i); break; } }
        let mut vs = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vs = Some(s); break; } }
        if let (Some(f), Some(s)) = (fd_slot, vs) {
            ctx.child_fds[f] = 14;
            ctx.vfs_files[s] = [1, 0, 0xDEAD, f as u64];
            *ctx.dir_len = 0;
            *ctx.dir_pos = 0;
            let entries: &[(&[u8], u8)] = &[
                (b".", DT_DIR), (b"..", DT_DIR),
                (b"stat", DT_REG), (b"meminfo", DT_REG), (b"cpuinfo", DT_REG),
                (b"uptime", DT_REG), (b"loadavg", DT_REG), (b"version", DT_REG),
                (b"self", DT_DIR),
            ];
            for (ename, dtype) in entries {
                let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                if *ctx.dir_len + reclen > ctx.dir_buf.len() { break; }
                let d = &mut ctx.dir_buf[*ctx.dir_len..*ctx.dir_len + reclen];
                for b in d.iter_mut() { *b = 0; }
                d[0..8].copy_from_slice(&1u64.to_le_bytes());
                d[8..16].copy_from_slice(&((*ctx.dir_len + reclen) as u64).to_le_bytes());
                d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                d[18] = *dtype;
                let n = ename.len().min(reclen - 19);
                d[19..19+n].copy_from_slice(&ename[..n]);
                *ctx.dir_len += reclen;
            }
            for i in 0..crate::process::MAX_PROCS {
                if crate::process::PROCESSES[i].state.load(core::sync::atomic::Ordering::Acquire) == 1 {
                    let pid = i + 1;
                    let mut nbuf = [0u8; 8];
                    let nlen = crate::child_handler::fmt_u64(pid as u64, &mut nbuf);
                    let ename = &nbuf[..nlen];
                    let reclen = ((19 + nlen + 1 + 7) / 8) * 8;
                    if *ctx.dir_len + reclen > ctx.dir_buf.len() { break; }
                    let d = &mut ctx.dir_buf[*ctx.dir_len..*ctx.dir_len + reclen];
                    for b in d.iter_mut() { *b = 0; }
                    d[0..8].copy_from_slice(&(pid as u64 + 100).to_le_bytes());
                    d[8..16].copy_from_slice(&((*ctx.dir_len + reclen) as u64).to_le_bytes());
                    d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                    d[18] = DT_DIR;
                    d[19..19+nlen].copy_from_slice(ename);
                    *ctx.dir_len += reclen;
                }
            }
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if name == b"/" || name == b"/bin" || name == b"/lib"
           || name == b"/lib64" || name == b"/sbin" || name == b"/tmp"
           || name == b"/usr" || name == b"/etc"
           || name == b"." {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        let mut vslot = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
        if let (Some(f), Some(vs)) = (fd, vslot) {
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
            ctx.child_fds[f] = 14;
            ctx.vfs_files[vs] = [dir_oid, 0, 0, f as u64];
            dir_store_path(ctx, f, name);
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        // Priority: VFS first, then initrd, then VFS O_CREAT.
        vfs_lock();
        let vfs_existing = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                let entry = store.stat(oid)?;
                if flags & O_TRUNC != 0 && !entry.is_dir() {
                    store.write_obj(oid, &[]).ok();
                    return Some((oid, 0u64, entry.is_dir()));
                }
                return Some((oid, entry.size, entry.is_dir()));
            }
            None
        });
        vfs_unlock();

        if let Some((oid, size, is_dir)) = vfs_existing {
            let mut vslot = None;
            for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let (Some(vs), Some(f)) = (vslot, fd) {
                ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                ctx.fd_flags[f] = flags;
                if is_dir { dir_store_path(ctx, f, name); }
                if path_len >= 8 && &name[path_len-8..path_len] == b"ntdll.so" && ctx.pid < 16 {
                    unsafe { (*crate::syscalls::mm::NTDLL_SO_FD.get())[ctx.pid] = f as u8; }
                    print(b"NTDLL-FD P"); crate::framebuffer::print_u64(ctx.pid as u64);
                    print(b" fd="); crate::framebuffer::print_u64(f as u64);
                    print(b"\n");
                }
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
            return;
        }

        // Step 2: Try initrd (skip for GLIBC processes on library paths —
        // prevents glibc ld.so from loading musl libc from initrd, which
        // causes a fatal dual-libc assertion crash)
        let skip_initrd = get_personality(ctx.pid) == PERS_GLIBC
            && (starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/"));
        let mut basename_start = 0usize;
        for idx in 0..path_len {
            if name[idx] == b'/' { basename_start = idx + 1; }
        }
        let basename = &name[basename_start..];
        let mut opened_initrd = false;

        if !skip_initrd && !basename.is_empty() {
            let mut slot = None;
            for s in 0..GRP_MAX_INITRD {
                if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
            }
            if let Some(slot) = slot {
                let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                // Query file size first (pass buf=0, len=0)
                let file_sz = sys::initrd_read(
                    basename.as_ptr() as u64, basename.len() as u64, 0, 0
                ).unwrap_or(0);
                let buf_pages = if file_sz > 0 {
                    ((file_sz + 0xFFF) / 0x1000).min(0xC000000 / 0x1000) // cap at 192 MiB
                } else { 576 }; // default 2.25 MiB
                let mut buf_ok = true;
                for p in 0..buf_pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            buf_ok = false; break;
                        }
                    } else { buf_ok = false; break; }
                }
                if buf_ok {
                    match sys::initrd_read(
                        basename.as_ptr() as u64,
                        basename.len() as u64,
                        file_buf,
                        buf_pages * 0x1000,
                    ) {
                        Ok(sz) => {
                            let mut fd = None;
                            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                            if let Some(f) = fd {
                                ctx.child_fds[f] = 12;
                                ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                reply_val(ctx.ep_cap, f as i64);
                                opened_initrd = true;
                            } else {
                                for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                reply_val(ctx.ep_cap, -EMFILE);
                                opened_initrd = true;
                            }
                        }
                        Err(_) => {
                            for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                        }
                    }
                }
            }
        }

        // Step 3: VFS O_CREAT
        if !opened_initrd {
            if flags & O_CREAT != 0 {
                vfs_lock();
                let vfs_result = unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    let mut last_slash = None;
                    for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
                    let (parent, fname) = match last_slash {
                        Some(pos) => {
                            let p = if pos == 0 { ROOT_OID } else {
                                store.resolve_path(&name[..pos], ROOT_OID).ok()?
                            };
                            (p, &name[pos+1..path_len])
                        }
                        None => (ROOT_OID, name),
                    };
                    let oid = store.create_in(fname, &[], parent).ok()?;
                    Some((oid, 0u64, false))
                });
                vfs_unlock();
                if let Some((oid, size, is_dir)) = vfs_result {
                    let mut vslot = None;
                    for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                    let mut fd = None;
                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                    if let (Some(vs), Some(f)) = (vslot, fd) {
                        ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                        ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                        ctx.fd_flags[f] = flags;
                        reply_val(ctx.ep_cap, f as i64);
                    } else {
                        reply_val(ctx.ep_cap, -EMFILE);
                    }
                } else {
                    reply_val(ctx.ep_cap, -ENOENT);
                }
            } else {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    }
}

/// SYS_OPENAT (257): open file relative to directory fd.
pub(crate) fn sys_openat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let flags = msg.regs[2] as u32;
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    if ctx.pid == 6 {
        print(b"OPENAT P"); print_u64(ctx.pid as u64);
        print(b" fl=0x"); crate::framebuffer::print_hex64(flags as u64);
        print(b" ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]\n");
    }
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    // Resolve symlinks (Wine dosdevices compat)
    let (path, path_len) = {
        let mut resolved = [0u8; 256];
        let rlen = crate::fd::symlink_resolve(&path[..path_len], &mut resolved);
        let mut out = [0u8; 128];
        let n = rlen.min(127);
        out[..n].copy_from_slice(&resolved[..n]);
        (out, n)
    };
    let name = &path[..path_len];

    // Synthetic directory open: /dev/dri/, /dev/input/
    if name == b"/dev/dri" || name == b"/dev/dri/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD01;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    if name == b"/dev/input" || name == b"/dev/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD02;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    }
    let kind = if name == b"/dev/null" { 8u8 }
        else if name == b"/dev/zero" { 9u8 }
        else if name == b"/dev/urandom" || name == b"/dev/random" { 20u8 }
        else if name == b"/dev/dri/card0" { 30u8 }
        else if name == b"/dev/input/event0" { 31u8 }
        else if name == b"/dev/input/event1" { 32u8 }
        else { 0u8 };

    if kind != 0 {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = kind;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else if false && crate::xkb::xkb_initrd_name(name).is_some() {
        // XKB files: DISABLED — served via VFS (kind=13) instead of dir_buf (kind=15)
        // VFS supports arbitrary file sizes and per-fd tracking
        unreachable!();
    } else if name == b"/sys/class" || name == b"/sys/class/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD05;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/drm" || name == b"/sys/class/drm/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD03;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if name == b"/sys/class/input" || name == b"/sys/class/input/" {
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let Some(f) = fd {
            ctx.child_fds[f] = 15;
            *ctx.dir_len = 0xDD04;
            *ctx.dir_pos = 0;
            reply_val(ctx.ep_cap, f as i64);
        } else { reply_val(ctx.ep_cap, -EMFILE); }
        return;
    } else if starts_with(name, b"/etc/") || starts_with(name, b"/proc/")
           || starts_with(name, b"/sys/")
           || starts_with(name, b"/usr/share/")
           || starts_with(name, b"/run/udev/") {
        let virt_len = open_virtual_file(name, ctx.dir_buf);
        if let Some(gen_len) = virt_len {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        } else {
            vfs_lock();
            let vfs_found = unsafe { shared_store() }.and_then(|store| {
                use sotos_objstore::ROOT_OID;
                if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
                    let entry = store.stat(oid)?;
                    Some((oid, entry.size, entry.is_dir()))
                } else { None }
            });
            vfs_unlock();
            if let Some((oid, size, is_dir)) = vfs_found {
                let mut vslot = None;
                for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
                let mut fslot = None;
                for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fslot = Some(i); break; } }
                if let (Some(vs), Some(f)) = (vslot, fslot) {
                    ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                    ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                    ctx.fd_flags[f] = flags;
                    reply_val(ctx.ep_cap, f as i64);
                } else {
                    reply_val(ctx.ep_cap, -EMFILE);
                }
            } else {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
        let mut gen_len: usize = 0;
        let mut handled = true;
        if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
            gen_len = crate::syscalls::mm::format_proc_maps(ctx.memg, ctx.dir_buf);
        } else if name == b"/proc/self/status" {
            gen_len = format_proc_status(ctx.dir_buf, ctx.pid);
        } else if name == b"/proc/self/stat" {
            gen_len = format_proc_self_stat(ctx.dir_buf, ctx.pid);
        } else if name == b"/proc/cpuinfo" {
            let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/meminfo" {
            let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/uptime" {
            let tsc = rdtsc();
            let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
            let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 } + UPTIME_OFFSET_SECS;
            gen_len = format_uptime_into(ctx.dir_buf, secs);
        } else if name == b"/proc/version" {
            let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/loadavg" {
            let info = b"0.01 0.05 0.10 1/32 42\n";
            let n = info.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/self/auxv" || name == b"/proc/self/environ" {
            // Empty content
        } else if starts_with(name, b"/proc/syslog/") {
            let rest = &path[13..path_len];
            let (max_n, _) = parse_u64_from(rest);
            let max_entries = if max_n == 0 { 10 } else { max_n as usize };
            gen_len = format_syslog_into(ctx.dir_buf, max_entries);
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
            let msg_text = if enable { b"packet mirroring: ON\n" as &[u8] } else { b"packet mirroring: OFF\n" };
            let n = msg_text.len().min(ctx.dir_buf.len());
            ctx.dir_buf[..n].copy_from_slice(&msg_text[..n]);
            gen_len = n;
        } else if starts_with(name, b"/proc/") {
            let rest = &path[6..path_len];
            let (n, consumed) = parse_u64_from(rest);
            if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64
                && PROCESSES[n as usize - 1].state.load(Ordering::Acquire) != 0
            {
                let after = &rest[consumed..];
                if after == b"/status" || after.is_empty() {
                    gen_len = format_proc_status(ctx.dir_buf, n as usize);
                } else {
                    handled = false;
                }
            } else {
                handled = false;
            }
        } else if starts_with(name, b"/sys/") {
            if name == b"/sys/devices/system/cpu/online" {
                let info = b"0-0\n";
                ctx.dir_buf[..info.len()].copy_from_slice(info);
                gen_len = info.len();
            } else if name == b"/sys/devices/system/cpu/possible" {
                let info = b"0-0\n";
                ctx.dir_buf[..info.len()].copy_from_slice(info);
                gen_len = info.len();
            } else if starts_with(name, b"/sys/devices/system/cpu/cpu0/") {
                gen_len = 0;
            } else {
                handled = false;
            }
        }

        if !handled {
            reply_val(ctx.ep_cap, -ENOENT);
        } else {
            *ctx.dir_len = gen_len;
            *ctx.dir_pos = 0;
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let Some(f) = fd {
                ctx.child_fds[f] = 15;
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
        }
    } else {
        if starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/") || ctx.pid >= 9 {
            print(b"OA P"); crate::framebuffer::print_u64(ctx.pid as u64);
            print(b" ["); for &b in name { sys::debug_print(b); } print(b"]\n");
        }
        let is_lib_path = starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/");
        let oflags = OFlags::from_bits_truncate(flags as u32);
        let has_creat = oflags.contains(OFlags::CREAT);
        let has_trunc = oflags.contains(OFlags::TRUNC);
        let has_dir = oflags.contains(OFlags::DIRECTORY);

        // Step 1: Try VFS resolve
        vfs_lock();
        let vfs_existing = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            match store.resolve_path(name, ROOT_OID) {
                Ok(oid) => {
                    let entry = store.stat(oid)?;
                    if has_dir && !entry.is_dir() {
                        return None;
                    }
                    if has_trunc && !entry.is_dir() {
                        store.write_obj(oid, &[]).ok();
                        Some((oid, 0u64, entry.is_dir()))
                    } else {
                        Some((oid, entry.size, entry.is_dir()))
                    }
                }
                Err(_) => None,
            }
        });
        vfs_unlock();

        if let Some((oid, size, is_dir)) = vfs_existing {
            let mut vslot = None;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; }
            }
            let mut fd = None;
            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
            if let (Some(vs), Some(f)) = (vslot, fd) {
                ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                ctx.fd_flags[f] = flags;
                if is_dir { dir_store_path(ctx, f, name); }
                if path_len >= 8 && &name[path_len-8..path_len] == b"ntdll.so" && ctx.pid < 16 {
                    unsafe { (*crate::syscalls::mm::NTDLL_SO_FD.get())[ctx.pid] = f as u8; }
                    print(b"NTDLL-FD P"); crate::framebuffer::print_u64(ctx.pid as u64);
                    print(b" fd="); crate::framebuffer::print_u64(f as u64);
                    print(b"\n");
                }
                reply_val(ctx.ep_cap, f as i64);
            } else {
                reply_val(ctx.ep_cap, -EMFILE);
            }
            return;
        }

        // Step 2: Try initrd (skip for GLIBC processes on library paths —
        // prevents glibc ld.so from loading musl libc from initrd, which
        // causes a fatal dual-libc assertion crash)
        let skip_initrd = get_personality(ctx.pid) == PERS_GLIBC
            && (starts_with(name, b"/lib/") || starts_with(name, b"/usr/lib/"));
        let mut basename_start = 0usize;
        for idx in 0..path_len {
            if name[idx] == b'/' { basename_start = idx + 1; }
        }
        let basename = &name[basename_start..];
        let mut opened_initrd = false;

        if !skip_initrd && !basename.is_empty() {
            let mut slot = None;
            for s in 0..GRP_MAX_INITRD {
                if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
            }
            if let Some(slot) = slot {
                let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                // Query file size first, allocate exact pages needed
                let file_sz = sys::initrd_read(
                    basename.as_ptr() as u64, basename.len() as u64, 0, 0
                ).unwrap_or(0);
                let buf_pages = if file_sz > 0 {
                    ((file_sz + 0xFFF) / 0x1000).min(0x3000000 / 0x1000)
                } else { 576 };
                let mut buf_ok = true;
                for p in 0..buf_pages {
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
                        buf_pages * 0x1000,
                    ) {
                        let mut fd = None;
                        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            ctx.child_fds[f] = 12;
                            ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                            if path_len >= 8 && &name[path_len-8..path_len] == b"ntdll.so" && ctx.pid < 16 {
                                unsafe { (*crate::syscalls::mm::NTDLL_SO_FD.get())[ctx.pid] = f as u8; }
                                print(b"NTDLL-FD P"); crate::framebuffer::print_u64(ctx.pid as u64);
                                print(b" fd="); crate::framebuffer::print_u64(f as u64);
                                print(b"\n");
                            }
                            reply_val(ctx.ep_cap, f as i64);
                            opened_initrd = true;
                        } else {
                            for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                            reply_val(ctx.ep_cap, -EMFILE);
                            opened_initrd = true;
                        }
                    } else {
                        for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                    }
                }
            }
        }

        // Step 3: VFS with O_CREAT
        if !opened_initrd {
            vfs_lock();
            let vfs_result = if has_creat {
                unsafe { shared_store() }.and_then(|store| {
                    use sotos_objstore::ROOT_OID;
                    match store.resolve_path(name, ROOT_OID) {
                        Ok(oid) => {
                            let entry = store.stat(oid)?;
                            if has_trunc && !entry.is_dir() {
                                store.write_obj(oid, &[]).ok();
                                Some((oid, 0u64, false))
                            } else {
                                Some((oid, entry.size, entry.is_dir()))
                            }
                        }
                        Err(_) => {
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
                    }
                })
            } else {
                None
            };
            vfs_unlock();

            if ctx.pid > 1 && has_creat && vfs_result.is_none() {
                print(b"CREAT-FAIL: ");
                print(name);
                print(b"\n");
            }

            match vfs_result {
                Some((oid, size, is_dir)) => {
                    let mut vslot = None;
                    for s in 0..GRP_MAX_VFS {
                        if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; }
                    }
                    let mut fd = None;
                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                    if let (Some(vs), Some(f)) = (vslot, fd) {
                        ctx.child_fds[f] = if is_dir { 14 } else { 13 };
                        ctx.vfs_files[vs] = [oid, size, 0, f as u64];
                        ctx.fd_flags[f] = flags;
                        if ctx.pid >= 5 {
                            print(b"OPENAT-OK P"); print_u64(ctx.pid as u64);
                            print(b" fd="); print_u64(f as u64);
                            print(b" oid=0x"); crate::framebuffer::print_hex64(oid);
                            print(b" vs="); print_u64(vs as u64);
                            print(b" fl=0x"); crate::framebuffer::print_hex64(flags as u64);
                            print(b"\n");
                        }
                        reply_val(ctx.ep_cap, f as i64);
                    } else {
                        if ctx.pid >= 5 {
                            print(b"OPENAT-EMFILE P"); print_u64(ctx.pid as u64);
                            let mut used = 0u64;
                            for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] != 0 { used += 1; } }
                            print(b" vfs_used="); print_u64(used);
                            let mut fd_used = 0u64;
                            for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] != 0 { fd_used += 1; } }
                            print(b" fd_used="); print_u64(fd_used);
                            print(b"\n");
                        }
                        reply_val(ctx.ep_cap, -EMFILE);
                    }
                }
                None => {
                    let mut found_initrd = false;
                    if !basename.is_empty() {
                        let mut slot = None;
                        for s in 0..GRP_MAX_INITRD {
                            if ctx.initrd_files[s][0] == 0 { slot = Some(s); break; }
                        }
                        if let Some(slot) = slot {
                            let file_buf = ctx.initrd_file_buf_base + (slot as u64) * 0xC000000;
                            let file_sz = sys::initrd_read(
                                basename.as_ptr() as u64, basename.len() as u64, 0, 0
                            ).unwrap_or(0);
                            let buf_pages = if file_sz > 0 {
                                ((file_sz + 0xFFF) / 0x1000).min(0x3000000 / 0x1000)
                            } else { 576 };
                            let mut buf_ok = true;
                            for p in 0..buf_pages {
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
                                    buf_pages * 0x1000,
                                ) {
                                    let mut fd = None;
                                    for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
                                    if let Some(f) = fd {
                                        ctx.child_fds[f] = 12;
                                        ctx.initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                        reply_val(ctx.ep_cap, f as i64);
                                        found_initrd = true;
                                    } else {
                                        for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                        reply_val(ctx.ep_cap, -EMFILE);
                                        found_initrd = true;
                                    }
                                } else {
                                    for p in 0..buf_pages { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                                }
                            }
                        }
                    }
                    if !found_initrd {
                        reply_val(ctx.ep_cap, -ENOENT);
                    }
                }
            }
        }
    }
}

/// SYS_FSTATAT (262): stat relative to dirfd.
pub(crate) fn sys_fstatat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let dirfd = msg.regs[0] as i64;
    let path_ptr = msg.regs[1];
    let stat_ptr = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    if ctx.pid == 2 && starts_with(&path[..path_len], b"/usr/share/X11") {
        print(b"FSTATAT-XKB P2 ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]\n");
    }
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    if (flags & AT_EMPTY_PATH) != 0 && path_len == 0 {
        let fd = dirfd as usize;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            if ctx.child_fds[fd] == 12 {
                let mut size = 0u64;
                let mut ino = 0u64;
                for s in 0..GRP_MAX_INITRD {
                    if ctx.initrd_files[s][3] == fd as u64 && ctx.initrd_files[s][0] != 0 {
                        size = ctx.initrd_files[s][1];
                        ino = ctx.initrd_files[s][0];
                        break;
                    }
                }
                let buf = build_linux_stat_dev(1, ino, size, false);
                ctx.guest_write(stat_ptr, &buf);
            } else if ctx.child_fds[fd] == 13 || ctx.child_fds[fd] == 14 {
                let is_vfs_dir = ctx.child_fds[fd] == 14;
                let mut size = 0u64;
                let mut oid = 0u64;
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                        oid = ctx.vfs_files[s][0];
                        size = ctx.vfs_files[s][1];
                        break;
                    }
                }
                let buf = build_linux_stat_dev(2, oid, size, is_vfs_dir);
                ctx.guest_write(stat_ptr, &buf);
            } else if ctx.child_fds[fd] == 30 {
                // DRM device: S_IFCHR with major 226
                crate::drm::drm_fstat(ctx, stat_ptr);
            } else {
                let buf = build_linux_stat(fd as u64, 0, false);
                ctx.guest_write(stat_ptr, &buf);
            }
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -EBADF);
        }
        return;
    }

    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            let buf = build_linux_stat(0, sz, false);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }
    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((entry.oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();
    if let Some((oid, size, is_dir)) = vfs_stat {
        let buf = build_linux_stat_dev(2, oid, size, is_dir);
        ctx.guest_write(stat_ptr, &buf);
        reply_val(ctx.ep_cap, 0);
    } else {
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/share/terminfo"
            || name == b"/usr/share/terminfo/x"
            || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
            || starts_with(name, b"/usr/share/X11/xkb/")
            || name == b"/usr/libexec"
            || name == b"/usr/libexec/git-core"
            || name == b"/usr/local" || name == b"/usr/local/bin"
            || starts_with(name, b"/dev/")
            || crate::udev::is_sys_drm_dir(name);
        // DRM and evdev device files should be reported as character devices, not dirs.
        let is_dev_char = name == b"/dev/dri/card0"
            || name == b"/dev/input/event0"
            || name == b"/dev/input/event1";
        if is_dev_char {
            crate::drm::drm_fstat(ctx, stat_ptr);
            reply_val(ctx.ep_cap, 0);
        } else if is_known_dir {
            let buf = build_linux_stat(0, 4096, true);
            ctx.guest_write(stat_ptr, &buf);
            reply_val(ctx.ep_cap, 0);
        } else {
            let mut found_sock = false;
            for i in 0..crate::fd::MAX_UNIX_LISTENERS {
                if crate::fd::UNIX_LISTEN_ACTIVE[i].load(Ordering::Acquire) != 0 {
                    let lpath = unsafe { &crate::fd::UNIX_LISTEN_PATH[i] };
                    let llen = lpath.iter().position(|&b| b == 0).unwrap_or(128);
                    if llen == path_len && &lpath[..llen] == name {
                        let mut st = sotos_common::linux_abi::Stat::zeroed();
                        st.st_ino = 0xA000 + i as u64;
                        st.st_nlink = 1;
                        st.st_mode = 0o140755;
                        let buf: [u8; 144] = unsafe { core::mem::transmute(st) };
                        ctx.guest_write(stat_ptr, &buf);
                        reply_val(ctx.ep_cap, 0);
                        found_sock = true;
                        break;
                    }
                }
            }
            if !found_sock {
                reply_val(ctx.ep_cap, -ENOENT);
            }
        }
    }
}

/// Helper: get /proc/self/exe path.
pub(crate) fn proc_self_exe(pid: usize) -> [u8; 32] {
    let mut buf = [0u8; 32];
    if pid > 0 && pid <= MAX_PROCS {
        let w0 = PROCESSES[pid - 1].exe_path[0].load(Ordering::Acquire);
        let w1 = PROCESSES[pid - 1].exe_path[1].load(Ordering::Acquire);
        let w2 = PROCESSES[pid - 1].exe_path[2].load(Ordering::Acquire);
        let w3 = PROCESSES[pid - 1].exe_path[3].load(Ordering::Acquire);
        if w0 != 0 {
            buf[0..8].copy_from_slice(&w0.to_le_bytes());
            buf[8..16].copy_from_slice(&w1.to_le_bytes());
            buf[16..24].copy_from_slice(&w2.to_le_bytes());
            buf[24..32].copy_from_slice(&w3.to_le_bytes());
            return buf;
        }
    }
    buf[..12].copy_from_slice(b"/bin/program");
    buf
}

/// SYS_READLINKAT (267): read symbolic link.
pub(crate) fn sys_readlinkat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let out_buf = msg.regs[2];
    let bufsiz = msg.regs[3] as usize;
    let mut rpath = [0u8; 64];
    let rpath_len = ctx.guest_copy_path(path_ptr, &mut rpath);
    let rname = &rpath[..rpath_len];
    if rpath_len >= 14 && &rpath[..14] == b"/proc/self/exe" {
        let exe = proc_self_exe(ctx.pid);
        let elen = exe.iter().position(|&b| b == 0).unwrap_or(exe.len());
        let n = elen.min(bufsiz);
        ctx.guest_write(out_buf, &exe[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else if let Some(target) = crate::udev::sys_drm_readlink(rname) {
        let n = target.len().min(bufsiz);
        ctx.guest_write(out_buf, &target[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else {
        // Check symlink table (Wine dosdevices compat)
        let mut abs = [0u8; 256];
        let alen = if rpath_len > 0 && rpath[0] != b'/' {
            crate::fd::resolve_with_cwd(ctx.cwd, rname, &mut abs)
        } else {
            let n = rpath_len.min(255);
            abs[..n].copy_from_slice(&rpath[..n]);
            n
        };
        let mut found = false;
        unsafe {
            for i in 0..crate::fd::SYMLINK_COUNT.min(16) {
                let sp = &crate::fd::SYMLINK_PATH[i];
                let slen = sp.iter().position(|&b| b == 0).unwrap_or(128);
                if slen > 0 && alen == slen && abs[..alen] == sp[..slen] {
                    let tgt = &crate::fd::SYMLINK_TARGET[i];
                    let tlen = tgt.iter().position(|&b| b == 0).unwrap_or(128);
                    let n = tlen.min(bufsiz);
                    ctx.guest_write(out_buf, &tgt[..n]);
                    reply_val(ctx.ep_cap, n as i64);
                    found = true;
                    break;
                }
            }
        }
        if !found { reply_val(ctx.ep_cap, -EINVAL); }
    }
}

/// SYS_READLINK (89).
pub(crate) fn sys_readlink(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let buf = msg.regs[1];
    let bufsiz = msg.regs[2] as usize;
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let name = &path[..plen];
    if name == b"/proc/self/exe" {
        let target = proc_self_exe(ctx.pid);
        let tlen = target.iter().position(|&b| b == 0).unwrap_or(target.len());
        let n = tlen.min(bufsiz);
        ctx.guest_write(buf, &target[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else if let Some(target) = crate::udev::sys_drm_readlink(name) {
        let n = target.len().min(bufsiz);
        ctx.guest_write(buf, &target[..n]);
        reply_val(ctx.ep_cap, n as i64);
    } else { reply_val(ctx.ep_cap, -EINVAL); }
}

/// SYS_ACCESS (21) / SYS_FACCESSAT (269).
pub(crate) fn sys_access(ctx: &mut SyscallContext, msg: &IpcMsg, syscall_nr: u64) {
    let path_ptr = if syscall_nr == SYS_FACCESSAT { msg.regs[1] } else { msg.regs[0] };
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];
    let is_dir = name == b"." || name == b".."
        || name == b"/" || name == b"/usr" || name == b"/etc"
        || name == b"/lib" || name == b"/lib64"
        || name == b"/bin" || name == b"/sbin"
        || name == b"/tmp" || name == b"/home" || name == b"/var"
        || name == b"/proc" || name == b"/sys" || name == b"/dev"
        || name == b"/usr/bin" || name == b"/usr/lib"
        || name == b"/usr/sbin" || name == b"/usr/lib64"
        || name == b"/usr/share" || name == b"/usr/share/terminfo"
        || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
        || starts_with(name, b"/usr/share/X11/xkb/");
    let is_virtual = name == b"/etc/passwd" || name == b"/etc/group"
        || name == b"/etc/resolv.conf" || name == b"/etc/hostname"
        || name == b"/etc/nsswitch.conf"
        || name == b"/dev/null" || name == b"/dev/zero"
        || name == b"/dev/urandom" || name == b"/dev/random"
        || name == b"/dev/dri/card0"
        || name == b"/dev/input/event0" || name == b"/dev/input/event1";
    let is_dir = is_dir
        || name == b"/dev/dri" || name == b"/dev/input";
    if is_dir || is_virtual {
        reply_val(ctx.ep_cap, 0);
    } else {
        let mut basename_start = 0usize;
        for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
        let basename = &name[basename_start..];
        if !basename.is_empty() {
            match sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                Ok(_) => reply_val(ctx.ep_cap, 0),
                Err(_) => {
                    vfs_lock();
                    let found = unsafe { shared_store() }.and_then(|store| {
                        store.resolve_path(name, sotos_objstore::ROOT_OID).ok()
                    }).is_some();
                    vfs_unlock();
                    if ctx.pid > 1 && name.windows(6).any(|w| w == b"config") {
                        print(if found { b"ACCESS-OK: " } else { b"ACCESS-MISS: " });
                        print(name);
                        print(b"\n");
                    }
                    reply_val(ctx.ep_cap, if found { 0 } else { -ENOENT });
                }
            }
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_FSYNC (74) / SYS_FDATASYNC (75).
pub(crate) fn sys_fsync(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_FTRUNCATE (77).
pub(crate) fn sys_ftruncate(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let length = msg.regs[1] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        let mut done = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                ctx.vfs_files[s][1] = length as u64;
                done = true;
                break;
            }
        }
        reply_val(ctx.ep_cap, if done { 0 } else { -9 });
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// SYS_RENAME (82).
pub(crate) fn sys_rename(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old_ptr = msg.regs[0];
    let new_ptr = msg.regs[1];
    let mut old_path = [0u8; 128];
    let mut new_path = [0u8; 128];
    let old_len = ctx.guest_copy_path(old_ptr, &mut old_path);
    let new_len = ctx.guest_copy_path(new_ptr, &mut new_path);
    let (old_path, old_len) = if old_len > 0 && old_path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &old_path[..old_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (old_path, old_len) };
    let (new_path, new_len) = if new_len > 0 && new_path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &new_path[..new_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (new_path, new_len) };
    let old_name = &old_path[..old_len];
    let new_name = &new_path[..new_len];

    if ctx.pid >= 3 {
        print(b"RENAME P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in old_name { sys::debug_print(b); }
        print(b"] -> ["); for &b in new_name { sys::debug_print(b); }
        print(b"]\n");
    }

    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let old_oid = match store.resolve_path(old_name, ROOT_OID) {
            Ok(oid) => oid,
            Err(_) => {
                if ctx.pid >= 3 { print(b"RENAME-FAIL: old path not found\n"); }
                return None;
            }
        };
        let mut last_slash = None;
        for (i, &b) in new_name.iter().enumerate() {
            if b == b'/' { last_slash = Some(i); }
        }
        let (new_parent, new_basename) = match last_slash {
            Some(pos) => {
                let pp = &new_name[..pos];
                let p = if pp.is_empty() { ROOT_OID }
                    else {
                        match store.resolve_path(pp, ROOT_OID) {
                            Ok(p) => p,
                            Err(_) => {
                                if ctx.pid >= 3 {
                                    print(b"RENAME-FAIL: new parent not found [");
                                    for &b in pp { sys::debug_print(b); }
                                    print(b"]\n");
                                }
                                return None;
                            }
                        }
                    };
                (p, &new_name[pos + 1..])
            }
            None => (ROOT_OID, new_name),
        };
        if let Err(e) = store.rename(old_oid, new_basename, new_parent) {
            if ctx.pid >= 3 {
                print(b"RENAME-FAIL: store.rename err=[");
                print(e.as_bytes());
                print(b"]\n");
            }
            return None;
        }
        if let Some(entry) = store.stat(old_oid) {
            if entry.is_dir() {
                print(b"REN-POSTCHECK-DIR: oid=");
                print_u64(old_oid);
                print(b" flags=");
                print_u64(entry.flags as u64);
                print(b" name=[");
                print(entry.name_as_str());
                print(b"]\n");
            }
        }
        if store.resolve_path(old_name, ROOT_OID).is_ok() {
            print(b"REN-OLDNAME-STILL-EXISTS: ");
            print(old_name);
            print(b"\n");
        }
        Some(())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -2 });
}

/// SYS_STATX (332): modern stat call used by musl 1.2.5+.
///
/// struct statx is 256 bytes. Key fields:
///   stx_mask(u32@0), stx_blksize(u32@4), stx_attributes(u64@8),
///   stx_nlink(u32@16), stx_uid(u32@20), stx_gid(u32@24),
///   stx_mode(u16@28), stx_ino(u64@32), stx_size(u64@40),
///   stx_blocks(u64@48), stx_attributes_mask(u64@56)
pub(crate) fn sys_statx(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let dirfd = msg.regs[0] as i64;
    let path_ptr = msg.regs[1];
    let _flags = msg.regs[2] as u32;
    let _mask = msg.regs[3] as u32;
    let buf_ptr = msg.regs[4];

    // AT_EMPTY_PATH: stat the fd itself
    if path_ptr == 0 || (_flags & 0x1000 != 0) { // AT_EMPTY_PATH = 0x1000
        let fd = dirfd as usize;
        if fd < GRP_MAX_FDS && ctx.child_fds[fd] != 0 {
            let kind = ctx.child_fds[fd];
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes()); // stx_mask = STATX_BASIC_STATS
            sx[4..8].copy_from_slice(&4096u32.to_le_bytes()); // stx_blksize
            sx[16..20].copy_from_slice(&1u32.to_le_bytes()); // stx_nlink
            let mode: u16 = if kind == 14 { 0o040755 } else if kind == 30 { 0o020666 } else { 0o100644 };
            sx[28..30].copy_from_slice(&mode.to_le_bytes()); // stx_mode
            sx[32..40].copy_from_slice(&(fd as u64).to_le_bytes()); // stx_ino
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
            return;
        }
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }

    // Path-based stat
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    if ctx.pid == 2 && starts_with(name, b"/usr/share/X11") {
        print(b"STATX P2 ["); for &b in name { sys::debug_print(b); } print(b"]\n");
    }

    // Check initrd by basename
    let mut basename_start = 0usize;
    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
    let basename = &name[basename_start..];
    if !basename.is_empty() {
        if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[4..8].copy_from_slice(&4096u32.to_le_bytes());
            sx[16..20].copy_from_slice(&1u32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o100644u16.to_le_bytes()); // S_IFREG
            sx[40..48].copy_from_slice(&sz.to_le_bytes()); // stx_size
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
            return;
        }
    }

    // VFS
    vfs_lock();
    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        Some((oid, entry.size, entry.is_dir()))
    });
    vfs_unlock();

    if let Some((_oid, size, is_dir)) = vfs_stat {
        let mut sx = [0u8; 256];
        sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
        sx[4..8].copy_from_slice(&4096u32.to_le_bytes());
        sx[16..20].copy_from_slice(&1u32.to_le_bytes());
        let mode: u16 = if is_dir { 0o040755 } else { 0o100644 };
        sx[28..30].copy_from_slice(&mode.to_le_bytes());
        sx[40..48].copy_from_slice(&size.to_le_bytes());
        ctx.guest_write(buf_ptr, &sx);
        reply_val(ctx.ep_cap, 0);
    } else {
        // Known directories
        let is_known_dir = name == b"." || path_len == 0
            || name == b"/" || name == b"/usr" || name == b"/etc"
            || name == b"/lib" || name == b"/lib64"
            || name == b"/bin" || name == b"/sbin"
            || name == b"/tmp" || name == b"/home" || name == b"/var"
            || name == b"/usr/bin" || name == b"/usr/lib"
            || name == b"/usr/sbin" || name == b"/usr/lib64"
            || name == b"/usr/share" || name == b"/usr/share/terminfo"
            || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
            || starts_with(name, b"/usr/share/X11/xkb/")
            || name == b"/usr/libexec"
            || name == b"/proc" || name == b"/sys" || name == b"/dev"
            || name == b"/dev/dri" || name == b"/dev/input"
            || name == b"/run" || name == b"/run/user" || name == b"/run/user/0";
        let is_dev_char = name == b"/dev/dri/card0"
            || name == b"/dev/input/event0" || name == b"/dev/input/event1";
        let is_virtual = name == b"/dev/null" || name == b"/dev/zero"
            || name == b"/dev/urandom" || name == b"/dev/random"
            || starts_with(name, b"/etc/") || starts_with(name, b"/proc/");

        if is_dev_char {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o020666u16.to_le_bytes()); // S_IFCHR
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
        } else if is_known_dir {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[4..8].copy_from_slice(&4096u32.to_le_bytes());
            sx[16..20].copy_from_slice(&1u32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o040755u16.to_le_bytes()); // S_IFDIR
            sx[40..48].copy_from_slice(&4096u64.to_le_bytes());
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
        } else if is_virtual {
            let mut sx = [0u8; 256];
            sx[0..4].copy_from_slice(&0x7FFu32.to_le_bytes());
            sx[28..30].copy_from_slice(&0o100644u16.to_le_bytes());
            ctx.guest_write(buf_ptr, &sx);
            reply_val(ctx.ep_cap, 0);
        } else {
            reply_val(ctx.ep_cap, -ENOENT);
        }
    }
}

/// SYS_STATFS (137) / SYS_FSTATFS (138).
pub(crate) fn sys_statfs(ctx: &mut SyscallContext, msg: &IpcMsg, _syscall_nr: u64) {
    let buf = msg.regs[1];
    if buf != 0 {
        let mut sfs = [0u8; 120];
        sfs[0..8].copy_from_slice(&0xEF53u64.to_le_bytes());
        sfs[8..16].copy_from_slice(&4096u64.to_le_bytes());
        sfs[16..24].copy_from_slice(&(1024u64 * 1024).to_le_bytes());
        sfs[24..32].copy_from_slice(&(512u64 * 1024).to_le_bytes());
        sfs[32..40].copy_from_slice(&(512u64 * 1024).to_le_bytes());
        sfs[40..48].copy_from_slice(&65536u64.to_le_bytes());
        sfs[48..56].copy_from_slice(&32768u64.to_le_bytes());
        sfs[72..80].copy_from_slice(&255u64.to_le_bytes());
        ctx.guest_write(buf, &sfs);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_CREAT (85).
pub(crate) fn sys_creat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let path_len = ctx.guest_copy_path(path_ptr, &mut path);
    if ctx.pid >= 3 {
        print(b"CREAT P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in &path[..path_len] { sys::debug_print(b); } print(b"]\n");
    }
    let (path, path_len) = if path_len > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..path_len], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, path_len)
    };
    let name = &path[..path_len];

    vfs_lock();
    let vfs_result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        if let Ok(oid) = store.resolve_path(name, ROOT_OID) {
            let entry = store.stat(oid)?;
            if !entry.is_dir() { store.write_obj(oid, &[]).ok(); }
            return Some((oid, 0u64, false));
        }
        let mut last_slash = None;
        for (i, &b) in name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, fname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else {
                    store.resolve_path(&name[..pos], ROOT_OID).ok()?
                };
                (p, &name[pos+1..path_len])
            }
            None => (ROOT_OID, name),
        };
        let oid = store.create_in(fname, &[], parent).ok()?;
        Some((oid, 0, false))
    });
    vfs_unlock();

    if let Some((oid, size, is_dir)) = vfs_result {
        let mut vslot = None;
        for s in 0..GRP_MAX_VFS { if ctx.vfs_files[s][0] == 0 { vslot = Some(s); break; } }
        let mut fd = None;
        for i in 3..GRP_MAX_FDS { if ctx.child_fds[i] == 0 { fd = Some(i); break; } }
        if let (Some(vs), Some(f)) = (vslot, fd) {
            ctx.child_fds[f] = if is_dir { 14 } else { 13 };
            ctx.vfs_files[vs] = [oid, size, 0, f as u64];
            ctx.fd_flags[f] = O_WRONLY;
            reply_val(ctx.ep_cap, f as i64);
        } else {
            reply_val(ctx.ep_cap, -EMFILE);
        }
    } else {
        reply_val(ctx.ep_cap, -ENOENT);
    }
}

/// SYS_PWRITE64 (18).
pub(crate) fn sys_pwrite64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let buf = msg.regs[1];
    let count = msg.regs[2] as usize;
    let offset = msg.regs[3] as usize;
    if fd < GRP_MAX_FDS && ctx.child_fds[fd] == 13 {
        let mut done = false;
        let copy_len = count.min(4096);
        let mut local_buf = [0u8; 4096];
        ctx.guest_read(buf, &mut local_buf[..copy_len]);
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let data = &local_buf[..copy_len];
                vfs_lock();
                let ok = unsafe { shared_store() }
                    .and_then(|store| store.write_obj_range(oid, offset, data).ok())
                    .is_some();
                vfs_unlock();
                if ok {
                    let new_end = (offset + data.len()) as u64;
                    if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                    reply_val(ctx.ep_cap, data.len() as i64);
                } else { reply_val(ctx.ep_cap, -EIO); }
                done = true; break;
            }
        }
        if !done { reply_val(ctx.ep_cap, -EBADF); }
    } else { reply_val(ctx.ep_cap, -EBADF); }
}

/// SYS_FADVISE64 (221): stub.
pub(crate) fn sys_fadvise64(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_COPY_FILE_RANGE (326): stub.
pub(crate) fn sys_copy_file_range(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ENOSYS);
}

/// SYS_SENDFILE (40).
pub(crate) fn sys_sendfile(ctx: &mut SyscallContext, msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ENOSYS);
}

/// File metadata stubs.
pub(crate) fn sys_file_metadata_stubs(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_UMASK (95).
pub(crate) fn sys_umask(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0o022);
}

/// SYS_FACCESSAT2 (439).
pub(crate) fn sys_faccessat2(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    let is_dir = name.is_empty() || name == b"." || name == b"/"
        || name == b"/bin" || name == b"/lib" || name == b"/lib64"
        || name == b"/usr" || name == b"/etc" || name == b"/proc"
        || name == b"/tmp" || name == b"/sbin" || name == b"/var"
        || name == b"/home" || name == b"/sys" || name == b"/dev"
        || name == b"/run" || name == b"/run/user" || name == b"/run/user/0"
        || name == b"/usr/bin" || name == b"/usr/lib" || name == b"/usr/lib64"
        || name == b"/usr/sbin" || name == b"/usr/share"
        || name == b"/usr/share/terminfo"
        || name == b"/usr/share/X11" || name == b"/usr/share/X11/xkb"
        || starts_with(name, b"/usr/share/X11/xkb/")
        || name == b"/usr/libexec"
        || name == b"/dev/dri" || name == b"/dev/input"
        || crate::udev::is_sys_drm_dir(name);
    let is_virtual = name == b"/etc/passwd" || name == b"/etc/group"
        || name == b"/etc/resolv.conf" || name == b"/etc/hostname"
        || name == b"/etc/nsswitch.conf"
        || name == b"/dev/null" || name == b"/dev/zero"
        || name == b"/dev/urandom" || name == b"/dev/random"
        || name == b"/dev/dri/card0"
        || name == b"/dev/input/event0" || name == b"/dev/input/event1"
        || starts_with(name, b"/etc/")
        || crate::udev::sys_class_drm_content(name).is_some();
    if is_dir || is_virtual {
        reply_val(ctx.ep_cap, 0);
    } else {
        let mut bstart = 0usize;
        for idx in 0..plen { if name[idx] == b'/' { bstart = idx + 1; } }
        let bname = &name[bstart..];
        let mut found = false;
        if !bname.is_empty() {
            if sys::initrd_read(bname.as_ptr() as u64, bname.len() as u64, 0, 0).is_ok() {
                found = true;
            }
        }
        if !found {
            vfs_lock();
            found = unsafe { shared_store() }
                .and_then(|store| store.resolve_path(name, sotos_objstore::ROOT_OID).ok())
                .is_some();
            vfs_unlock();
        }
        reply_val(ctx.ep_cap, if found { 0 } else { -ENOENT });
    }
}

/// Readv for VFS files (kind=13).
pub(crate) fn readv_vfs(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let mut total: usize = 0;
    let mut found = false;
    for s_idx in 0..GRP_MAX_VFS {
        if ctx.vfs_files[s_idx][3] == fd as u64 && ctx.vfs_files[s_idx][0] != 0 {
            let oid = ctx.vfs_files[s_idx][0];
            let mut pos = ctx.vfs_files[s_idx][2] as usize;
            let cnt = iovcnt.min(16);
            for i in 0..cnt {
                let entry = iov_ptr + (i as u64) * 16;
                if entry + 16 > 0x0000_8000_0000_0000 { break; }
                let base = ctx.guest_read_u64(entry);
                let len = ctx.guest_read_u64(entry + 8) as usize;
                if base == 0 || len == 0 { continue; }
                let safe_len = len.min(4096);
                let mut local_buf = [0u8; 4096];
                let dst = &mut local_buf[..safe_len];
                vfs_lock();
                let n = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(oid, pos, dst).ok())
                    .unwrap_or(0);
                vfs_unlock();
                if n > 0 { ctx.guest_write(base, &local_buf[..n]); }
                pos += n;
                total += n;
                if n < len { break; }
            }
            ctx.vfs_files[s_idx][2] = pos as u64;
            found = true;
            break;
        }
    }
    if found {
        reply_val(ctx.ep_cap, total as i64);
    } else {
        reply_val(ctx.ep_cap, -EBADF);
    }
}

/// Readv for TCP socket (kind=16).
pub(crate) fn readv_tcp(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let mut total = 0usize;
    let mut saw_eof = false;
    let cnt = iovcnt.min(16);
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let mut off = 0usize;
        let mut empty = 0u32;
        while off < ilen && !saw_eof {
            let chunk = (ilen - off).min(64);
            let want = (ilen - off).min(4096) as u64;
            let req = sotos_common::IpcMsg {
                tag: NET_CMD_TCP_RECV,
                regs: [conn_id, chunk as u64, 0, want, 0, 0, 0, 0],
            };
            match sys::call_timeout(net_cap, &req, 200) {
                Ok(resp) => {
                    let n = resp.tag as usize;
                    if n == 0xFFFE { saw_eof = true; break; }
                    if n > 0 && n <= 64 {
                        let src = unsafe {
                            core::slice::from_raw_parts(&resp.regs[0] as *const u64 as *const u8, n)
                        };
                        ctx.guest_write(base + off as u64, src);
                        off += n;
                        total += n;
                        empty = 0;
                        let mut buf_off = n;
                        while off < ilen && buf_off < 4096 {
                            let cr = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_RECV,
                                regs: [conn_id, 64, buf_off as u64, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &cr, 100) {
                                Ok(r) => {
                                    let cn = r.tag as usize;
                                    if cn == 0 || cn == 0xFFFE { break; }
                                    let an = cn.min(64);
                                    let cs = unsafe {
                                        core::slice::from_raw_parts(&r.regs[0] as *const u64 as *const u8, an)
                                    };
                                    ctx.guest_write(base + off as u64, cs);
                                    off += an;
                                    total += an;
                                    buf_off += an;
                                    if an < 64 { break; }
                                }
                                Err(_) => break,
                            }
                        }
                        if n < 64 { break; }
                    } else {
                        if total > 0 || off > 0 { break; }
                        empty += 1;
                        if empty > 5000 { break; }
                        sys::yield_now();
                    }
                }
                Err(_) => {
                    if total > 0 || off > 0 { break; }
                    empty += 1;
                    if empty > 5000 { break; }
                    sys::yield_now();
                }
            }
        }
        if off == 0 && !saw_eof { break; }
    }
    if total > 0 {
        reply_val(ctx.ep_cap, total as i64);
    } else if saw_eof {
        reply_val(ctx.ep_cap, 0);
    } else {
        reply_val(ctx.ep_cap, -EAGAIN);
    }
}

/// Readv for virtual file (kind=15).
pub(crate) fn readv_virtual(ctx: &mut SyscallContext, iov_ptr: u64, iovcnt: usize) {
    let cnt = iovcnt.min(16);
    let mut total = 0usize;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let avail = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
        let to_read = ilen.min(avail);
        if to_read > 0 {
            ctx.guest_write(base, &ctx.dir_buf[*ctx.dir_pos..*ctx.dir_pos + to_read]);
            *ctx.dir_pos += to_read;
            total += to_read;
        }
        if to_read < ilen { break; }
    }
    reply_val(ctx.ep_cap, total as i64);
}

/// Writev for /dev/null (kind=8).
pub(crate) fn writev_devnull(ctx: &mut SyscallContext, iov_ptr: u64, iovcnt: usize) {
    let mut total: usize = 0;
    let cnt = iovcnt.min(16);
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let len = unsafe { *((entry + 8) as *const u64) } as usize;
        total += len;
    }
    reply_val(ctx.ep_cap, total as i64);
}

/// Writev for TCP socket (kind=16).
pub(crate) fn writev_tcp(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
    let conn_id = ctx.sock_conn_id[fd] as u64;
    let cnt = iovcnt.min(16);
    let mut total_sent = 0usize;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let mut off = 0;
        while off < ilen {
            let chunk = (ilen - off).min(40);
            let mut req = sotos_common::IpcMsg {
                tag: NET_CMD_TCP_SEND,
                regs: [conn_id, 0, chunk as u64, 0, 0, 0, 0, 0],
            };
            let mut data = [0u8; 40];
            ctx.guest_read(base + off as u64, &mut data[..chunk]);
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
    reply_val(ctx.ep_cap, total_sent as i64);
}

/// Writev for VFS file (kind=13).
pub(crate) fn writev_vfs(ctx: &mut SyscallContext, fd: usize, iov_ptr: u64, iovcnt: usize) {
    let cnt = iovcnt.min(16);
    let mut total: usize = 0;
    let mut ok = true;
    for i in 0..cnt {
        let entry = iov_ptr + (i as u64) * 16;
        if entry + 16 > 0x0000_8000_0000_0000 { break; }
        let base = ctx.guest_read_u64(entry);
        let ilen = ctx.guest_read_u64(entry + 8) as usize;
        if base == 0 || ilen == 0 { continue; }
        let safe_ilen = ilen.min(4096);
        let mut local_buf = [0u8; 4096];
        ctx.guest_read(base, &mut local_buf[..safe_ilen]);
        let data = &local_buf[..safe_ilen];
        let mut wrote = false;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                let oid = ctx.vfs_files[s][0];
                let pos = ctx.vfs_files[s][2] as usize;
                vfs_lock();
                let result = unsafe { shared_store() }
                    .and_then(|store| store.write_obj_range(oid, pos, data).ok());
                vfs_unlock();
                match result {
                    Some(_) => {
                        ctx.vfs_files[s][2] += safe_ilen as u64;
                        let new_end = ctx.vfs_files[s][2];
                        if new_end > ctx.vfs_files[s][1] { ctx.vfs_files[s][1] = new_end; }
                        total += safe_ilen;
                        wrote = true;
                    }
                    None => { ok = false; }
                }
                break;
            }
        }
        if !wrote && ok { ok = false; }
        if !ok { break; }
    }
    reply_val(ctx.ep_cap, if ok && total > 0 { total as i64 } else { -EIO });
}

/// SYS_PREADV (295).
pub(crate) fn sys_preadv(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    let offset = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); return;
    }
    let mut total = 0i64;
    for i in 0..iovcnt.min(16) {
        let iov = unsafe { iov_ptr.wrapping_add((i * 16) as u64) };
        let base = unsafe { *(iov as *const u64) };
        let len = unsafe { *((iov + 8) as *const u64) } as usize;
        if base == 0 || len == 0 { continue; }
        if ctx.child_fds[fd] == 13 {
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
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
    reply_val(ctx.ep_cap, total);
}

/// SYS_PWRITEV (296).
pub(crate) fn sys_pwritev(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    let iov_ptr = msg.regs[1];
    let iovcnt = msg.regs[2] as usize;
    let offset = msg.regs[3];
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] == 0 {
        reply_val(ctx.ep_cap, -EBADF); return;
    }
    let mut total = 0i64;
    for i in 0..iovcnt.min(16) {
        let iov = unsafe { iov_ptr.wrapping_add((i * 16) as u64) };
        let base = unsafe { *(iov as *const u64) };
        let len = unsafe { *((iov + 8) as *const u64) } as usize;
        if base == 0 || len == 0 { continue; }
        if ctx.child_fds[fd] == 13 {
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    let oid = ctx.vfs_files[s][0];
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
    reply_val(ctx.ep_cap, total);
}

/// SYS_UNLINK (87).
pub(crate) fn sys_unlink(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
    let abs_name = &abs[..alen];
    if ctx.pid >= 3 {
        print(b"UNLINK P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in abs_name { if b == 0 { break; } sys::debug_print(b); } print(b"]\n");
    }
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        store.resolve_path(abs_name, ROOT_OID).ok()
            .and_then(|oid| store.delete(oid).ok())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}

/// SYS_UNLINKAT (263).
pub(crate) fn sys_unlinkat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let flags = msg.regs[2] as u32;
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    if ctx.pid >= 3 {
        print(b"UNLINKAT P"); print_u64(ctx.pid as u64);
        print(b" fl=0x"); crate::framebuffer::print_hex64(flags as u64);
        print(b" ["); for &b in name { if b == 0 { break; } sys::debug_print(b); } print(b"]\n");
    }
    if flags & 0x200 != 0 {
        reply_val(ctx.ep_cap, 0);
    } else {
        vfs_lock();
        let result = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            store.resolve_path(name, ROOT_OID).ok()
                .and_then(|oid| store.delete(oid).ok())
        });
        vfs_unlock();
        reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
    }
}

/// SYS_RENAMEAT (264) / SYS_RENAMEAT2 (316).
pub(crate) fn sys_renameat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let oldpath_ptr = msg.regs[1];
    let newpath_ptr = msg.regs[3];
    let mut oldpath = [0u8; 128];
    let mut newpath = [0u8; 128];
    let olen = ctx.guest_copy_path(oldpath_ptr, &mut oldpath);
    let nlen = ctx.guest_copy_path(newpath_ptr, &mut newpath);
    let (oldpath, olen) = if olen > 0 && oldpath[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &oldpath[..olen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (oldpath, olen) };
    let (newpath, nlen) = if nlen > 0 && newpath[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &newpath[..nlen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else { (newpath, nlen) };
    if ctx.pid >= 3 {
        print(b"RENAMEAT P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in &oldpath[..olen] { sys::debug_print(b); }
        print(b"] -> ["); for &b in &newpath[..nlen] { sys::debug_print(b); }
        print(b"]\n");
    }
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let oid = match store.resolve_path(&oldpath[..olen], ROOT_OID) {
            Ok(o) => o,
            Err(_) => {
                if ctx.pid >= 3 { print(b"RENAMEAT-FAIL: old not found\n"); }
                return None;
            }
        };
        let mut last_slash = None;
        for (i, &b) in newpath[..nlen].iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, fname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else {
                    match store.resolve_path(&newpath[..pos], ROOT_OID) {
                        Ok(p) => p,
                        Err(_) => {
                            if ctx.pid >= 3 { print(b"RENAMEAT-FAIL: new parent not found\n"); }
                            return None;
                        }
                    }
                };
                (p, &newpath[pos+1..nlen])
            }
            None => (ROOT_OID, &newpath[..nlen]),
        };
        if let Err(e) = store.rename(oid, fname, parent) {
            if ctx.pid >= 3 {
                print(b"RENAMEAT-FAIL: store err=[");
                print(e.as_bytes());
                print(b"]\n");
            }
            return None;
        }
        Some(())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}
