// ---------------------------------------------------------------------------
// fs_dir.rs — Directory operations: getdents64, mkdir, mkdirat, rmdir,
//             chdir, fchdir, getcwd
// Extracted from fs.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::reply_val;
use crate::fd::*;
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// SYS_GETDENTS64 (217): read directory entries.
pub(crate) fn sys_getdents64(ctx: &mut SyscallContext, msg: &IpcMsg) {
    use sotos_common::linux_abi::{DT_REG, DT_DIR};
    let fd = msg.regs[0] as usize;
    let dirp = msg.regs[1];
    let count = msg.regs[2] as usize;

    if fd >= GRP_MAX_FDS || (ctx.child_fds[fd] != 14 && ctx.child_fds[fd] != 15) {
        reply_val(ctx.ep_cap, -EBADF);
    } else if ctx.child_fds[fd] == 15 && *ctx.dir_pos == 0 {
        // Virtual directory listing (e.g. /dev/dri/, /dev/input/)
        // Populate dir_buf with synthetic entries based on the dir path
        // For /dev/dri/: card0
        // For /dev/input/: event0, event1
        use sotos_common::linux_abi::DT_CHR;
        let entries: &[&[u8]] = if *ctx.dir_len == 0xDD01 {
            &[b"card0"]  // /dev/dri/
        } else if *ctx.dir_len == 0xDD02 {
            &[b"event0", b"event1"] // /dev/input/
        } else if *ctx.dir_len == 0xDD03 {
            &[b"card0"] // /sys/class/drm/
        } else if *ctx.dir_len == 0xDD04 {
            &[b"event0", b"event1"] // /sys/class/input/
        } else if *ctx.dir_len == 0xDD05 {
            &[b"drm", b"input"] // /sys/class/ (libudev enumerates subsystems)
        } else {
            &[]
        };
        let mut off = 0usize;
        for (idx, name) in entries.iter().enumerate() {
            let reclen = ((19 + name.len() + 1 + 7) / 8) * 8;
            if off + reclen > ctx.dir_buf.len() { break; }
            let d = &mut ctx.dir_buf[off..off + reclen];
            for b in d.iter_mut() { *b = 0; }
            d[0..8].copy_from_slice(&((idx + 100) as u64).to_le_bytes()); // ino
            d[8..16].copy_from_slice(&((off + reclen) as u64).to_le_bytes()); // next offset
            d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
            // /sys/class/ and /sys/class/drm/ entries are dirs; /dev/ entries are char devices
            d[18] = if *ctx.dir_len >= 0xDD03 { 4 /* DT_DIR */ } else { DT_CHR };
            d[19..19 + name.len()].copy_from_slice(name);
            off += reclen;
        }
        if off > 0 {
            ctx.guest_write(dirp, &ctx.dir_buf[..off]);
            *ctx.dir_pos = 1; // mark as read
            reply_val(ctx.ep_cap, off as i64);
        } else {
            reply_val(ctx.ep_cap, 0); // EOF
        }
    } else {
        let mut need_populate = true;
        for s in 0..GRP_MAX_VFS {
            if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                if ctx.vfs_files[s][2] == 0xDEAD { need_populate = false; }
                break;
            }
        }
        if need_populate {
            *ctx.dir_len = 0;
            *ctx.dir_pos = 0;
            let mut dir_oid = 0u64;
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    dir_oid = ctx.vfs_files[s][0];
                    break;
                }
            }
            if dir_oid != 0 {
                vfs_lock();
                if let Some(store) = unsafe { shared_store() } {
                    for entry in &store.dir {
                        if entry.is_free() || entry.parent_oid != dir_oid || entry.oid == dir_oid {
                            continue;
                        }
                        let ename = entry.name_as_str();
                        let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                        if *ctx.dir_len + reclen > ctx.dir_buf.len() { break; }
                        let d = &mut ctx.dir_buf[*ctx.dir_len..*ctx.dir_len + reclen];
                        for b in d.iter_mut() { *b = 0; }
                        d[0..8].copy_from_slice(&entry.oid.to_le_bytes());
                        d[8..16].copy_from_slice(&((*ctx.dir_len + reclen) as u64).to_le_bytes());
                        d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                        d[18] = if entry.is_dir() { DT_DIR } else { DT_REG };
                        let nlen = ename.len().min(reclen - 19);
                        d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                        *ctx.dir_len += reclen;
                    }
                }
                vfs_unlock();
            }
            for s in 0..GRP_MAX_VFS {
                if ctx.vfs_files[s][3] == fd as u64 && ctx.vfs_files[s][0] != 0 {
                    ctx.vfs_files[s][2] = 0xDEAD;
                    break;
                }
            }
        }

        let remaining = if *ctx.dir_pos < *ctx.dir_len { *ctx.dir_len - *ctx.dir_pos } else { 0 };
        if remaining == 0 {
            reply_val(ctx.ep_cap, 0); // EOF
        } else {
            let copy_len = remaining.min(count);
            ctx.guest_write(dirp, &ctx.dir_buf[*ctx.dir_pos..*ctx.dir_pos + copy_len]);
            *ctx.dir_pos += copy_len;
            reply_val(ctx.ep_cap, copy_len as i64);
        }
    }
}

/// SYS_MKDIR (83): create directory in VFS.
pub(crate) fn sys_mkdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let name = &path[..plen];
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, name, &mut abs);
    let abs_name = &abs[..alen];
    vfs_lock();
    let mut mkdir_ok = false;
    if let Some(store) = unsafe { shared_store() } {
        use sotos_objstore::ROOT_OID;
        let mut last_slash = None;
        for (i, &b) in abs_name.iter().enumerate() { if b == b'/' { last_slash = Some(i); } }
        let (parent, dname) = match last_slash {
            Some(pos) => {
                let p = if pos == 0 { ROOT_OID } else {
                    match store.resolve_path(&abs_name[..pos], ROOT_OID) {
                        Ok(oid) => oid,
                        Err(_) => { vfs_unlock(); reply_val(ctx.ep_cap, -ENOENT); return; }
                    }
                };
                (p, &abs_name[pos+1..alen])
            }
            None => (ROOT_OID, abs_name),
        };
        if store.resolve_path(dname, parent).is_ok() {
            mkdir_ok = true;
        } else if store.mkdir(dname, parent).is_ok() {
            mkdir_ok = true;
        }
    }
    vfs_unlock();
    trace!(Debug, FS, {
        print(b"MKDIR P"); print_u64(ctx.pid as u64);
        print(b" "); print(abs_name);
        print(if mkdir_ok { b" OK" } else { b" FAIL" });
    });
    reply_val(ctx.ep_cap, if mkdir_ok { 0 } else { -ENOSPC });
}

/// SYS_MKDIRAT (258): mkdir with dirfd.
pub(crate) fn sys_mkdirat(ctx: &mut SyscallContext, msg: &IpcMsg) {
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
        if store.resolve_path(dname, parent).is_ok() {
            Some(0u64)
        } else {
            store.mkdir(dname, parent).ok()
        }
    });
    vfs_unlock();
    trace!(Debug, FS, {
        print(b"MKDIRAT P"); print_u64(ctx.pid as u64);
        print(b" "); print(name);
        if result.is_some() { print(b" OK"); } else { print(b" FAIL"); }
    });
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOSPC });
}

/// SYS_RMDIR (84): remove directory.
pub(crate) fn sys_rmdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
    let abs_name = &abs[..alen];
    vfs_lock();
    let result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        store.resolve_path(abs_name, ROOT_OID).ok()
            .and_then(|oid| store.delete(oid).ok())
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if result.is_some() { 0 } else { -ENOENT });
}

/// SYS_GETCWD (79): get current working directory.
pub(crate) fn sys_getcwd(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let buf_addr = msg.regs[0];
    let size = msg.regs[1] as usize;
    let mut cwd_len = 0;
    while cwd_len < GRP_CWD_MAX && ctx.cwd[cwd_len] != 0 { cwd_len += 1; }
    if cwd_len == 0 { cwd_len = 1; ctx.cwd[0] = b'/'; }
    trace!(Debug, FS, {
        print(b"GETCWD P"); print_u64(ctx.pid as u64);
        print(b" len="); print_u64(cwd_len as u64);
        print(b" ["); for i in 0..cwd_len.min(40) { sys::debug_print(ctx.cwd[i]); } print(b"]");
    });
    if size > cwd_len {
        let mut tmp = [0u8; GRP_CWD_MAX + 1];
        tmp[..cwd_len].copy_from_slice(&ctx.cwd[..cwd_len]);
        tmp[cwd_len] = 0;
        ctx.guest_write(buf_addr, &tmp[..cwd_len + 1]);
        // Linux raw syscall returns length (including NUL), not pointer
        reply_val(ctx.ep_cap, (cwd_len + 1) as i64);
    } else {
        reply_val(ctx.ep_cap, -ERANGE);
    }
}

/// SYS_CHDIR (80): change working directory.
pub(crate) fn sys_chdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let name = &path[..plen];
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, name, &mut abs);
    let abs_name = &abs[..alen];
    trace!(Debug, FS, {
        print(b"CHDIR P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in abs_name { if b == 0 { break; } sys::debug_print(b); } print(b"]");
    });
    let is_root = alen == 1 && abs[0] == b'/';
    let is_well_known = abs_name == b"/tmp" || abs_name == b"/home"
        || abs_name == b"/var" || abs_name == b"/usr"
        || abs_name == b"/bin" || abs_name == b"/lib"
        || abs_name == b"/lib64" || abs_name == b"/sbin"
        || abs_name == b"/etc" || abs_name == b"/proc"
        || abs_name == b"/usr/bin" || abs_name == b"/usr/lib"
        || abs_name == b"/usr/sbin" || abs_name == b"/usr/share";
    let vfs_ok = if !is_root && !is_well_known {
        vfs_lock();
        let ok = unsafe { shared_store() }.and_then(|store| {
            store.resolve_path(abs_name, sotos_objstore::ROOT_OID).ok()
        }).is_some();
        vfs_unlock();
        ok
    } else { false };
    if is_root || is_well_known || vfs_ok {
        let copy_len = alen.min(GRP_CWD_MAX - 1);
        ctx.cwd[..copy_len].copy_from_slice(&abs[..copy_len]);
        ctx.cwd[copy_len] = 0;
        if copy_len > 1 && ctx.cwd[copy_len - 1] == b'/' {
            ctx.cwd[copy_len - 1] = 0;
        }
        reply_val(ctx.ep_cap, 0);
    } else {
        reply_val(ctx.ep_cap, -ENOENT);
    }
}

/// SYS_FCHDIR (81): change CWD via file descriptor.
pub(crate) fn sys_fchdir(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let fd = msg.regs[0] as usize;
    trace!(Debug, FS, {
        print(b"FCHDIR P"); print_u64(ctx.pid as u64);
        print(b" fd="); print_u64(fd as u64);
        if fd < crate::fd::GRP_MAX_FDS { print(b" k="); print_u64(ctx.child_fds[fd] as u64); }
        print(b" slot="); print_u64(ctx.sock_conn_id[fd] as u64);
        print(b" grp="); print_u64((ctx.pid.saturating_sub(1) * 8) as u64);
    });
    if fd >= GRP_MAX_FDS || ctx.child_fds[fd] != 14 {
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }
    let slot = ctx.sock_conn_id[fd] as usize;
    let grp_base = (ctx.pid.saturating_sub(1)) * 8;
    let global_slot = grp_base + (slot & 7);
    if global_slot >= crate::fd::MAX_DIR_SLOTS {
        reply_val(ctx.ep_cap, -EBADF);
        return;
    }
    let path = unsafe { &crate::fd::DIR_FD_PATHS[global_slot] };
    let mut plen = 0;
    while plen < 127 && path[plen] != 0 { plen += 1; }
    if plen == 0 {
        trace!(Error, FS, {
            print(b"FCHDIR-ENOENT P"); print_u64(ctx.pid as u64);
            print(b" gslot="); print_u64(global_slot as u64);
        });
        reply_val(ctx.ep_cap, -ENOENT);
        return;
    }
    let copy_len = plen.min(GRP_CWD_MAX - 1);
    ctx.cwd[..copy_len].copy_from_slice(&path[..copy_len]);
    ctx.cwd[copy_len] = 0;
    trace!(Debug, FS, {
        print(b"FCHDIR P"); print_u64(ctx.pid as u64);
        print(b" fd="); print_u64(fd as u64);
        print(b" ["); for &b in &ctx.cwd[..copy_len] { if b == 0 { break; } sys::debug_print(b); } print(b"]");
    });
    reply_val(ctx.ep_cap, 0);
}
