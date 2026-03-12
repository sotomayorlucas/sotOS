// ---------------------------------------------------------------------------
// Memory management syscalls: brk, mmap, munmap, mprotect, mremap
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::process::*;
use crate::fd::*;
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::print;
use super::context::SyscallContext;

const MAP_WRITABLE: u64 = 2;

/// SYS_BRK (12): expand/query the program break.
pub(crate) fn sys_brk(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0];
    let brk_limit = ctx.my_brk_base + CHILD_MMAP_OFFSET;

    if addr == 0 || addr <= *ctx.current_brk {
        reply_val(ctx.ep_cap, *ctx.current_brk as i64);
    } else {
        let new_brk = (addr + 0xFFF) & !0xFFF;
        if new_brk > brk_limit {
            reply_val(ctx.ep_cap, *ctx.current_brk as i64);
            return;
        }
        let mut ok = true;
        let mut pg = (*ctx.current_brk + 0xFFF) & !0xFFF;
        while pg < new_brk {
            if let Ok(f) = sys::frame_alloc() {
                if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
            } else { ok = false; break; }
            pg += 0x1000;
        }
        if ok {
            *ctx.current_brk = new_brk;
            if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                PROCESSES[ctx.pid - 1].brk_current.store(new_brk, Ordering::Release);
            }
        }
        reply_val(ctx.ep_cap, *ctx.current_brk as i64);
    }
}

/// SYS_MMAP (9): map anonymous or file-backed pages.
pub(crate) fn sys_mmap(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let req_addr = msg.regs[0];
    let len = msg.regs[1];
    let prot = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let fd = msg.regs[4] as i64;
    let offset = msg.regs[5];

    let mflags = MFlags::from_bits_truncate(flags);
    let map_fixed = mflags.contains(MFlags::FIXED);
    let map_anon = mflags.contains(MFlags::ANONYMOUS);
    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;

    // Determine base address
    let base = if map_fixed && req_addr != 0 {
        for p in 0..pages {
            let _ = sys::unmap_free(req_addr + p * 0x1000);
        }
        req_addr
    } else {
        let b = *ctx.mmap_next;
        *ctx.mmap_next += pages * 0x1000;
        if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
            PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
        }
        b
    };

    let mmap_fixup_prot = |base: u64, pages: u64, prot: u64| {
        if prot & 2 == 0 {
            let pflags = if prot & 4 != 0 { 0u64 } else { 1u64 << 63 };
            for p in 0..pages {
                let _ = sys::protect(base + p * 0x1000, pflags);
            }
        }
    };

    // DIAG: trace mmap for pid >= 4
    if ctx.pid >= 4 {
        for &b in b"MM9:" { sys::debug_print(b); }
        // pid digit
        sys::debug_print(b'0' + ctx.pid as u8);
        sys::debug_print(b' ');
        // fd
        if fd >= 0 { for &b in b"fd=" { sys::debug_print(b); } sys::debug_print(b'0' + fd as u8); }
        else { for &b in b"anon" { sys::debug_print(b); } }
        sys::debug_print(b' ');
        // pages
        for &b in b"pg=" { sys::debug_print(b); }
        crate::framebuffer::print_u64(pages);
        sys::debug_print(b' ');
        // flags
        if map_fixed { sys::debug_print(b'F'); }
        if map_anon { sys::debug_print(b'A'); }
        sys::debug_print(b'\n');
    }

    if fd >= 0 && !map_anon {
        // File-backed mmap
        let fdu = fd as usize;
        let mut file_data: u64 = 0;
        let mut file_size: u64 = 0;
        let mut is_vfs = false;
        let mut vfs_oid: u64 = 0;

        if ctx.pid >= 4 {
            for &b in b"MM9-FK:" { sys::debug_print(b); }
            sys::debug_print(b'0' + ctx.child_fds[fdu as usize]);
            sys::debug_print(b'\n');
        }

        if fdu < GRP_MAX_FDS {
            if ctx.child_fds[fdu] == 12 {
                // First: exact fd match (current open file)
                for s in 0..GRP_MAX_INITRD {
                    if ctx.initrd_files[s][0] != 0
                        && ctx.initrd_files[s][3] == fdu as u64
                    {
                        file_data = ctx.initrd_files[s][0];
                        file_size = ctx.initrd_files[s][1];
                        break;
                    }
                }
                // Fallback: closed-but-alive entry (u64::MAX) — only if no exact match.
                // NOTE: stale entries from forked parents can shadow new opens,
                // so this fallback should rarely be needed.
                if file_data == 0 {
                    for s in 0..GRP_MAX_INITRD {
                        if ctx.initrd_files[s][0] != 0
                            && ctx.initrd_files[s][3] == u64::MAX
                        {
                            file_data = ctx.initrd_files[s][0];
                            file_size = ctx.initrd_files[s][1];
                            break;
                        }
                    }
                }
            }
            if file_data == 0 && ctx.child_fds[fdu] == 13 {
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][0] != 0 && ctx.vfs_files[s][3] == fdu as u64 {
                        vfs_oid = ctx.vfs_files[s][0];
                        file_size = ctx.vfs_files[s][1];
                        is_vfs = true;
                        break;
                    }
                }
            }
        }

        if file_data == 0 && !is_vfs {
            if ctx.pid >= 4 { for &b in b"MM9-EBADF\n" { sys::debug_print(b); } }
            reply_val(ctx.ep_cap, -EBADF);
            return;
        }

        if ctx.pid >= 4 {
            for &b in b"MM9-ALLOC:" { sys::debug_print(b); }
            crate::framebuffer::print_u64(pages);
            if is_vfs { for &b in b" vfs" { sys::debug_print(b); } }
            sys::debug_print(b'\n');
        }

        let mut ok = true;
        for p in 0..pages {
            if let Ok(f) = sys::frame_alloc() {
                if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                    if ctx.pid >= 4 { for &b in b"MM9-MAPFAIL\n" { sys::debug_print(b); } }
                    ok = false; break;
                }
            } else {
                if ctx.pid >= 4 { for &b in b"MM9-OOM\n" { sys::debug_print(b); } }
                ok = false; break;
            }
        }
        if ctx.pid >= 4 { for &b in b"MM9-ALLOCD\n" { sys::debug_print(b); } }
        if ok {
            let map_size = (pages * 0x1000) as usize;
            unsafe { core::ptr::write_bytes(base as *mut u8, 0, map_size); }
            if ctx.pid >= 4 { for &b in b"MM9-ZERO\n" { sys::debug_print(b); } }
            let file_off = offset as usize;
            let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
            let to_copy = map_size.min(avail);

            if is_vfs && to_copy > 0 {
                if ctx.pid >= 4 {
                    for &b in b"MM9-VFSRD oid=" { sys::debug_print(b); }
                    crate::framebuffer::print_u64(vfs_oid);
                    for &b in b" sz=" { sys::debug_print(b); }
                    crate::framebuffer::print_u64(file_size);
                    sys::debug_print(b'\n');
                }
                let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, to_copy) };
                vfs_lock();
                let read_result = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(vfs_oid, file_off, dst).ok());
                vfs_unlock();

                match read_result {
                    Some(n) => {
                        if ctx.pid >= 4 {
                            for &b in b"MM9-RD:" { sys::debug_print(b); }
                            crate::framebuffer::print_u64(n as u64);
                            for &b in b"/" { sys::debug_print(b); }
                            crate::framebuffer::print_u64(to_copy as u64);
                            // Show first 4 bytes to verify data integrity
                            if n >= 4 {
                                for &b in b" [" { sys::debug_print(b); }
                                for i in 0..4u64 {
                                    let byte = unsafe { *((base + i) as *const u8) };
                                    crate::framebuffer::print_hex8(byte);
                                }
                                for &b in b"]" { sys::debug_print(b); }
                            }
                            sys::debug_print(b'\n');
                        }
                    }
                    None => {
                        // VFS read failed — return error instead of zeroed pages
                        print(b"MM9-VFS-FAIL oid=");
                        crate::framebuffer::print_u64(vfs_oid);
                        print(b" off=");
                        crate::framebuffer::print_u64(file_off as u64);
                        print(b" sz=");
                        crate::framebuffer::print_u64(to_copy as u64);
                        print(b" P");
                        crate::framebuffer::print_u64(ctx.pid as u64);
                        print(b"\n");
                        // Free the frames we already allocated
                        for p in 0..pages {
                            let _ = sys::unmap_free(base + p * 0x1000);
                        }
                        reply_val(ctx.ep_cap, -EIO);
                        return;
                    }
                }
            } else if to_copy > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (file_data + file_off as u64) as *const u8,
                        base as *mut u8,
                        to_copy,
                    );
                }

            }
            if ctx.pid >= 4 { for &b in b"MM9-PROT\n" { sys::debug_print(b); } }
            mmap_fixup_prot(base, pages, prot);
            if ctx.pid >= 4 { for &b in b"MM9-REPLY\n" { sys::debug_print(b); } }
            reply_val(ctx.ep_cap, base as i64);
        } else {
            if ctx.pid >= 4 { for &b in b"MM9-ENOMEM\n" { sys::debug_print(b); } }
            reply_val(ctx.ep_cap, -ENOMEM);
        }
        return;
    }

    // Anonymous mmap
    if ctx.pid >= 4 {
        for &b in b"ANON:" { sys::debug_print(b); }
        sys::debug_print(b'0' + ctx.pid as u8);
        for &b in b" pg=" { sys::debug_print(b); }
        crate::framebuffer::print_u64(pages);
        for &b in b" base=0x" { sys::debug_print(b); }
        crate::framebuffer::print_hex64(base);
        sys::debug_print(b'\n');
    }
    let mut ok = true;
    for p in 0..pages {
        if ctx.pid >= 4 && (p == 0 || p == pages / 2 || p == pages - 1) {
            for &b in b"AP:" { sys::debug_print(b); }
            sys::debug_print(b'0' + ctx.pid as u8);
            sys::debug_print(b':');
            crate::framebuffer::print_u64(p);
            sys::debug_print(b'/');
            crate::framebuffer::print_u64(pages);
            sys::debug_print(b'\n');
        }
        let f = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                for &b in b"MMAP-OOM p=" { sys::debug_print(b); }
                crate::framebuffer::print_u64(p);
                sys::debug_print(b'\n');
                ok = false; break;
            }
        };
        if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
            for &b in b"MMAP-MAPF p=" { sys::debug_print(b); }
            crate::framebuffer::print_u64(p);
            sys::debug_print(b'\n');
            ok = false; break;
        }
    }
    if ctx.pid >= 4 {
        for &b in b"ANON-LOOP-DONE:" { sys::debug_print(b); }
        sys::debug_print(b'0' + ctx.pid as u8);
        sys::debug_print(if ok { b'Y' } else { b'N' });
        sys::debug_print(b'\n');
    }
    if ok {
        if ctx.pid >= 4 { for &b in b"ANON-ZERO\n" { sys::debug_print(b); } }
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 0x1000) as usize); }
        if ctx.pid >= 4 { for &b in b"ANON-PROT\n" { sys::debug_print(b); } }
        mmap_fixup_prot(base, pages, prot);
        if ctx.pid >= 4 { for &b in b"ANON-REPLY\n" { sys::debug_print(b); } }
        reply_val(ctx.ep_cap, base as i64);
    } else {
        reply_val(ctx.ep_cap, -ENOMEM);
    }
}

/// SYS_MPROTECT (10): change page permissions.
pub(crate) fn sys_mprotect(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0] & !0xFFF;
    let len = msg.regs[1];
    let prot = msg.regs[2];
    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
    let flags = if prot & 2 != 0 {
        MAP_WRITABLE
    } else if prot & 4 != 0 {
        0u64
    } else {
        1u64 << 63
    };
    for p in 0..pages {
        let _ = sys::protect(addr + p * 0x1000, flags);
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_MUNMAP (11): unmap pages and free frames.
pub(crate) fn sys_munmap(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0];
    let len = msg.regs[1];
    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
    for p in 0..pages {
        let _ = sys::unmap_free(addr + p * 0x1000);
    }
    let freed_end = addr + pages * 0x1000;
    if freed_end == *ctx.mmap_next {
        *ctx.mmap_next = addr;
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_MREMAP (25): remap/resize an existing mapping.
pub(crate) fn sys_mremap(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old_addr = msg.regs[0];
    let old_size = msg.regs[1];
    let new_size = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let mremap_maymove = (flags & 1) != 0;

    if new_size <= old_size {
        // Shrink
        let old_pages = ((old_size + 0xFFF) & !0xFFF) / 0x1000;
        let new_pages = ((new_size + 0xFFF) & !0xFFF) / 0x1000;
        for p in new_pages..old_pages {
            let _ = sys::unmap_free(old_addr + p * 0x1000);
        }
        let freed_end = old_addr + old_pages * 0x1000;
        if freed_end == *ctx.mmap_next {
            *ctx.mmap_next = old_addr + new_pages * 0x1000;
        }
        reply_val(ctx.ep_cap, old_addr as i64);
    } else if mremap_maymove {
        let old_pages = ((old_size + 0xFFF) & !0xFFF) / 0x1000;
        let new_pages = ((new_size + 0xFFF) & !0xFFF) / 0x1000;
        let old_end = old_addr + old_pages * 0x1000;

        if old_end == *ctx.mmap_next {
            // In-place growth
            let extra_pages = new_pages - old_pages;
            let mut ok = true;
            for p in 0..extra_pages {
                if let Ok(f) = sys::frame_alloc() {
                    if sys::map(*ctx.mmap_next + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                } else { ok = false; break; }
            }
            if ok {
                unsafe { core::ptr::write_bytes(*ctx.mmap_next as *mut u8, 0, (extra_pages * 0x1000) as usize); }
                *ctx.mmap_next += extra_pages * 0x1000;
                if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                    PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
                }
                reply_val(ctx.ep_cap, old_addr as i64);
            } else {
                reply_val(ctx.ep_cap, -ENOMEM);
            }
        } else {
            // Allocate new region, copy, unmap old
            let new_base = *ctx.mmap_next;
            *ctx.mmap_next += new_pages * 0x1000;
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
                if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                    PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
                }
                reply_val(ctx.ep_cap, new_base as i64);
            } else {
                reply_val(ctx.ep_cap, -ENOMEM);
            }
        }
    } else {
        reply_val(ctx.ep_cap, -ENOMEM);
    }
}

// Constant re-exported for brk limit calculation
pub(crate) const CHILD_MMAP_OFFSET: u64 = 0x1000000;
