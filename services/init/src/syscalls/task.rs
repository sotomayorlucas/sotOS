// ---------------------------------------------------------------------------
// Process lifecycle + identity syscalls
// Extracted from child_handler.rs
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::process::*;
use crate::fd::*;
use super::context::SyscallContext;

/// Return value for syscalls that may break the main handler loop.
pub(crate) enum SyscallAction {
    Continue,
    Break,
}

impl SyscallAction {
    pub(crate) fn is_break(&self) -> bool {
        matches!(self, SyscallAction::Break)
    }
}

// ─── Identity / credential syscalls ─────────────────────────────

/// SYS_GETPID (39): returns tgid (thread group ID), not tid.
pub(crate) fn sys_getpid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let tgid = PROC_TGID[ctx.pid - 1].load(Ordering::Acquire);
    reply_val(ctx.ep_cap, if tgid != 0 { tgid as i64 } else { ctx.pid as i64 });
}

/// SYS_GETTID (186): returns actual thread ID.
pub(crate) fn sys_gettid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_GETPPID (110): returns parent pid.
pub(crate) fn sys_getppid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    let parent_pid = PROC_PARENT[ctx.pid - 1].load(Ordering::Acquire);
    reply_val(ctx.ep_cap, parent_pid as i64);
}

/// SYS_GETUID/GETGID/GETEUID/GETEGID — all return 0 (root).
pub(crate) fn sys_getuid_family(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_SETPGID (109): stub.
pub(crate) fn sys_setpgid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETPGRP (111): returns pid.
pub(crate) fn sys_getpgrp(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_SETSID (112): returns pid.
pub(crate) fn sys_setsid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_SETFSUID/SYS_SETFSGID — return previous (0).
pub(crate) fn sys_setfsuid_family(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GETPGID (121) / SYS_GETSID (124).
pub(crate) fn sys_getpgid(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let target = msg.regs[0] as usize;
    reply_val(ctx.ep_cap, if target == 0 { ctx.pid as i64 } else { target as i64 });
}

/// SYS_TGKILL (234): send signal to thread in group.
pub(crate) fn sys_tgkill(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let _tgid = msg.regs[0];
    let tid = msg.regs[1] as usize;
    let sig = msg.regs[2] as u8;
    if sig > 0 && sig <= 64 && tid >= 1 && tid <= MAX_PROCS {
        sig_send(tid, sig as u64);
    }
    reply_val(ctx.ep_cap, 0);
}

// ─── TID / robust list ──────────────────────────────────────────

/// SYS_SET_TID_ADDRESS (218): store clear_child_tid pointer, return TID.
pub(crate) fn sys_set_tid_address(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let tidptr = msg.regs[0];
    PROC_CLEAR_TID[ctx.pid - 1].store(tidptr, Ordering::Release);
    reply_val(ctx.ep_cap, ctx.pid as i64);
}

/// SYS_SET_ROBUST_LIST (273): stub.
pub(crate) fn sys_set_robust_list(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, 0);
}

/// SYS_GET_ROBUST_LIST (274): not supported.
pub(crate) fn sys_get_robust_list(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ENOSYS);
}

// ─── Signals ────────────────────────────────────────────────────

/// SYS_KILL (62): send signal to process.
pub(crate) fn sys_kill(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let target = msg.regs[0] as usize;
    let sig = msg.regs[1];
    if target == 0 || target > MAX_PROCS || PROC_STATE[target - 1].load(Ordering::Acquire) == 0 {
        reply_val(ctx.ep_cap, -ESRCH);
        return;
    }
    sig_send(target, sig);
    reply_val(ctx.ep_cap, 0);
}

// ─── Wait ───────────────────────────────────────────────────────

/// SYS_WAIT4 (61): wait for child process.
pub(crate) fn sys_wait4(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let pid = ctx.pid;
    let ep_cap = ctx.ep_cap;
    let wait_pid = msg.regs[0] as i64;
    let status_ptr = msg.regs[1];
    let options = msg.regs[2] as u32;
    let wnohang = options & 1 != 0;

    let mut target: Option<usize> = None;
    if wait_pid > 0 && (wait_pid as usize) <= MAX_PROCS {
        let idx = wait_pid as usize - 1;
        if PROC_PARENT[idx].load(Ordering::Acquire) == pid as u64 {
            target = Some(wait_pid as usize);
        }
    } else if wait_pid == -1 || wait_pid == 0 {
        for i in 0..MAX_PROCS {
            if PROC_PARENT[i].load(Ordering::Acquire) == pid as u64 {
                if PROC_STATE[i].load(Ordering::Acquire) == 2 {
                    target = Some(i + 1);
                    break;
                }
                if target.is_none() && PROC_STATE[i].load(Ordering::Acquire) == 1 {
                    target = Some(i + 1);
                }
            }
        }
    }

    if let Some(cpid) = target {
        let idx = cpid - 1;
        if wnohang && PROC_STATE[idx].load(Ordering::Acquire) != 2 {
            reply_val(ep_cap, 0);
        } else {
            let mut spins = 0u64;
            while PROC_STATE[idx].load(Ordering::Acquire) != 2 {
                sys::yield_now();
                spins += 1;
                if spins > 50_000 { break; }
            }
            if PROC_STATE[idx].load(Ordering::Acquire) == 2 {
                let exit_status = PROC_EXIT[idx].load(Ordering::Acquire) as u32;
                if status_ptr != 0 && status_ptr < 0x0000_8000_0000_0000 {
                    let ws = (exit_status << 8) & 0xFF00;
                    unsafe { *(status_ptr as *mut u32) = ws; }
                }
                PROC_STATE[idx].store(0, Ordering::Release);
                reply_val(ep_cap, cpid as i64);
            } else {
                reply_val(ep_cap, -ECHILD);
            }
        }
    } else {
        reply_val(ep_cap, -ECHILD);
    }
}

/// SYS_WAITID (247): stub.
pub(crate) fn sys_waitid(ctx: &mut SyscallContext, _msg: &IpcMsg) {
    reply_val(ctx.ep_cap, -ECHILD);
}

// ─── Exit ───────────────────────────────────────────────────────

/// Shared cleanup for SYS_EXIT and SYS_EXIT_GROUP.
fn exit_cleanup(ctx: &mut SyscallContext, status: u64) {
    let pid = ctx.pid;
    let memg = PROC_MEM_GROUP[pid - 1].load(Ordering::Acquire) as usize;
    if pid > 0 && pid <= MAX_PROCS {
        // CLONE_CHILD_CLEARTID: write 0 to *clear_child_tid + futex_wake
        let ctid_ptr = PROC_CLEAR_TID[pid - 1].load(Ordering::Acquire);
        if ctid_ptr != 0 {
            unsafe { core::ptr::write_volatile(ctid_ptr as *mut u32, 0); }
            futex_wake(ctid_ptr, 1);
        }
        // Free initrd file buffer pages
        for s in 0..GRP_MAX_INITRD {
            if ctx.initrd_files[s][0] != 0 {
                let buf = ctx.initrd_files[s][0];
                let sz = ctx.initrd_files[s][1];
                let pages = (sz + 0xFFF) / 0x1000;
                for p in 0..pages { let _ = sys::unmap_free(buf + p * 0x1000); }
                ctx.initrd_files[s] = [0; 4];
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
        for f in 0..GRP_MAX_FDS { ctx.child_fds[f] = 0; }
        for s in 0..GRP_MAX_VFS { ctx.vfs_files[s] = [0; 4]; }
        PROC_EXIT[pid - 1].store(status, Ordering::Release);
        PROC_STATE[pid - 1].store(2, Ordering::Release);
        // Deliver SIGCHLD to parent
        let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire) as usize;
        if ppid > 0 && ppid <= MAX_PROCS {
            sig_send(ppid, SIGCHLD as u64);
        }
    }
}

/// SYS_EXIT (60): exit current thread.
pub(crate) fn sys_exit(ctx: &mut SyscallContext, msg: &IpcMsg) -> SyscallAction {
    exit_cleanup(ctx, msg.regs[0]);
    SyscallAction::Break
}

/// SYS_EXIT_GROUP (231): exit all threads in group.
pub(crate) fn sys_exit_group(ctx: &mut SyscallContext, msg: &IpcMsg) -> SyscallAction {
    let status = msg.regs[0] as i32;
    exit_cleanup(ctx, status as u64);
    SyscallAction::Break
}
