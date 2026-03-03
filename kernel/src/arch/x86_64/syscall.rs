//! SYSCALL/SYSRET setup and entry/exit assembly.
//!
//! Programs the four MSRs (EFER, STAR, LSTAR, FMASK) and provides
//! the syscall_entry trampoline that saves/restores user state.

use super::gdt;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::SegmentSelector;
use x86_64::VirtAddr;

// ---------------------------------------------------------------------------
// Per-CPU globals (single-core, accessed only with IF=0)
// ---------------------------------------------------------------------------

/// Kernel RSP loaded on SYSCALL entry. Set by the scheduler on every
/// context switch to the current thread's kernel_stack_top.
#[no_mangle]
static mut KERNEL_STACK_TOP: u64 = 0;

/// Scratch space to save the user RSP across a syscall.
#[no_mangle]
static mut USER_RSP_SAVE: u64 = 0;

/// Set the kernel stack pointer used by SYSCALL entry.
///
/// # Safety
/// Must be called with interrupts disabled, single-core.
#[allow(static_mut_refs)]
pub unsafe fn set_kernel_stack_top(rsp0: u64) {
    unsafe {
        KERNEL_STACK_TOP = rsp0;
    }
}

// ---------------------------------------------------------------------------
// Trap frame — matches the push/pop order in syscall_entry
// ---------------------------------------------------------------------------

/// Saved register state pushed by syscall_entry.
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub rax: u64, // syscall number / return value
    pub rbx: u64,
    pub rcx: u64, // user RIP (saved by CPU on SYSCALL)
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64, // arg0
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64, // user RFLAGS (saved by CPU on SYSCALL)
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

// ---------------------------------------------------------------------------
// SYSCALL entry/exit assembly
// ---------------------------------------------------------------------------

core::arch::global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // CPU did: RCX = user RIP, R11 = user RFLAGS, CS/SS = kernel
    // IF=0 (FMASK cleared it). Single-core, safe to use globals.

    // Save user RSP, switch to kernel stack
    "    mov [rip + USER_RSP_SAVE], rsp",
    "    mov rsp, [rip + KERNEL_STACK_TOP]",

    // Push trap frame (matches TrapFrame struct, low-to-high)
    "    push r15",
    "    push r14",
    "    push r13",
    "    push r12",
    "    push r11", // user RFLAGS
    "    push r10",
    "    push r9",
    "    push r8",
    "    push rbp",
    "    push rdi", // arg0
    "    push rsi",
    "    push rdx",
    "    push rcx", // user RIP
    "    push rbx",
    "    push rax", // syscall number

    // Call Rust dispatcher: syscall_dispatch(&mut TrapFrame)
    "    mov rdi, rsp",
    "    call syscall_dispatch",

    // Pop trap frame
    "    pop rax",
    "    pop rbx",
    "    pop rcx",
    "    pop rdx",
    "    pop rsi",
    "    pop rdi",
    "    pop rbp",
    "    pop r8",
    "    pop r9",
    "    pop r10",
    "    pop r11",
    "    pop r12",
    "    pop r13",
    "    pop r14",
    "    pop r15",

    // Restore user RSP and return to Ring 3
    "    mov rsp, [rip + USER_RSP_SAVE]",
    "    sysretq",
);

// ---------------------------------------------------------------------------
// MSR initialization
// ---------------------------------------------------------------------------

extern "C" {
    fn syscall_entry();
}

/// Program SYSCALL/SYSRET MSRs. Call once during boot, after GDT init.
pub fn init() {
    // Enable SYSCALL/SYSRET in EFER.
    unsafe {
        Efer::update(|flags| {
            *flags |= EferFlags::SYSTEM_CALL_EXTENSIONS;
        });
    }

    // STAR: segment selectors for SYSCALL (kernel) and SYSRET (user).
    //
    // SYSRET: CS = STAR[63:48]+16, SS = STAR[63:48]+8
    //   We want CS=0x20|3=0x23 (User Code), SS=0x18|3=0x1B (User Data)
    //   So STAR[63:48] = 0x1B-8 = 0x13  →  0x13+16=0x23 ✓, 0x13+8=0x1B ✓
    //
    // SYSCALL: CS = STAR[47:32], SS = STAR[47:32]+8
    //   We want CS=0x08 (Kernel Code), SS=0x10 (Kernel Data)
    //   So STAR[47:32] = 0x08  →  0x08+8=0x10 ✓
    Star::write(
        SegmentSelector(gdt::USER_CS),  // cs_sysret  = 0x23
        SegmentSelector(gdt::USER_DS),  // ss_sysret  = 0x1B
        SegmentSelector(gdt::KERNEL_CS), // cs_syscall = 0x08
        SegmentSelector(gdt::KERNEL_DS), // ss_syscall = 0x10
    )
    .expect("STAR segment selector validation failed");

    // LSTAR: RIP target for SYSCALL.
    LStar::write(VirtAddr::new(syscall_entry as *const () as u64));

    // FMASK: clear IF on SYSCALL entry (disable interrupts).
    SFMask::write(RFlags::INTERRUPT_FLAG);
}
