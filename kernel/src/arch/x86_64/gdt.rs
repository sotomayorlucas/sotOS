//! Global Descriptor Table setup.
//!
//! GDT layout for SYSRET compatibility:
//!   0x00 — Null
//!   0x08 — Kernel Code 64 (DPL=0)
//!   0x10 — Kernel Data    (DPL=0)
//!   0x18 — User Data      (DPL=3)
//!   0x20 — User Code 64   (DPL=3)
//!   0x28 — TSS            (16-byte descriptor)
//!
//! SYSRET requires User Data immediately before User Code.

use core::cell::UnsafeCell;
use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

// ---------------------------------------------------------------------------
// Selector constants (including RPL bits)
// ---------------------------------------------------------------------------

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
/// User data selector — 0x18 | RPL 3.
pub const USER_DS: u16 = 0x1B;
/// User code selector — 0x20 | RPL 3.
pub const USER_CS: u16 = 0x23;

// ---------------------------------------------------------------------------
// IST / Double-fault stack
// ---------------------------------------------------------------------------

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

#[repr(align(16))]
struct DoubleFaultStack([u8; 4096 * 5]);
static DOUBLE_FAULT_STACK: DoubleFaultStack = DoubleFaultStack([0; 4096 * 5]);

// ---------------------------------------------------------------------------
// TSS — mutable for rsp0 updates on context switch
// ---------------------------------------------------------------------------

#[repr(align(16))]
struct TssStorage(UnsafeCell<TaskStateSegment>);
unsafe impl Sync for TssStorage {}

static TSS_STORAGE: TssStorage = TssStorage(UnsafeCell::new(TaskStateSegment::new()));

fn tss() -> &'static TaskStateSegment {
    unsafe { &*TSS_STORAGE.0.get() }
}

/// Set TSS.privilege_stack_table[0] (RSP0) — the stack used by the CPU
/// when an interrupt arrives while in Ring 3.
///
/// # Safety
/// Must be called with interrupts disabled, single-core.
pub unsafe fn set_tss_rsp0(rsp0: u64) {
    unsafe {
        (*TSS_STORAGE.0.get()).privilege_stack_table[0] = VirtAddr::new(rsp0);
    }
}

// ---------------------------------------------------------------------------
// GDT
// ---------------------------------------------------------------------------

struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    #[allow(dead_code)]
    user_data: SegmentSelector,
    #[allow(dead_code)]
    user_code: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    // Set up the double-fault IST entry before the GDT captures a reference
    // to the TSS. (Lazy init runs exactly once, before GDT.0.load().)
    unsafe {
        (*TSS_STORAGE.0.get()).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            let stack_start = VirtAddr::from_ptr(&DOUBLE_FAULT_STACK);
            let stack_size = core::mem::size_of::<DoubleFaultStack>() as u64;
            stack_start + stack_size
        };
    }

    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment()); // 0x08
    let data = gdt.append(Descriptor::kernel_data_segment()); // 0x10
    let user_data = gdt.append(Descriptor::user_data_segment()); // 0x18
    let user_code = gdt.append(Descriptor::user_code_segment()); // 0x20
    let tss = gdt.append(Descriptor::tss_segment(tss())); // 0x28

    (
        gdt,
        Selectors {
            code,
            data,
            user_data,
            user_code,
            tss,
        },
    )
});

pub fn init() {
    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code);
        SS::set_reg(GDT.1.data);
        DS::set_reg(GDT.1.data);
        ES::set_reg(GDT.1.data);
        load_tss(GDT.1.tss);
    }
}
