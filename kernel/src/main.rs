//! sotOS Microkernel
//!
//! A formally-verifiable microkernel implementing five primitives:
//! - Thread scheduling (preemptive with delegation)
//! - IRQ virtualization to userspace
//! - IPC (register-based + shared memory channels)
//! - Capability management (creation, delegation, revocation)
//! - Physical frame allocation (no virtual memory — that's userspace)

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod arch;
mod cap;
mod ipc;
mod mm;
mod panic;
mod sched;
mod syscall;
mod user_init;

use limine::BaseRevision;
use limine::request::{HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker};

#[used]
#[link_section = ".requests_start_marker"]
static _REQUESTS_START: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".requests_end_marker"]
static _REQUESTS_END: RequestsEndMarker = RequestsEndMarker::new();

/// Limine base revision — ensures bootloader compatibility.
#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

/// Request the Higher Half Direct Map offset.
/// All physical memory is identity-mapped at this offset.
#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

/// Request the physical memory map from the bootloader.
#[used]
#[link_section = ".requests"]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

/// Kernel entry point — called by the Limine bootloader.
#[no_mangle]
extern "C" fn kmain() -> ! {
    // Serial MUST be first — we need debug output before anything else.
    arch::serial::init();
    kprintln!("sotOS v0.1.0 — microkernel booting...");

    if !BASE_REVISION.is_supported() {
        kprintln!("FATAL: Limine base revision not supported");
        arch::halt_loop();
    }

    // CPU structures.
    arch::gdt::init();
    kprintln!("[ok] GDT");

    arch::idt::init();
    kprintln!("[ok] IDT");

    // Physical frame allocator from bootloader memory map.
    let mmap_response = MEMORY_MAP_REQUEST
        .get_response()
        .expect("bootloader: no memory map");
    let hhdm_response = HHDM_REQUEST
        .get_response()
        .expect("bootloader: no HHDM");

    mm::init(mmap_response, hhdm_response.offset());
    kprintln!("[ok] Frame allocator");

    // Save boot CR3 before any address space changes.
    mm::paging::init_boot_cr3();

    // Capability system.
    cap::init();
    kprintln!("[ok] Capabilities");

    // Scheduler.
    sched::init();
    kprintln!("[ok] Scheduler");

    // SYSCALL/SYSRET MSRs.
    arch::syscall::init();
    kprintln!("[ok] SYSCALL/SYSRET");

    // Hardware interrupts.
    arch::pic::init();
    kprintln!("[ok] PIC");

    arch::pit::init();
    kprintln!("[ok] PIT");

    // Spawn init process (first userspace code).
    spawn_init_process();
    kprintln!("[ok] Init process");

    // Enable timer IRQ and interrupts.
    arch::pic::unmask(0);
    x86_64::instructions::interrupts::enable();
    kprintln!("Kernel ready — entering idle loop");

    // Idle loop (thread 0). Timer interrupts cause preemptive switching.
    loop {
        x86_64::instructions::hlt();
    }
}

/// Create the user address space and spawn the init process.
fn spawn_init_process() {
    use mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let addr_space = AddressSpace::new_user();

    // Copy init code into a user-accessible page.
    let code = user_init::init_code();
    let code_frame = mm::alloc_frame().expect("no frame for init code");
    let code_phys = code_frame.addr();
    let code_virt_hhdm = code_phys + mm::hhdm_offset();
    unsafe {
        // Zero the page first, then copy code.
        core::ptr::write_bytes(code_virt_hhdm as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(code.as_ptr(), code_virt_hhdm as *mut u8, code.len());
    }

    // Map code at 0x400000 (user, present, not writable).
    let user_code_addr: u64 = 0x400000;
    addr_space.map_page(user_code_addr, code_phys, PAGE_PRESENT | PAGE_USER);

    // Allocate and map a user stack page at 0x800000.
    let stack_frame = mm::alloc_frame().expect("no frame for init stack");
    let stack_phys = stack_frame.addr();
    // Zero the stack page.
    unsafe {
        core::ptr::write_bytes((stack_phys + mm::hhdm_offset()) as *mut u8, 0, 4096);
    }

    let user_stack_base: u64 = 0x800000;
    addr_space.map_page(
        user_stack_base,
        stack_phys,
        PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER,
    );

    // Stack grows downward — top is base + 4 KiB.
    let user_stack_top = user_stack_base + 0x1000;

    kprintln!(
        "  init: code @ {:#x}, stack @ {:#x}, cr3 = {:#x}",
        user_code_addr,
        user_stack_top,
        addr_space.cr3()
    );

    sched::spawn_user(user_code_addr, user_stack_top, addr_space.cr3());
}
