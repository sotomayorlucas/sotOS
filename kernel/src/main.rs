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
mod irq;
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

/// Create the user address space and spawn two threads for IPC testing.
///
/// - Sender at 0x400000: prints "INIT\n", sends IPC message, prints "OK\n"
/// - Receiver at 0x401000: receives IPC message, prints "IPC!\n"
/// - Both share one address space and one IPC endpoint (ep 0).
/// - Receiver spawned first so it blocks on Recv before sender runs.
fn spawn_init_process() {
    use mm::paging::{AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE};

    let addr_space = AddressSpace::new_user();
    let hhdm = mm::hhdm_offset();
    let cr3 = addr_space.cr3();

    // --- Copy sender code to 0x400000 ---
    let sender_code = user_init::init_code();
    let sender_frame = mm::alloc_frame().expect("no frame for sender code");
    let sender_phys = sender_frame.addr();
    unsafe {
        core::ptr::write_bytes((sender_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            sender_code.as_ptr(),
            (sender_phys + hhdm) as *mut u8,
            sender_code.len(),
        );
    }
    let sender_addr: u64 = 0x400000;
    addr_space.map_page(sender_addr, sender_phys, PAGE_PRESENT | PAGE_USER);

    // --- Copy receiver code to 0x401000 ---
    let recv_code = user_init::recv_code();
    let recv_frame = mm::alloc_frame().expect("no frame for receiver code");
    let recv_phys = recv_frame.addr();
    unsafe {
        core::ptr::write_bytes((recv_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            recv_code.as_ptr(),
            (recv_phys + hhdm) as *mut u8,
            recv_code.len(),
        );
    }
    let recv_addr: u64 = 0x401000;
    addr_space.map_page(recv_addr, recv_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate sender stack at 0x800000 ---
    let stack1_frame = mm::alloc_frame().expect("no frame for sender stack");
    let stack1_phys = stack1_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack1_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack1_base: u64 = 0x800000;
    addr_space.map_page(stack1_base, stack1_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack1_top = stack1_base + 0x1000;

    // --- Allocate receiver stack at 0x802000 ---
    let stack2_frame = mm::alloc_frame().expect("no frame for receiver stack");
    let stack2_phys = stack2_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack2_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack2_base: u64 = 0x802000;
    addr_space.map_page(stack2_base, stack2_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack2_top = stack2_base + 0x1000;

    // --- Create IPC endpoint 0 ---
    let ep = ipc::endpoint::create().expect("failed to create endpoint");
    kprintln!("  ipc: endpoint {} created", ep.0);

    kprintln!(
        "  init: receiver @ {:#x}, sender @ {:#x}, cr3 = {:#x}",
        recv_addr, sender_addr, cr3
    );

    // --- Copy keyboard driver code to 0x402000 ---
    let kb_code = user_init::kb_code();
    let kb_frame = mm::alloc_frame().expect("no frame for kb code");
    let kb_phys = kb_frame.addr();
    unsafe {
        core::ptr::write_bytes((kb_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            kb_code.as_ptr(),
            (kb_phys + hhdm) as *mut u8,
            kb_code.len(),
        );
    }
    let kb_addr: u64 = 0x402000;
    addr_space.map_page(kb_addr, kb_phys, PAGE_PRESENT | PAGE_USER);

    // --- Allocate keyboard driver stack at 0x804000 ---
    let stack3_frame = mm::alloc_frame().expect("no frame for kb stack");
    let stack3_phys = stack3_frame.addr();
    unsafe {
        core::ptr::write_bytes((stack3_phys + hhdm) as *mut u8, 0, 4096);
    }
    let stack3_base: u64 = 0x804000;
    addr_space.map_page(stack3_base, stack3_phys, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    let stack3_top = stack3_base + 0x1000;

    // Spawn receiver FIRST — it will block on Recv(ep 0), then sender runs.
    // Keyboard driver spawned last — it registers for IRQ 1 and blocks.
    sched::spawn_user(recv_addr, stack2_top, cr3);
    sched::spawn_user(sender_addr, stack1_top, cr3);
    sched::spawn_user(kb_addr, stack3_top, cr3);
}
