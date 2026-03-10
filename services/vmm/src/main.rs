//! sotOS VMM (Virtual Memory Manager) Service Process
//!
//! Handles page faults for the init process and CoW-cloned child address
//! spaces by allocating frames and mapping them.
//!
//! Runs as a separate process with its own CR3.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

/// Root capability indices (must match kernel write_vmm_boot_info() order).
const CAP_NOTIFY: usize = 0;  // Notification (fault delivery)
const CAP_INIT_AS: usize = 1; // AddrSpace cap for init's CR3

/// WRITABLE flag for map_into syscall (bit 1).
const MAP_WRITABLE: u64 = 2;

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"VMM: invalid BootInfo!\n");
        loop { sys::yield_now(); }
    }

    let notify_cap = boot_info.caps[CAP_NOTIFY];
    let init_as_cap = boot_info.caps[CAP_INIT_AS];

    // Register for page faults in init's address space.
    sys::fault_register_as(notify_cap, init_as_cap).unwrap_or_else(|_| {
        print(b"VMM: fault_register_as failed!\n");
        loop { sys::yield_now(); }
    });

    // Also register as global fallback handler (cr3=0) to catch faults
    // from CoW-cloned child address spaces created by fork.
    sys::fault_register(notify_cap).unwrap_or_else(|_| {
        print(b"VMM: global fault_register failed!\n");
        loop { sys::yield_now(); }
    });

    print(b"VMM: registered for init + global faults\n");

    // Track last fault per thread to detect infinite loops.
    // [tid % 16] -> (last_addr, repeat_count)
    let mut fault_track: [(u64, u32); 16] = [(0, 0); 16];

    // Fault handling loop.
    loop {
        sys::notify_wait(notify_cap);
        loop {
            match sys::fault_recv() {
                Ok(fault) => {
                    let vaddr_raw = fault.addr & !0xFFF;
                    let code = fault.code;
                    let slot = (fault.tid as usize) % 16;

                    // Use the AS cap delivered with the fault.
                    // The kernel resolves cr3 → as_cap_id via register_cr3_cap().
                    // Fall back to init_as_cap if no specific cap was registered.
                    let target_as_cap = if fault.as_cap_id != 0 {
                        fault.as_cap_id
                    } else {
                        init_as_cap
                    };

                    // Guard: NX violation (instruction fetch on NX page).
                    // Mapping a new writable frame would get NX again (W^X) -> infinite loop.
                    if code & 0x11 == 0x11 {
                        continue; // leave thread suspended
                    }

                    // Guard: Infinite loop detection (same address > 4 times).
                    if fault_track[slot].0 == vaddr_raw {
                        fault_track[slot].1 += 1;
                        if fault_track[slot].1 > 4 {
                            continue; // leave thread suspended
                        }
                    } else {
                        fault_track[slot] = (vaddr_raw, 1);
                    }

                    // Check for CoW fault: write (bit 1) to present (bit 0) page.
                    if code & 0x03 == 0x03 {
                        // CoW fault: page is present but read-only due to clone_cow.
                        // 1. Allocate a new frame
                        let new_frame = sys::frame_alloc().unwrap_or_else(|_| {
                            print(b"VMM: OOM(CoW)\n");
                            loop { sys::yield_now(); }
                        });
                        // 2. Copy 4KiB from the old frame to the new frame
                        //    (kernel copies via HHDM using SYS_FRAME_COPY)
                        if let Err(_) = sys::frame_copy(new_frame, target_as_cap, vaddr_raw) {
                            print(b"VMM: frame_copy failed\n");
                            // Fall through to demand-page as fallback
                        }
                        // 3. Unmap old PTE
                        let _ = sys::unmap_from(target_as_cap, vaddr_raw);
                        // 4. Map new frame as WRITABLE
                        sys::map_into(target_as_cap, vaddr_raw, new_frame, MAP_WRITABLE).unwrap_or_else(|_| {
                            print(b"VMM: map_into(CoW) failed!\n");
                            loop { sys::yield_now(); }
                        });
                        // 5. Resume thread
                        sys::thread_resume(fault.tid as u64).unwrap_or_else(|_| {
                            print(b"VMM: resume(CoW) failed!\n");
                            loop { sys::yield_now(); }
                        });
                        continue;
                    }

                    // Demand paging: page not present — allocate new frame.
                    let frame = sys::frame_alloc().unwrap_or_else(|_| {
                        print(b"VMM: OOM\n");
                        loop { sys::yield_now(); }
                    });
                    sys::map_into(target_as_cap, vaddr_raw, frame, MAP_WRITABLE).unwrap_or_else(|_| {
                        print(b"VMM: map_into failed!\n");
                        loop { sys::yield_now(); }
                    });
                    sys::thread_resume(fault.tid as u64).unwrap_or_else(|_| {
                        print(b"VMM: thread_resume failed!\n");
                        loop { sys::yield_now(); }
                    });
                }
                Err(_) => break,
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"VMM PANIC\n");
    loop { sys::yield_now(); }
}
