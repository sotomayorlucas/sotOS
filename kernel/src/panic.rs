use crate::kprintln;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts immediately to prevent further scheduling on this CPU.
    x86_64::instructions::interrupts::disable();

    let cpu_index = crate::arch::percpu::current_percpu().cpu_index;
    kprintln!("!!! KERNEL PANIC (CPU {}) !!!", cpu_index);
    kprintln!("{}", info);
    crate::arch::halt_loop()
}
