use crate::kprintln;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("!!! KERNEL PANIC !!!");
    kprintln!("{}", info);
    crate::arch::halt_loop()
}
