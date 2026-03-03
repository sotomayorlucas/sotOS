//! Interrupt Descriptor Table setup.
//!
//! Registers CPU exception handlers and hardware interrupt handlers.

use crate::kprintln;
use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use super::gdt::DOUBLE_FAULT_IST_INDEX;
use super::pic;

/// Timer interrupt vector (IRQ0 after PIC remap).
pub const TIMER_VECTOR: u8 = 32;

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    idt.breakpoint.set_handler_fn(breakpoint_handler);

    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }

    idt.general_protection_fault
        .set_handler_fn(general_protection_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);

    idt[TIMER_VECTOR].set_handler_fn(timer_handler);

    idt
});

pub fn init() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(frame: InterruptStackFrame) {
    kprintln!("EXCEPTION: breakpoint\n{:#?}", frame);
}

extern "x86-interrupt" fn double_fault_handler(frame: InterruptStackFrame, _code: u64) -> ! {
    panic!("EXCEPTION: double fault\n{:#?}", frame);
}

extern "x86-interrupt" fn general_protection_handler(frame: InterruptStackFrame, code: u64) {
    panic!("EXCEPTION: general protection fault (code {})\n{:#?}", code, frame);
}

extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    code: x86_64::structures::idt::PageFaultErrorCode,
) {
    kprintln!("EXCEPTION: page fault");
    kprintln!("Error code: {:?}", code);
    kprintln!("{:#?}", frame);
    crate::arch::halt_loop();
}

extern "x86-interrupt" fn timer_handler(_frame: InterruptStackFrame) {
    pic::send_eoi(0);
    crate::sched::tick();
}
