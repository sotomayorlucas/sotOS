//! Syscall dispatcher.
//!
//! Called from the SYSCALL entry trampoline with a pointer to the
//! saved register frame. Decodes rax as the syscall number and
//! dispatches to the appropriate handler.

use crate::arch::serial;
use crate::arch::x86_64::io;
use crate::arch::x86_64::syscall::TrapFrame;
use crate::ipc::endpoint::{self, Message};
use crate::mm::{self, PhysFrame};
use crate::mm::paging::{self, AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, PAGE_NO_EXECUTE};
use crate::{irq, sched};
use sotos_common::SysError;

/// Syscall numbers — IPC.
const SYS_SEND: u64 = 1;
const SYS_RECV: u64 = 2;
const SYS_CALL: u64 = 3;
const SYS_ENDPOINT_CREATE: u64 = 10;

/// Syscall numbers — memory management.
const SYS_FRAME_ALLOC: u64 = 20;
const SYS_FRAME_FREE: u64 = 21;
const SYS_MAP: u64 = 22;
const SYS_UNMAP: u64 = 23;

/// Syscall numbers — IRQ virtualization.
const SYS_IRQ_REGISTER: u64 = 50;
const SYS_IRQ_ACK: u64 = 51;

/// Syscall numbers — I/O (temporary debug).
const SYS_PORT_IN: u64 = 60;

/// Temporary syscall number for debug serial output.
const SYS_DEBUG_PRINT: u64 = 255;

/// Upper bound of user-space virtual addresses.
const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

/// User-controllable page flags: WRITABLE (bit 1) and NO_EXECUTE (bit 63).
const USER_FLAG_MASK: u64 = PAGE_WRITABLE | PAGE_NO_EXECUTE;

/// Extract an IPC Message from the TrapFrame registers.
///
/// Register convention:
///   rsi = tag, rdx/r8/r9/r10/r12/r13/r14/r15 = msg regs 0–7
fn msg_from_frame(frame: &TrapFrame) -> Message {
    Message {
        tag: frame.rsi,
        regs: [
            frame.rdx,
            frame.r8,
            frame.r9,
            frame.r10,
            frame.r12,
            frame.r13,
            frame.r14,
            frame.r15,
        ],
    }
}

/// Write an IPC Message back into the TrapFrame registers.
fn msg_to_frame(frame: &mut TrapFrame, msg: &Message) {
    frame.rsi = msg.tag;
    frame.rdx = msg.regs[0];
    frame.r8 = msg.regs[1];
    frame.r9 = msg.regs[2];
    frame.r10 = msg.regs[3];
    frame.r12 = msg.regs[4];
    frame.r13 = msg.regs[5];
    frame.r14 = msg.regs[6];
    frame.r15 = msg.regs[7];
}

/// Main syscall dispatcher — called from assembly with IF=0.
#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut TrapFrame) {
    match frame.rax {
        // SYS_YIELD — give up remaining timeslice
        0 => {
            sched::schedule();
            frame.rax = 0;
        }

        // SYS_SEND — synchronous send on endpoint rdi
        SYS_SEND => {
            let ep_id = frame.rdi as u32;
            let msg = msg_from_frame(frame);
            match endpoint::send(ep_id, msg) {
                Ok(()) => frame.rax = 0,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_RECV — synchronous receive on endpoint rdi
        SYS_RECV => {
            let ep_id = frame.rdi as u32;
            match endpoint::recv(ep_id) {
                Ok(msg) => {
                    frame.rax = 0;
                    msg_to_frame(frame, &msg);
                }
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CALL — send then receive on endpoint rdi
        SYS_CALL => {
            let ep_id = frame.rdi as u32;
            let msg = msg_from_frame(frame);
            match endpoint::call(ep_id, msg) {
                Ok(reply) => {
                    frame.rax = 0;
                    msg_to_frame(frame, &reply);
                }
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_ENDPOINT_CREATE — create a new IPC endpoint
        SYS_ENDPOINT_CREATE => {
            match endpoint::create() {
                Some(ep) => frame.rax = ep.0 as u64,
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

        // SYS_FRAME_ALLOC — allocate a physical frame
        SYS_FRAME_ALLOC => {
            match mm::alloc_frame() {
                Some(f) => frame.rax = f.addr(),
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

        // SYS_FRAME_FREE — free a physical frame
        SYS_FRAME_FREE => {
            let paddr = frame.rdi;
            if paddr & 0xFFF != 0 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                mm::free_frame(PhysFrame::from_addr(paddr));
                frame.rax = 0;
            }
        }

        // SYS_MAP — map a frame into the caller's address space
        SYS_MAP => {
            let vaddr = frame.rdi;
            let paddr = frame.rsi;
            let user_flags = frame.rdx;

            if vaddr & 0xFFF != 0 || paddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Build leaf flags: force PRESENT | USER, allow user WRITABLE | NO_EXECUTE.
                let flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                let cr3 = paging::read_cr3();
                let aspace = AddressSpace::from_cr3(cr3);
                aspace.map_page(vaddr, paddr, flags);
                paging::invlpg(vaddr);
                frame.rax = 0;
            }
        }

        // SYS_UNMAP — unmap a page from the caller's address space
        SYS_UNMAP => {
            let vaddr = frame.rdi;
            if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                let cr3 = paging::read_cr3();
                let aspace = AddressSpace::from_cr3(cr3);
                if aspace.unmap_page(vaddr) {
                    paging::invlpg(vaddr);
                    frame.rax = 0;
                } else {
                    frame.rax = SysError::NotFound as i64 as u64;
                }
            }
        }

        // SYS_IRQ_REGISTER — bind current thread to an IRQ line
        SYS_IRQ_REGISTER => {
            match irq::register(frame.rdi as u8) {
                Ok(()) => frame.rax = 0,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_IRQ_ACK — acknowledge IRQ, unmask, block until next
        SYS_IRQ_ACK => {
            match irq::ack_and_wait(frame.rdi as u8) {
                Ok(()) => frame.rax = 0,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_PORT_IN — read a byte from an I/O port (temporary debug)
        SYS_PORT_IN => {
            let val = unsafe { io::inb(frame.rdi as u16) };
            frame.rax = val as u64;
        }

        // SYS_DEBUG_PRINT — write a single byte to serial (temporary)
        SYS_DEBUG_PRINT => {
            serial::write_byte(frame.rdi as u8);
            frame.rax = 0;
        }

        // Unknown syscall
        _ => {
            frame.rax = SysError::InvalidArg as i64 as u64;
        }
    }
}
