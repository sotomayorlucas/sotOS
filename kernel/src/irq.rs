//! IRQ virtualization — binding table for userspace driver threads.
//!
//! Maps hardware IRQ lines to handler threads. The kernel masks the IRQ
//! on entry and wakes the handler; the handler processes the device and
//! calls `ack_and_wait()` to unmask and block for the next interrupt.

use crate::arch::x86_64::pic;
use crate::sched::{self, ThreadId};
use sotos_common::SysError;
use spin::Mutex;

/// Maximum IRQ lines managed (8259 PIC: 0-15).
const MAX_IRQ: usize = 16;

/// Per-IRQ binding state.
#[derive(Clone, Copy)]
struct IrqBinding {
    /// Thread registered to handle this IRQ (None = unbound).
    handler_tid: Option<ThreadId>,
    /// Thread currently blocked in ack_and_wait (None = not waiting).
    waiting_tid: Option<ThreadId>,
    /// IRQ fired while handler wasn't waiting yet.
    pending: bool,
}

impl IrqBinding {
    const fn empty() -> Self {
        Self {
            handler_tid: None,
            waiting_tid: None,
            pending: false,
        }
    }
}

static IRQ_TABLE: Mutex<[IrqBinding; MAX_IRQ]> = Mutex::new([IrqBinding::empty(); MAX_IRQ]);

/// Register the current thread as the handler for `irq`.
///
/// Called from SYS_IRQ_REGISTER. Rejects IRQ 0 (kernel timer) and
/// already-bound lines.
pub fn register(irq: u8) -> Result<(), SysError> {
    let tid = sched::current_tid().ok_or(SysError::InvalidArg)?;

    if irq == 0 || irq as usize >= MAX_IRQ {
        return Err(SysError::InvalidArg);
    }

    let mut table = IRQ_TABLE.lock();
    let entry = &mut table[irq as usize];

    if entry.handler_tid.is_some() {
        return Err(SysError::OutOfResources);
    }

    entry.handler_tid = Some(tid);
    entry.pending = false;
    entry.waiting_tid = None;

    pic::unmask(irq);
    Ok(())
}

/// Acknowledge the previous IRQ, unmask the line, and block until
/// the next one fires. Returns immediately if an IRQ is already pending.
///
/// Called from SYS_IRQ_ACK.
pub fn ack_and_wait(irq: u8) -> Result<(), SysError> {
    let tid = sched::current_tid().ok_or(SysError::InvalidArg)?;

    if irq as usize >= MAX_IRQ {
        return Err(SysError::InvalidArg);
    }

    // Check binding and pending state, then decide whether to block.
    let should_block = {
        let mut table = IRQ_TABLE.lock();
        let entry = &mut table[irq as usize];

        // Only the registered handler may ack.
        match entry.handler_tid {
            Some(h) if h == tid => {}
            _ => return Err(SysError::NoRights),
        }

        if entry.pending {
            // IRQ already fired — consume it, unmask, return immediately.
            entry.pending = false;
            pic::unmask(irq);
            false
        } else {
            // No pending IRQ — unmask and prepare to block.
            entry.waiting_tid = Some(tid);
            pic::unmask(irq);
            true
        }
    };
    // IRQ_TABLE lock dropped here.

    if should_block {
        sched::block_current();
    }

    Ok(())
}

/// Called from IDT interrupt handler (IF=0). Sets pending flag and
/// wakes the handler thread if it's blocked in ack_and_wait.
///
/// The IRQ line is already masked by the IDT handler before calling this.
pub fn notify(irq: u8) {
    if irq as usize >= MAX_IRQ {
        return;
    }

    let wake_tid = {
        let mut table = IRQ_TABLE.lock();
        let entry = &mut table[irq as usize];

        if entry.handler_tid.is_none() {
            // Unbound IRQ — ignore (spurious or unregistered).
            return;
        }

        entry.pending = true;
        entry.waiting_tid.take()
    };
    // IRQ_TABLE lock dropped here — safe to acquire SCHEDULER.

    if let Some(tid) = wake_tid {
        sched::wake(tid);
    }
}
