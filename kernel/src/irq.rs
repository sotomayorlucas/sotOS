//! IRQ virtualization — notification-based binding for userspace drivers.
//!
//! Maps hardware IRQ lines to notification objects. When an IRQ fires,
//! the kernel signals the bound notification; the driver calls
//! `NOTIFY_WAIT` to block and `IRQ_ACK` to unmask the line.
//!
//! Lock ordering: IRQ_TABLE dropped before calling ipc::notify (which
//! acquires NOTIFICATIONS then SCHEDULER).

use crate::arch::x86_64::pic;
use crate::ipc::notify;
use crate::pool::PoolHandle;
use sotos_common::SysError;
use spin::Mutex;

/// Maximum IRQ lines managed (8259 PIC: 0-15).
const MAX_IRQ: usize = 16;

/// Per-IRQ binding: maps an IRQ line to a notification object.
#[derive(Clone, Copy)]
struct IrqBinding {
    /// Bound notification handle (None = unbound).
    notify_handle: Option<PoolHandle>,
}

impl IrqBinding {
    const fn empty() -> Self {
        Self { notify_handle: None }
    }
}

static IRQ_TABLE: Mutex<[IrqBinding; MAX_IRQ]> = Mutex::new([IrqBinding::empty(); MAX_IRQ]);

/// Bind an IRQ line to a notification object and unmask the line.
///
/// Rejects IRQ 0 (kernel timer) and already-bound lines.
pub fn register(irq: u8, notify_handle: PoolHandle) -> Result<(), SysError> {
    if irq == 0 || irq as usize >= MAX_IRQ {
        return Err(SysError::InvalidArg);
    }

    let mut table = IRQ_TABLE.lock();
    let entry = &mut table[irq as usize];

    if entry.notify_handle.is_some() {
        return Err(SysError::OutOfResources);
    }

    entry.notify_handle = Some(notify_handle);
    pic::unmask(irq);
    Ok(())
}

/// Acknowledge an IRQ by unmasking the line. Does not block.
///
/// The driver blocks separately via `SYS_NOTIFY_WAIT`.
pub fn ack(irq: u8) -> Result<(), SysError> {
    if irq as usize >= MAX_IRQ {
        return Err(SysError::InvalidArg);
    }

    pic::unmask(irq);
    Ok(())
}

/// Called from IDT interrupt handler (IF=0). Signals the bound
/// notification object if one exists.
///
/// The IRQ line is already masked by the IDT handler before calling this.
pub fn notify(irq: u8) {
    if irq as usize >= MAX_IRQ {
        return;
    }

    let notify_handle = {
        let table = IRQ_TABLE.lock();
        table[irq as usize].notify_handle
    };
    // IRQ_TABLE lock dropped — safe to call into notify subsystem.

    if let Some(handle) = notify_handle {
        let _ = notify::signal(handle);
    }
}
