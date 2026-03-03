//! Fault queue — forwards user page faults to the VMM server.
//!
//! The kernel pushes `FaultInfo` entries and signals a notification.
//! The VMM server drains the queue via `SYS_FAULT_RECV`.
//!
//! Lock ordering: FAULT_STATE → drop → NOTIFICATIONS → drop → SCHEDULER

use alloc::collections::VecDeque;
use spin::Mutex;

use crate::ipc::notify;
use crate::pool::PoolHandle;

/// Information about a user-mode page fault.
pub struct FaultInfo {
    pub tid: u32,
    pub addr: u64,
    pub code: u64,
}

struct FaultState {
    notify_handle: Option<PoolHandle>,
    queue: VecDeque<FaultInfo>,
}

static FAULT_STATE: Mutex<FaultState> = Mutex::new(FaultState {
    notify_handle: None,
    queue: VecDeque::new(),
});

/// Register the notification object used to wake the VMM on faults.
pub fn register(notify_handle: PoolHandle) {
    let mut state = FAULT_STATE.lock();
    state.notify_handle = Some(notify_handle);
}

/// Push a fault onto the queue and signal the VMM.
/// Returns `false` if no VMM is registered (caller should kill the thread).
pub fn push_fault(tid: u32, addr: u64, code: u64) -> bool {
    let notify_handle = {
        let mut state = FAULT_STATE.lock();
        let handle = match state.notify_handle {
            Some(h) => h,
            None => return false,
        };
        state.queue.push_back(FaultInfo { tid, addr, code });
        handle
    };
    // FAULT_STATE dropped — safe to call into notify (which acquires NOTIFICATIONS).
    let _ = notify::signal(notify_handle);
    true
}

/// Pop the next fault from the queue (called by VMM via SYS_FAULT_RECV).
pub fn pop_fault() -> Option<FaultInfo> {
    let mut state = FAULT_STATE.lock();
    state.queue.pop_front()
}
