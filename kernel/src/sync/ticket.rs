//! Ticket spinlock — FIFO ordering prevents starvation.
//!
//! Each `lock()` draws an incrementing ticket number. The lock holder
//! advances `now_serving` when it unlocks, granting access to the next
//! waiter in order. This is fairer than a simple test-and-set spinlock
//! under contention.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

pub struct TicketMutex<T> {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for TicketMutex<T> {}
unsafe impl<T: Send> Sync for TicketMutex<T> {}

impl<T> TicketMutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> TicketGuard<'_, T> {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        TicketGuard { lock: self }
    }

    pub fn try_lock(&self) -> Option<TicketGuard<'_, T>> {
        let current = self.now_serving.load(Ordering::Relaxed);
        if self
            .next_ticket
            .compare_exchange(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(TicketGuard { lock: self })
        } else {
            None
        }
    }
}

pub struct TicketGuard<'a, T> {
    lock: &'a TicketMutex<T>,
}

impl<T> Deref for TicketGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for TicketGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for TicketGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.now_serving.fetch_add(1, Ordering::Release);
    }
}
