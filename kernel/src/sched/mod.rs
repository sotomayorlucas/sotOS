//! Scheduler — Preemptive Round-Robin.
//!
//! **Level 1 (kernel)**: Preemptive, priority-based with deadline awareness.
//! Currently implements simple round-robin as the foundation.
//!
//! **Level 2 (userspace)**: Scheduling Domains (future).

pub mod thread;

pub use thread::{IpcRole, ThreadId, ThreadState};
use thread::{Thread, MAX_THREADS};

use crate::ipc::endpoint::Message;

use crate::kprintln;
use spin::Mutex;

/// Timeslice in ticks (100 ms at 100 Hz).
const TIMESLICE: u32 = 10;

// ---------------------------------------------------------------------------
// Context switch — assembly trampoline
// ---------------------------------------------------------------------------

extern "C" {
    /// Switch CPU context from the current thread to a new thread.
    ///
    /// Saves callee-saved registers on the current stack, stores RSP into
    /// `*old_rsp_ptr`, loads RSP from `new_rsp`, restores callee-saved regs,
    /// and returns (into the new thread's continuation point).
    fn context_switch(old_rsp_ptr: *mut u64, new_rsp: u64);
}

core::arch::global_asm!(
    ".global context_switch",
    "context_switch:",
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rdi], rsp",    // save old RSP
    "    mov rsp, rsi",      // load new RSP
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
);

// ---------------------------------------------------------------------------
// Thread trampolines
// ---------------------------------------------------------------------------

/// Trampoline for kernel threads. Enables interrupts and jumps to entry.
#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "sti",
        "jmp r12",
    );
}

/// Trampoline for user threads. Switches to user address space and
/// enters Ring 3 via sysretq.
///
/// Registers from initial stack frame:
///   r12 = user RIP, r13 = user RSP, r14 = CR3
#[unsafe(naked)]
unsafe extern "C" fn user_thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "mov cr3, r14",         // switch to user address space
        "mov rcx, r12",         // user RIP → RCX for sysretq
        "mov r11, 0x202",       // user RFLAGS (IF=1) → R11 for sysretq
        "mov rsp, r13",         // user RSP
        "sysretq",              // enter Ring 3
    );
}

// ---------------------------------------------------------------------------
// Scheduler state
// ---------------------------------------------------------------------------

struct Scheduler {
    threads: [Thread; MAX_THREADS],
    /// Circular run queue (indices into `threads`).
    run_queue: [usize; MAX_THREADS],
    rq_head: usize,
    rq_tail: usize,
    rq_len: usize,
    /// Index of the currently running thread in `threads` (None before first schedule).
    current: Option<usize>,
    next_id: u32,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: {
                let empty = Thread::empty();
                [
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                    empty, empty, empty, empty, empty, empty, empty, empty,
                ]
            },
            run_queue: [0; MAX_THREADS],
            rq_head: 0,
            rq_tail: 0,
            rq_len: 0,
            current: None,
            next_id: 0,
        }
    }

    fn enqueue(&mut self, idx: usize) {
        assert!(self.rq_len < MAX_THREADS, "run queue full");
        self.run_queue[self.rq_tail] = idx;
        self.rq_tail = (self.rq_tail + 1) % MAX_THREADS;
        self.rq_len += 1;
    }

    fn dequeue(&mut self) -> Option<usize> {
        if self.rq_len == 0 {
            return None;
        }
        let idx = self.run_queue[self.rq_head];
        self.rq_head = (self.rq_head + 1) % MAX_THREADS;
        self.rq_len -= 1;
        Some(idx)
    }

    /// Allocate a slot and return its index.
    fn alloc_slot(&mut self) -> Option<usize> {
        for i in 0..MAX_THREADS {
            if self.threads[i].state == ThreadState::Dead {
                return Some(i);
            }
        }
        None
    }
}

static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the scheduler and create the idle thread (thread 0).
pub fn init() {
    let mut sched = SCHEDULER.lock();

    // Thread 0 = idle thread.
    // It doesn't get a real stack via Thread::new — it will run on the
    // boot stack. We just need a slot to save its context into.
    let slot = sched.alloc_slot().expect("no slot for idle thread");
    sched.threads[slot].id = ThreadId(sched.next_id);
    sched.threads[slot].state = ThreadState::Running;
    sched.threads[slot].priority = 255; // lowest priority
    sched.threads[slot].timeslice = TIMESLICE;
    sched.next_id += 1;
    sched.current = Some(slot);

    kprintln!("  scheduler: preemptive round-robin (single core)");
}

/// Spawn a new kernel thread.
pub fn spawn(entry: fn() -> !) -> ThreadId {
    let mut sched = SCHEDULER.lock();
    let id = sched.next_id;
    sched.next_id += 1;

    let slot = sched.alloc_slot().expect("no free thread slots");
    sched.threads[slot] = Thread::new(id, entry, 128, thread_trampoline);
    sched.threads[slot].timeslice = TIMESLICE;

    let tid = sched.threads[slot].id;
    sched.enqueue(slot);
    tid
}

/// Spawn a new user thread that enters Ring 3 at `user_rip`.
pub fn spawn_user(user_rip: u64, user_rsp: u64, cr3: u64) -> ThreadId {
    let mut sched = SCHEDULER.lock();
    let id = sched.next_id;
    sched.next_id += 1;

    let slot = sched.alloc_slot().expect("no free thread slots");
    sched.threads[slot] = Thread::new_user(id, user_rip, user_rsp, cr3, user_thread_trampoline);
    sched.threads[slot].timeslice = TIMESLICE;

    let tid = sched.threads[slot].id;
    sched.enqueue(slot);
    tid
}

/// Terminate the current thread and switch away.
///
/// Marks the current thread as Dead (so `schedule()` won't re-enqueue it),
/// then calls `schedule()` to switch to the next runnable thread.
pub fn exit_current() -> ! {
    {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            sched.threads[idx].state = ThreadState::Dead;
        }
    }
    schedule();
    // Safety net if run queue was empty (idle thread should always be present).
    crate::arch::halt_loop();
}

/// Return the current thread's ID.
pub fn current_tid() -> Option<ThreadId> {
    let sched = SCHEDULER.lock();
    sched.current.map(|idx| sched.threads[idx].id)
}

/// Block the current thread (set to Blocked) and switch away.
/// The caller must have already set the IPC state via `set_current_ipc()`.
pub fn block_current() {
    {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            sched.threads[idx].state = ThreadState::Blocked;
        }
    }
    schedule();
}

/// Wake a blocked thread: set to Ready, reset timeslice, enqueue.
pub fn wake(tid: ThreadId) {
    let mut sched = SCHEDULER.lock();
    for i in 0..MAX_THREADS {
        if sched.threads[i].id == tid && sched.threads[i].state == ThreadState::Blocked {
            sched.threads[i].state = ThreadState::Ready;
            sched.threads[i].timeslice = TIMESLICE;
            sched.enqueue(i);
            return;
        }
    }
}

/// Store IPC state on the current thread before blocking.
pub fn set_current_ipc(ep_id: u32, role: IpcRole, msg: Message) {
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        sched.threads[idx].ipc_endpoint = Some(ep_id);
        sched.threads[idx].ipc_role = role;
        sched.threads[idx].ipc_msg = msg;
    }
}

/// Clear IPC state on the current thread after waking.
pub fn clear_current_ipc() {
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        sched.threads[idx].ipc_endpoint = None;
        sched.threads[idx].ipc_role = IpcRole::None;
    }
}

/// Write a message into a specific thread's IPC buffer.
pub fn write_ipc_msg(tid: ThreadId, msg: Message) {
    let mut sched = SCHEDULER.lock();
    for i in 0..MAX_THREADS {
        if sched.threads[i].id == tid {
            sched.threads[i].ipc_msg = msg;
            return;
        }
    }
}

/// Read the message from a specific thread's IPC buffer.
pub fn read_ipc_msg(tid: ThreadId) -> Message {
    let sched = SCHEDULER.lock();
    for i in 0..MAX_THREADS {
        if sched.threads[i].id == tid {
            return sched.threads[i].ipc_msg;
        }
    }
    Message::empty()
}

/// Read the current thread's own IPC message buffer (after being woken).
pub fn current_ipc_msg() -> Message {
    let sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        return sched.threads[idx].ipc_msg;
    }
    Message::empty()
}

/// Called from the timer interrupt handler on every tick.
pub fn tick() {
    let needs_reschedule = {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            if sched.threads[idx].timeslice > 0 {
                sched.threads[idx].timeslice -= 1;
            }
            sched.threads[idx].timeslice == 0
        } else {
            false
        }
    };

    if needs_reschedule {
        schedule();
    }
}

/// Pick the next thread and switch to it.
///
/// **Callers are responsible for interrupt state.** This function does NOT
/// enable or disable interrupts — each call site restores IF naturally:
/// - Timer handler: iretq restores RFLAGS (IF=1)
/// - Syscall yield: sysretq restores R11 (IF=1)
/// - New thread trampoline: sti / sysretq
pub fn schedule() {
    let switch_info: Option<(*mut u64, u64)> = {
        let mut sched = SCHEDULER.lock();

        let old_idx = match sched.current {
            Some(idx) => idx,
            None => return,
        };

        // Try to dequeue a ready thread.
        let new_idx = match sched.dequeue() {
            Some(idx) => idx,
            None => {
                // No other thread ready — reset timeslice and continue.
                sched.threads[old_idx].timeslice = TIMESLICE;
                return;
            }
        };

        // Re-enqueue the old thread if it's still runnable.
        if sched.threads[old_idx].state == ThreadState::Running {
            sched.threads[old_idx].state = ThreadState::Ready;
            sched.threads[old_idx].timeslice = TIMESLICE;
            sched.enqueue(old_idx);
        }

        sched.threads[new_idx].state = ThreadState::Running;
        sched.threads[new_idx].timeslice = TIMESLICE;
        sched.current = Some(new_idx);

        // Update kernel stack for TSS (Ring 3 → Ring 0 on interrupt)
        // and for SYSCALL entry.
        let new_kstack_top = sched.threads[new_idx].kernel_stack_top;
        if new_kstack_top != 0 {
            unsafe {
                crate::arch::gdt::set_tss_rsp0(new_kstack_top);
                crate::arch::syscall::set_kernel_stack_top(new_kstack_top);
            }
        }

        // Switch address space if the new thread has a different CR3.
        let new_cr3 = sched.threads[new_idx].cr3;
        let target_cr3 = if new_cr3 != 0 {
            new_cr3
        } else {
            crate::mm::paging::boot_cr3()
        };
        if target_cr3 != 0 {
            let current_cr3 = crate::mm::paging::read_cr3();
            if target_cr3 != current_cr3 {
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {}",
                        in(reg) target_cr3,
                        options(nostack, preserves_flags)
                    );
                }
            }
        }

        let old_rsp_ptr = &mut sched.threads[old_idx].context.rsp as *mut u64;
        let new_rsp = sched.threads[new_idx].context.rsp;

        Some((old_rsp_ptr, new_rsp))
    };
    // Lock is dropped here ^

    if let Some((old_rsp_ptr, new_rsp)) = switch_info {
        unsafe {
            context_switch(old_rsp_ptr, new_rsp);
        }
    }
}
