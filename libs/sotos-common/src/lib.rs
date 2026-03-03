//! Shared types and constants between the sotOS kernel and userspace services.
//!
//! This crate defines the ABI contract: syscall numbers, capability types,
//! IPC message formats, and error codes. Both the kernel and userspace
//! link against this crate to ensure type-safe communication.

#![no_std]

pub mod spsc;
pub mod typed_channel;

/// Syscall numbers. The kernel exposes exactly these operations.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    /// Yield the current thread's remaining timeslice.
    Yield = 0,
    /// Send a message to an IPC endpoint.
    Send = 1,
    /// Receive a message from an IPC endpoint.
    Recv = 2,
    /// Combined send+receive (call semantics).
    Call = 3,
    /// Create a new async IPC channel.
    ChannelCreate = 4,
    /// Send a message on an async channel.
    ChannelSend = 5,
    /// Receive a message from an async channel.
    ChannelRecv = 6,
    /// Close an async channel.
    ChannelClose = 7,
    /// Create a new IPC endpoint.
    EndpointCreate = 10,
    /// Allocate a physical frame.
    FrameAlloc = 20,
    /// Free a physical frame.
    FrameFree = 21,
    /// Map a frame into a virtual address space (delegated to VMM).
    Map = 22,
    /// Unmap a virtual page.
    Unmap = 23,
    /// Delegate a capability (with optional rights restriction).
    CapGrant = 30,
    /// Revoke a capability and all its derivatives.
    CapRevoke = 31,
    /// Create a new thread.
    ThreadCreate = 40,
    /// Destroy a thread.
    ThreadDestroy = 41,
    /// Exit the current thread.
    ThreadExit = 42,
    /// Resume a faulted thread (used by VMM server).
    ThreadResume = 43,
    /// Register an IRQ handler (userspace driver).
    IrqRegister = 50,
    /// Acknowledge an IRQ.
    IrqAck = 51,
    /// Read a byte from an I/O port.
    PortIn = 60,
    /// Write a byte to an I/O port.
    PortOut = 61,
    /// Create a notification object (binary semaphore).
    NotifyCreate = 70,
    /// Wait on a notification (blocks if not pending).
    NotifyWait = 71,
    /// Signal a notification (wakes waiter or sets pending).
    NotifySignal = 72,
    /// Register a notification for page fault delivery (VMM).
    FaultRegister = 80,
    /// Receive the next pending page fault (VMM).
    FaultRecv = 81,
    /// Write a single byte to serial (temporary debug aid).
    DebugPrint = 255,
}

/// Error codes returned by syscalls.
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// Operation succeeded.
    Ok = 0,
    /// Invalid capability.
    InvalidCap = -1,
    /// Insufficient rights on capability.
    NoRights = -2,
    /// Resource exhausted (no frames, no endpoint slots, etc.).
    OutOfResources = -3,
    /// Invalid argument.
    InvalidArg = -4,
    /// Operation would block (for non-blocking variants).
    WouldBlock = -5,
    /// Object not found.
    NotFound = -6,
}

/// Well-known virtual address of the BootInfo page (mapped read-only for init).
pub const BOOT_INFO_ADDR: u64 = 0xB00000;

/// Boot info magic number ("SOTOS" in ASCII, zero-extended).
pub const BOOT_INFO_MAGIC: u64 = 0x534F544F53;

/// Maximum capabilities passed to init.
pub const BOOT_INFO_MAX_CAPS: usize = 32;

/// Boot information struct passed from kernel to the init process.
/// Located at BOOT_INFO_ADDR, mapped read-only into the init address space.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
    pub magic: u64,
    pub cap_count: u64,
    pub caps: [u64; BOOT_INFO_MAX_CAPS],
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            cap_count: 0,
            caps: [0; BOOT_INFO_MAX_CAPS],
        }
    }

    /// Check if this BootInfo is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC
    }
}

/// Raw syscall wrappers for userspace programs.
///
/// These issue the `syscall` instruction directly. Only usable from
/// Ring 3 code compiled for `x86_64-unknown-none`.
pub mod sys {
    #[inline(always)]
    pub fn syscall0(nr: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline(always)]
    pub fn syscall1(nr: u64, a1: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline(always)]
    pub fn syscall2(nr: u64, a1: u64, a2: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline(always)]
    pub fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    /// Write a single byte to the kernel debug serial port.
    #[inline(always)]
    pub fn debug_print(byte: u8) {
        syscall1(super::Syscall::DebugPrint as u64, byte as u64);
    }

    /// Allocate a physical frame. Returns the frame capability ID.
    #[inline(always)]
    pub fn frame_alloc() -> Result<u64, i64> {
        let ret = syscall0(super::Syscall::FrameAlloc as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Map a frame into the caller's address space.
    /// `flags`: bit 1 = WRITABLE, bit 63 = NO_EXECUTE.
    #[inline(always)]
    pub fn map(vaddr: u64, frame_cap: u64, flags: u64) -> Result<(), i64> {
        let ret = syscall3(super::Syscall::Map as u64, vaddr, frame_cap, flags);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Create a notification object. Returns the notification capability ID.
    #[inline(always)]
    pub fn notify_create() -> Result<u64, i64> {
        let ret = syscall0(super::Syscall::NotifyCreate as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Wait on a notification (blocks if not pending).
    #[inline(always)]
    pub fn notify_wait(cap: u64) {
        syscall1(super::Syscall::NotifyWait as u64, cap);
    }

    /// Signal a notification (wakes waiter or sets pending).
    #[inline(always)]
    pub fn notify_signal(cap: u64) {
        syscall1(super::Syscall::NotifySignal as u64, cap);
    }

    /// Create a new thread. Returns the thread capability ID.
    #[inline(always)]
    pub fn thread_create(rip: u64, rsp: u64) -> Result<u64, i64> {
        let ret = syscall2(super::Syscall::ThreadCreate as u64, rip, rsp);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Terminate the current thread (never returns).
    #[inline(always)]
    pub fn thread_exit() -> ! {
        syscall0(super::Syscall::ThreadExit as u64);
        // Safety: the kernel destroys the thread, so this is unreachable.
        unsafe { core::hint::unreachable_unchecked() }
    }

    /// Yield the remainder of the current timeslice.
    #[inline(always)]
    pub fn yield_now() {
        syscall0(super::Syscall::Yield as u64);
    }

    /// Read a byte from an I/O port.
    #[inline(always)]
    pub fn port_in(cap: u64, port: u64) -> Result<u8, i64> {
        let ret = syscall2(super::Syscall::PortIn as u64, cap, port);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret as u8) }
    }

    /// Write a byte to an I/O port.
    #[inline(always)]
    pub fn port_out(cap: u64, port: u64, value: u8) -> Result<(), i64> {
        let ret = syscall3(super::Syscall::PortOut as u64, cap, port, value as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Read the CPU timestamp counter (rdtsc).
    #[inline(always)]
    pub fn rdtsc() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        ((hi as u64) << 32) | lo as u64
    }
}
