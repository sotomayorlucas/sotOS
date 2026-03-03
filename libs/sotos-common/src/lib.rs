//! Shared types and constants between the sotOS kernel and userspace services.
//!
//! This crate defines the ABI contract: syscall numbers, capability types,
//! IPC message formats, and error codes. Both the kernel and userspace
//! link against this crate to ensure type-safe communication.

#![no_std]

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
    /// Register an IRQ handler (userspace driver).
    IrqRegister = 50,
    /// Acknowledge an IRQ.
    IrqAck = 51,
    /// Read a byte from an I/O port (temporary debug).
    PortIn = 60,
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
