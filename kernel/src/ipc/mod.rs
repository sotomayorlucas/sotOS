//! Inter-Process Communication.
//!
//! Two IPC mechanisms:
//! - **Endpoints**: Synchronous, register-based message passing (L4-style).
//!   For control messages and capability transfers. Small messages (≤64 bytes)
//!   are passed in registers during context switch — zero memory overhead.
//!
//! - **Channels** (future): Shared-memory ring buffers for high-throughput
//!   data transfer. Lock-free, zero-copy, zero-syscall on the hot path.

pub mod endpoint;

pub use endpoint::{EndpointId, Message};
