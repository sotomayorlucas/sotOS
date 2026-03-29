//! SOT (Secure Object Transfer) domain transition layer.
//!
//! Provides optimized IPC paths for domain transitions, targeting
//! <1000 cycles for 64-byte synchronous register-based IPC.

pub mod fast_ipc;
