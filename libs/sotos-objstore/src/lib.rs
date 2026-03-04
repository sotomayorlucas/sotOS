//! sotOS Object Store — a transactional object store with WAL for crash consistency.
//!
//! Provides named blob storage on top of virtio-blk, with a POSIX-like VFS shim.

#![no_std]

pub mod layout;
pub mod bitmap;
pub mod wal;
pub mod store;
pub mod vfs;

pub use layout::*;
pub use store::ObjectStore;
pub use vfs::Vfs;
