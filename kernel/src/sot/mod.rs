//! SOT (Secure Object Transactional) exokernel subsystem.
//!
//! Core SOT primitives: Secure Objects, capability epoch tracking,
//! transactions (Tier 0/1/2), provenance ring buffers, domains,
//! and OpenBSD-derived security primitives (ChaCha20, W^X, ASLR).

pub mod aslr;
pub mod cap_epoch;
pub mod crypto;
pub mod domain;
pub mod provenance;
pub mod secure_string;
pub mod so;
pub mod tx;
pub mod tx_wal;
pub mod types;
pub mod wx_enforce;

pub use so::{CapObjectAdapter, SecureObject};
pub use types::{Policy, SOId, SOOperation, SOType, SOVersion};
