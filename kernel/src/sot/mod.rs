//! SOT (Secure Object Transactional) exokernel subsystem.
//!
//! This module implements the core SOT primitives: Secure Objects,
//! capability epoch tracking, transactions, provenance, and domains.

pub mod cap_epoch;
pub mod so;
pub mod types;

pub use so::{CapObjectAdapter, SecureObject};
pub use types::{Policy, SOId, SOOperation, SOType, SOVersion};
