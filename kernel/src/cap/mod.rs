//! Capability-based security system.
//!
//! Every kernel object is accessed through capabilities — opaque handles
//! with associated rights. Capabilities can be delegated (with reduced
//! rights) and revoked (invalidating all derivatives via the CDT).

pub mod table;

pub use table::{CapId, CapObject, CapabilityTable, Rights};
use crate::kprintln;

use spin::Mutex;

static CAP_TABLE: Mutex<CapabilityTable> = Mutex::new(CapabilityTable::new());

pub fn init() {
    // The root capability table is ready — it starts empty.
    // The init service will receive root capabilities for all resources.
    kprintln!("  capability table ready (max {} entries)", table::MAX_CAPS);
}

/// Insert a new capability and return its ID.
pub fn insert(object: CapObject, rights: Rights, parent: Option<CapId>) -> Option<CapId> {
    CAP_TABLE.lock().insert(object, rights, parent)
}

/// Look up a capability by ID.
pub fn lookup(id: CapId) -> Option<(CapObject, Rights)> {
    CAP_TABLE.lock().lookup(id)
}

/// Revoke a capability and all its derivatives.
pub fn revoke(id: CapId) {
    CAP_TABLE.lock().revoke(id);
}
