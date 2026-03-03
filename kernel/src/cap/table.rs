//! Capability table implementation.
//!
//! Fixed-size table mapping CapId → (Object, Rights, Parent).
//! The Capability Derivation Tree (CDT) tracks parent-child
//! relationships for O(n) revocation of all derivatives.

/// Maximum number of capabilities in the system.
pub const MAX_CAPS: usize = 4096;

/// Unique capability identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapId(u32);

impl CapId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Rights bitmask for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);
    pub const REVOKE: Self = Self(1 << 4);
    pub const ALL: Self = Self(0x1F);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Derive new rights that are a subset of the current rights.
    pub const fn restrict(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }
}

/// Kernel objects that capabilities can reference.
#[derive(Debug, Clone, Copy)]
pub enum CapObject {
    /// Physical memory: base address + size in bytes.
    Memory { base: u64, size: u64 },
    /// IPC endpoint.
    Endpoint { id: u32 },
    /// Thread.
    Thread { id: u32 },
    /// Hardware IRQ line.
    Irq { line: u32 },
    /// x86 I/O port range.
    IoPort { base: u16, count: u16 },
    /// Null / empty slot.
    Null,
}

/// A single entry in the capability table.
#[derive(Debug, Clone, Copy)]
struct CapEntry {
    object: CapObject,
    rights: Rights,
    /// Parent capability (for the CDT). None = root capability.
    parent: Option<CapId>,
    /// Is this entry alive?
    alive: bool,
}

impl CapEntry {
    const fn empty() -> Self {
        Self {
            object: CapObject::Null,
            rights: Rights::empty(),
            parent: None,
            alive: false,
        }
    }
}

/// The kernel's capability table.
pub struct CapabilityTable {
    entries: [CapEntry; MAX_CAPS],
    next_free: u32,
}

impl CapabilityTable {
    pub const fn new() -> Self {
        Self {
            entries: [CapEntry::empty(); MAX_CAPS],
            next_free: 0,
        }
    }

    /// Insert a new capability. Returns None if the table is full.
    pub fn insert(
        &mut self,
        object: CapObject,
        rights: Rights,
        parent: Option<CapId>,
    ) -> Option<CapId> {
        // Linear scan from next_free hint.
        for i in 0..MAX_CAPS {
            let idx = (self.next_free as usize + i) % MAX_CAPS;
            if !self.entries[idx].alive {
                self.entries[idx] = CapEntry {
                    object,
                    rights,
                    parent,
                    alive: true,
                };
                self.next_free = (idx as u32 + 1) % MAX_CAPS as u32;
                return Some(CapId(idx as u32));
            }
        }
        None
    }

    /// Look up a capability by ID. Returns None if not found or revoked.
    pub fn lookup(&self, id: CapId) -> Option<(CapObject, Rights)> {
        let entry = &self.entries[id.index()];
        if entry.alive {
            Some((entry.object, entry.rights))
        } else {
            None
        }
    }

    /// Revoke a capability and all capabilities derived from it (CDT walk).
    pub fn revoke(&mut self, id: CapId) {
        if !self.entries[id.index()].alive {
            return;
        }
        self.entries[id.index()].alive = false;

        // Walk the table and revoke all children.
        // This is O(n*depth) in the worst case — acceptable for the current
        // fixed-size table. A real CDT would use a tree structure.
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..MAX_CAPS {
                if self.entries[i].alive {
                    if let Some(parent) = self.entries[i].parent {
                        if !self.entries[parent.index()].alive {
                            self.entries[i].alive = false;
                            changed = true;
                        }
                    }
                }
            }
        }
    }
}
