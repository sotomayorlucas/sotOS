//! Distributed VFS — object store replication across nodes.
//!
//! Provides a coordination layer for replicating object store operations
//! across multiple nodes in a distributed system. Uses an operation log
//! (sync log) for eventual consistency and last-writer-wins conflict
//! resolution.
//!
//! Each node maintains a local object store and replicates operations
//! to peer nodes. The `DistributedVfs` coordinator tracks node membership,
//! logs operations, and manages the sync state.

/// Maximum number of nodes in the distributed VFS cluster.
pub const MAX_NODES: usize = 8;
/// Maximum number of sync log entries.
pub const MAX_SYNC_LOG: usize = 64;
/// Maximum name length for sync entries.
pub const SYNC_NAME_LEN: usize = 48;

/// Node information for the distributed VFS.
#[derive(Clone, Copy)]
pub struct VfsNode {
    /// Unique node identifier.
    pub node_id: u16,
    /// Whether this node is currently active/reachable.
    pub active: bool,
    /// Last sync sequence number acknowledged by this node.
    pub last_sync_seq: u64,
}

impl VfsNode {
    pub const fn empty() -> Self {
        Self {
            node_id: 0,
            active: false,
            last_sync_seq: 0,
        }
    }
}

/// Type of synchronization operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncOp {
    /// Object created.
    Create,
    /// Object data written/updated.
    Write,
    /// Object deleted.
    Delete,
    /// Directory created.
    Mkdir,
    /// Object renamed.
    Rename,
}

impl SyncOp {
    /// Encode as a single byte for serialization.
    pub fn to_byte(self) -> u8 {
        match self {
            SyncOp::Create => 0,
            SyncOp::Write => 1,
            SyncOp::Delete => 2,
            SyncOp::Mkdir => 3,
            SyncOp::Rename => 4,
        }
    }

    /// Decode from a single byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(SyncOp::Create),
            1 => Some(SyncOp::Write),
            2 => Some(SyncOp::Delete),
            3 => Some(SyncOp::Mkdir),
            4 => Some(SyncOp::Rename),
            _ => None,
        }
    }
}

/// A single sync log entry describing one replicated operation.
#[derive(Clone, Copy)]
pub struct SyncEntry {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// The operation type.
    pub op: SyncOp,
    /// Object ID affected.
    pub oid: u64,
    /// Object/directory name (null-terminated).
    pub name: [u8; SYNC_NAME_LEN],
    /// Node that originated this operation.
    pub node_id: u16,
    /// Timestamp (tick counter) when the operation occurred.
    pub timestamp: u64,
}

impl SyncEntry {
    pub const fn empty() -> Self {
        Self {
            seq: 0,
            op: SyncOp::Create,
            oid: 0,
            name: [0; SYNC_NAME_LEN],
            node_id: 0,
            timestamp: 0,
        }
    }

    /// Get the name as a byte slice (up to null terminator).
    pub fn name_str(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(SYNC_NAME_LEN);
        &self.name[..len]
    }
}

/// Distributed VFS coordinator.
///
/// Manages node membership, operation logging, and sync state for
/// replicated object store operations. Sits on top of the local
/// `ObjectStore` and intercepts mutations to log them for replication.
pub struct DistributedVfs {
    /// Known nodes in the cluster.
    pub nodes: [VfsNode; MAX_NODES],
    /// Number of registered nodes.
    pub node_count: usize,
    /// This node's ID.
    pub local_node_id: u16,
    /// How many copies of each object to maintain (1 = no replication).
    pub replication_factor: u8,
    /// Circular operation log for pending replication.
    pub sync_log: [SyncEntry; MAX_SYNC_LOG],
    /// Index of the next write position in the sync log.
    pub sync_log_head: usize,
    /// Total number of entries written (monotonic, wraps the ring buffer).
    pub total_entries: u64,
    /// Next sequence number to assign.
    next_seq: u64,
}

impl DistributedVfs {
    /// Create a new distributed VFS coordinator for the given local node.
    pub fn new(local_node_id: u16, replication_factor: u8) -> Self {
        let mut dvfs = Self {
            nodes: [VfsNode::empty(); MAX_NODES],
            node_count: 0,
            local_node_id,
            replication_factor: replication_factor.max(1),
            sync_log: [SyncEntry::empty(); MAX_SYNC_LOG],
            sync_log_head: 0,
            total_entries: 0,
            next_seq: 1,
        };

        // Register self as the first node.
        dvfs.nodes[0] = VfsNode {
            node_id: local_node_id,
            active: true,
            last_sync_seq: 0,
        };
        dvfs.node_count = 1;

        dvfs
    }

    /// Add a remote node to the cluster.
    ///
    /// Returns `true` if the node was added, `false` if the cluster is full
    /// or the node is already registered.
    pub fn add_node(&mut self, node_id: u16) -> bool {
        // Check if already registered.
        for i in 0..self.node_count {
            if self.nodes[i].node_id == node_id {
                self.nodes[i].active = true;
                return true; // Re-activated
            }
        }

        if self.node_count >= MAX_NODES {
            return false;
        }

        self.nodes[self.node_count] = VfsNode {
            node_id,
            active: true,
            last_sync_seq: 0,
        };
        self.node_count += 1;
        true
    }

    /// Remove (deactivate) a node from the cluster.
    ///
    /// The node is marked inactive but its slot is preserved so that
    /// sync state is not lost if the node comes back.
    pub fn remove_node(&mut self, node_id: u16) -> bool {
        for i in 0..self.node_count {
            if self.nodes[i].node_id == node_id {
                self.nodes[i].active = false;
                return true;
            }
        }
        false
    }

    /// Log an operation to the sync log for replication.
    ///
    /// The entry is stamped with a sequence number and the local node ID.
    /// It will be available for retrieval by `get_pending_sync()`.
    pub fn log_operation(&mut self, op: SyncOp, oid: u64, name: &[u8]) {
        let seq = self.next_seq;
        self.next_seq += 1;

        let mut entry = SyncEntry::empty();
        entry.seq = seq;
        entry.op = op;
        entry.oid = oid;
        entry.node_id = self.local_node_id;
        let copy_len = name.len().min(SYNC_NAME_LEN - 1);
        entry.name[..copy_len].copy_from_slice(&name[..copy_len]);

        self.sync_log[self.sync_log_head] = entry;
        self.sync_log_head = (self.sync_log_head + 1) % MAX_SYNC_LOG;
        self.total_entries += 1;
    }

    /// Log an operation with a timestamp.
    pub fn log_operation_with_timestamp(
        &mut self,
        op: SyncOp,
        oid: u64,
        name: &[u8],
        timestamp: u64,
    ) {
        let seq = self.next_seq;
        self.next_seq += 1;

        let mut entry = SyncEntry::empty();
        entry.seq = seq;
        entry.op = op;
        entry.oid = oid;
        entry.node_id = self.local_node_id;
        entry.timestamp = timestamp;
        let copy_len = name.len().min(SYNC_NAME_LEN - 1);
        entry.name[..copy_len].copy_from_slice(&name[..copy_len]);

        self.sync_log[self.sync_log_head] = entry;
        self.sync_log_head = (self.sync_log_head + 1) % MAX_SYNC_LOG;
        self.total_entries += 1;
    }

    /// Get pending sync entries for a target node.
    ///
    /// Returns entries that the target node has not yet acknowledged
    /// (entries with seq > target's last_sync_seq).
    ///
    /// Writes matching entries into `out` and returns the count.
    pub fn get_pending_sync(&self, target_node: u16, out: &mut [SyncEntry]) -> usize {
        // Find the target node's last ack'd sequence.
        let last_ack = self
            .find_node(target_node)
            .map_or(0, |n| n.last_sync_seq);

        let mut count = 0;
        let max = out.len();

        // Scan the sync log for entries after last_ack.
        for i in 0..MAX_SYNC_LOG {
            let entry = &self.sync_log[i];
            if entry.seq > last_ack && entry.seq > 0 && count < max {
                out[count] = *entry;
                count += 1;
            }
        }

        // Sort by sequence number (simple insertion sort for small arrays).
        for i in 1..count {
            let mut j = i;
            while j > 0 && out[j].seq < out[j - 1].seq {
                out.swap(j, j - 1);
                j -= 1;
            }
        }

        count
    }

    /// Apply a remote operation received from another node.
    ///
    /// This adds the entry to the local sync log (for forwarding to other nodes)
    /// and updates the originating node's last_sync_seq.
    ///
    /// The caller is responsible for actually executing the operation on the
    /// local `ObjectStore`.
    pub fn apply_remote_op(&mut self, entry: &SyncEntry) {
        // Update the originating node's last sync seq.
        for i in 0..self.node_count {
            if self.nodes[i].node_id == entry.node_id {
                if entry.seq > self.nodes[i].last_sync_seq {
                    self.nodes[i].last_sync_seq = entry.seq;
                }
                break;
            }
        }

        // Add to our log for forwarding (re-stamp with local seq).
        self.log_operation_with_timestamp(entry.op, entry.oid, entry.name_str(), entry.timestamp);
    }

    /// Acknowledge that a target node has received all entries up to `seq`.
    pub fn acknowledge(&mut self, target_node: u16, seq: u64) {
        for i in 0..self.node_count {
            if self.nodes[i].node_id == target_node {
                if seq > self.nodes[i].last_sync_seq {
                    self.nodes[i].last_sync_seq = seq;
                }
                break;
            }
        }
    }

    /// Resolve a conflict between a local and remote operation.
    ///
    /// Uses last-writer-wins strategy: the entry with the higher timestamp
    /// wins. If timestamps are equal, higher node_id wins (deterministic
    /// tiebreaker).
    pub fn resolve_conflict(local: &SyncEntry, remote: &SyncEntry) -> SyncEntry {
        // Last-writer-wins: compare timestamps.
        if remote.timestamp > local.timestamp {
            *remote
        } else if local.timestamp > remote.timestamp {
            *local
        } else {
            // Tiebreaker: higher node_id wins.
            if remote.node_id > local.node_id {
                *remote
            } else {
                *local
            }
        }
    }

    /// Get the number of active nodes in the cluster.
    pub fn active_node_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.node_count {
            if self.nodes[i].active {
                count += 1;
            }
        }
        count
    }

    /// Check if we have enough replicas for the configured replication factor.
    pub fn has_quorum(&self) -> bool {
        self.active_node_count() >= self.replication_factor as usize
    }

    /// Find a node by ID.
    fn find_node(&self, node_id: u16) -> Option<&VfsNode> {
        for i in 0..self.node_count {
            if self.nodes[i].node_id == node_id {
                return Some(&self.nodes[i]);
            }
        }
        None
    }

    /// Get the current sequence number (for external use).
    pub fn current_seq(&self) -> u64 {
        self.next_seq - 1
    }
}
