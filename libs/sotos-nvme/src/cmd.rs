//! NVMe command opcodes and builders.

use crate::queue::SqEntry;

// --- Admin command opcodes ---

/// Identify (admin opcode 0x06).
pub const ADMIN_IDENTIFY: u8 = 0x06;
/// Create I/O Completion Queue (admin opcode 0x05).
pub const ADMIN_CREATE_IO_CQ: u8 = 0x05;
/// Create I/O Submission Queue (admin opcode 0x01).
pub const ADMIN_CREATE_IO_SQ: u8 = 0x01;

// --- I/O command opcodes (NVM command set) ---

/// Read (I/O opcode 0x02).
pub const IO_READ: u8 = 0x02;
/// Write (I/O opcode 0x01).
pub const IO_WRITE: u8 = 0x01;

/// Build an Identify Controller command (CNS=1).
pub fn identify_controller(prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_IDENTIFY as u32;
    e.prp1 = prp1_phys;
    e.cdw10 = 1; // CNS = 01h (Identify Controller)
    e
}

/// Build an Identify Namespace command (CNS=0, NSID=1).
pub fn identify_namespace(nsid: u32, prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_IDENTIFY as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.cdw10 = 0; // CNS = 00h (Identify Namespace)
    e
}

/// Build a Create I/O Completion Queue command.
///
/// - `qid`: Queue identifier (1-based for I/O queues).
/// - `prp1_phys`: Physical address of the CQ buffer.
/// - `size`: Queue size (0-based: actual entries - 1).
pub fn create_io_cq(qid: u16, prp1_phys: u64, size: u16) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_CREATE_IO_CQ as u32;
    e.prp1 = prp1_phys;
    // CDW10: QSIZE (31:16) | QID (15:0)
    e.cdw10 = ((size as u32) << 16) | (qid as u32);
    // CDW11: IEN=1 (bit 1), PC=1 (bit 0) — physically contiguous, interrupts enabled
    e.cdw11 = 0x03;
    e
}

/// Build a Create I/O Submission Queue command.
///
/// - `qid`: Queue identifier (1-based for I/O queues).
/// - `prp1_phys`: Physical address of the SQ buffer.
/// - `size`: Queue size (0-based: actual entries - 1).
/// - `cqid`: Associated Completion Queue ID.
pub fn create_io_sq(qid: u16, prp1_phys: u64, size: u16, cqid: u16) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = ADMIN_CREATE_IO_SQ as u32;
    e.prp1 = prp1_phys;
    // CDW10: QSIZE (31:16) | QID (15:0)
    e.cdw10 = ((size as u32) << 16) | (qid as u32);
    // CDW11: CQID (31:16) | QPRIO=0 (13:12) | PC=1 (bit 0)
    e.cdw11 = ((cqid as u32) << 16) | 0x01;
    e
}

/// Build an I/O Read command (single-page PRP).
///
/// - `nsid`: Namespace ID (usually 1).
/// - `lba`: Starting LBA.
/// - `count`: Number of logical blocks to read (0-based: actual - 1).
/// - `prp1_phys`: Physical address of the data buffer.
pub fn io_read(nsid: u32, lba: u64, count: u16, prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_READ as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}

/// Build an I/O Read command with PRP List support for multi-page transfers.
///
/// - `nsid`: Namespace ID.
/// - `lba`: Starting LBA.
/// - `count`: Number of logical blocks (0-based).
/// - `prp1_phys`: Physical address of the first data page.
/// - `prp2_phys`: Physical address of the second page, OR a PRP List pointer
///   if the transfer spans more than 2 pages.
pub fn io_read_prp(nsid: u32, lba: u64, count: u16, prp1_phys: u64, prp2_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_READ as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.prp2 = prp2_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}

/// Build an I/O Write command (single-page PRP).
///
/// - `nsid`: Namespace ID (usually 1).
/// - `lba`: Starting LBA.
/// - `count`: Number of logical blocks to write (0-based: actual - 1).
/// - `prp1_phys`: Physical address of the data buffer.
pub fn io_write(nsid: u32, lba: u64, count: u16, prp1_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_WRITE as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}

/// Build an I/O Write command with PRP List support for multi-page transfers.
pub fn io_write_prp(nsid: u32, lba: u64, count: u16, prp1_phys: u64, prp2_phys: u64) -> SqEntry {
    let mut e = SqEntry::zeroed();
    e.cdw0 = IO_WRITE as u32;
    e.nsid = nsid;
    e.prp1 = prp1_phys;
    e.prp2 = prp2_phys;
    e.cdw10 = lba as u32;
    e.cdw11 = (lba >> 32) as u32;
    e.cdw12 = count as u32;
    e
}
