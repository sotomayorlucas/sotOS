//! NVMe Submission and Completion queue management.

/// NVMe Submission Queue Entry (64 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SqEntry {
    /// Command Dword 0: opcode (7:0), fuse (9:8), PSDT (15:14), CID (31:16).
    pub cdw0: u32,
    /// Namespace Identifier.
    pub nsid: u32,
    /// Reserved.
    pub cdw2: u32,
    /// Reserved.
    pub cdw3: u32,
    /// Metadata pointer.
    pub mptr: u64,
    /// Data pointer — PRP Entry 1.
    pub prp1: u64,
    /// Data pointer — PRP Entry 2 (or PRP List pointer).
    pub prp2: u64,
    /// Command-specific Dwords 10-15.
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

const _: () = assert!(core::mem::size_of::<SqEntry>() == 64);

impl SqEntry {
    pub const fn zeroed() -> Self {
        Self {
            cdw0: 0, nsid: 0, cdw2: 0, cdw3: 0,
            mptr: 0, prp1: 0, prp2: 0,
            cdw10: 0, cdw11: 0, cdw12: 0,
            cdw13: 0, cdw14: 0, cdw15: 0,
        }
    }
}

/// NVMe Completion Queue Entry (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CqEntry {
    /// Command-specific result.
    pub dw0: u32,
    /// Reserved.
    pub dw1: u32,
    /// SQ Head Pointer (15:0) | SQ Identifier (31:16).
    pub sq_head_sqid: u32,
    /// Command ID (15:0) | Phase Tag (16) | Status (31:17).
    pub cid_status: u32,
}

const _: () = assert!(core::mem::size_of::<CqEntry>() == 16);

impl CqEntry {
    pub const fn zeroed() -> Self {
        Self { dw0: 0, dw1: 0, sq_head_sqid: 0, cid_status: 0 }
    }

    /// Extract the phase bit from this CQE.
    pub fn phase(&self) -> bool {
        (self.cid_status & (1 << 16)) != 0
    }

    /// Extract status code (bits 31:17 of dw3, shifted to 14:1, bit 0 = DNR).
    pub fn status(&self) -> u16 {
        ((self.cid_status >> 17) & 0x7FFF) as u16
    }

    /// Extract the command ID.
    pub fn cid(&self) -> u16 {
        (self.cid_status & 0xFFFF) as u16
    }
}

/// Queue depth (number of entries). Keep small for initial driver.
pub const QUEUE_DEPTH: usize = 32;

/// Entries per 4 KiB page for SQ (64 bytes each).
pub const SQ_ENTRIES_PER_PAGE: usize = 4096 / 64; // 64

/// Entries per 4 KiB page for CQ (16 bytes each).
pub const CQ_ENTRIES_PER_PAGE: usize = 4096 / 16; // 256

/// Submission queue ring buffer state.
pub struct SubmissionQueue {
    /// Virtual address of the SQ buffer (page-aligned).
    pub base: *mut SqEntry,
    /// Physical address of the SQ buffer (for hardware).
    pub phys: u64,
    /// Current tail index (next slot to write).
    pub tail: u16,
    /// Queue depth.
    pub depth: u16,
    /// Next command ID to assign.
    pub next_cid: u16,
}

impl SubmissionQueue {
    /// Create a new SQ from pre-allocated memory.
    pub fn new(virt: *mut u8, phys: u64, depth: u16) -> Self {
        // Zero-init the queue memory.
        unsafe { core::ptr::write_bytes(virt, 0, depth as usize * 64); }
        Self {
            base: virt as *mut SqEntry,
            phys,
            tail: 0,
            depth,
            next_cid: 0,
        }
    }

    /// Submit a command. Returns the command ID.
    pub fn submit(&mut self, mut entry: SqEntry) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        // Set CID in CDW0 bits 31:16.
        entry.cdw0 = (entry.cdw0 & 0xFFFF) | ((cid as u32) << 16);
        unsafe {
            core::ptr::write_volatile(self.base.add(self.tail as usize), entry);
        }
        self.tail = (self.tail + 1) % self.depth;
        cid
    }
}

/// Completion queue ring buffer state.
pub struct CompletionQueue {
    /// Virtual address of the CQ buffer (page-aligned).
    pub base: *mut CqEntry,
    /// Physical address of the CQ buffer (for hardware).
    pub phys: u64,
    /// Current head index (next slot to read).
    pub head: u16,
    /// Queue depth.
    pub depth: u16,
    /// Expected phase bit (toggles on wrap).
    pub phase: bool,
}

impl CompletionQueue {
    /// Create a new CQ from pre-allocated memory.
    pub fn new(virt: *mut u8, phys: u64, depth: u16) -> Self {
        // Zero-init the queue memory.
        unsafe { core::ptr::write_bytes(virt, 0, depth as usize * 16); }
        Self {
            base: virt as *mut CqEntry,
            phys,
            head: 0,
            depth,
            phase: true, // Phase starts at 1
        }
    }

    /// Check if the next CQE is ready (phase bit matches expected).
    pub fn poll(&self) -> Option<CqEntry> {
        let entry = unsafe { core::ptr::read_volatile(self.base.add(self.head as usize)) };
        if entry.phase() == self.phase {
            Some(entry)
        } else {
            None
        }
    }

    /// Advance head after consuming a CQE.
    pub fn advance(&mut self) {
        self.head += 1;
        if self.head >= self.depth {
            self.head = 0;
            self.phase = !self.phase;
        }
    }
}
