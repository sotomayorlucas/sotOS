//! xHCI Transfer Request Block (TRB) structures and ring buffers.

// ---------------------------------------------------------------------------
// TRB structure (16 bytes, 16-byte aligned)
// ---------------------------------------------------------------------------

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Trb {
    pub param: u64,
    pub status: u32,
    pub control: u32,
}

const _: () = assert!(core::mem::size_of::<Trb>() == 16);

impl Trb {
    pub const fn zeroed() -> Self {
        Trb { param: 0, status: 0, control: 0 }
    }

    /// Extract TRB type from control word (bits 15:10).
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Extract completion code from status word (bits 31:24).
    pub fn completion_code(&self) -> u8 {
        (self.status >> 24) as u8
    }

    /// Extract slot ID from control word (bits 31:24).
    pub fn slot_id(&self) -> u8 {
        (self.control >> 24) as u8
    }

    /// Extract endpoint ID from Transfer Event control (bits 20:16).
    pub fn endpoint_id(&self) -> u8 {
        ((self.control >> 16) & 0x1F) as u8
    }

    /// Extract cycle bit (bit 0 of control).
    pub fn cycle(&self) -> bool {
        self.control & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// TRB Type constants
// ---------------------------------------------------------------------------

pub const TRB_NORMAL: u8 = 1;
pub const TRB_SETUP_STAGE: u8 = 2;
pub const TRB_DATA_STAGE: u8 = 3;
pub const TRB_STATUS_STAGE: u8 = 4;
pub const TRB_LINK: u8 = 6;
pub const TRB_NO_OP_CMD: u8 = 23;
pub const TRB_ENABLE_SLOT: u8 = 9;
pub const TRB_ADDRESS_DEV: u8 = 11;
pub const TRB_CONFIGURE_EP: u8 = 12;
pub const TRB_XFER_EVENT: u8 = 32;
pub const TRB_CMD_COMPLETE: u8 = 33;
pub const TRB_PORT_STATUS: u8 = 34;

// ---------------------------------------------------------------------------
// Completion codes
// ---------------------------------------------------------------------------

pub const CC_SUCCESS: u8 = 1;

// ---------------------------------------------------------------------------
// Ring sizes
// ---------------------------------------------------------------------------

/// Total TRB slots in a ring (fits in one 4 KiB page: 4096/16 = 256).
pub const RING_SIZE: usize = 256;
/// Usable slots (last slot is Link TRB for command/transfer rings).
pub const RING_USABLE: usize = 255;

// ---------------------------------------------------------------------------
// Command TRB builders
// ---------------------------------------------------------------------------

/// Build a No-Op Command TRB.
pub fn cmd_no_op() -> Trb {
    Trb {
        param: 0,
        status: 0,
        control: (TRB_NO_OP_CMD as u32) << 10,
    }
}

/// Build an Enable Slot Command TRB.
pub fn cmd_enable_slot() -> Trb {
    Trb {
        param: 0,
        status: 0,
        control: (TRB_ENABLE_SLOT as u32) << 10,
    }
}

/// Build an Address Device Command TRB.
/// `input_ctx_phys`: physical address of the input context (16-byte aligned).
/// `slot_id`: slot to address.
/// `bsr`: Block Set Address Request — if true, skip SET_ADDRESS.
pub fn cmd_address_device(input_ctx_phys: u64, slot_id: u8, bsr: bool) -> Trb {
    let mut ctrl = (TRB_ADDRESS_DEV as u32) << 10 | ((slot_id as u32) << 24);
    if bsr {
        ctrl |= 1 << 9; // BSR bit
    }
    Trb {
        param: input_ctx_phys,
        status: 0,
        control: ctrl,
    }
}

/// Build a Configure Endpoint Command TRB.
pub fn cmd_configure_endpoint(input_ctx_phys: u64, slot_id: u8) -> Trb {
    Trb {
        param: input_ctx_phys,
        status: 0,
        control: (TRB_CONFIGURE_EP as u32) << 10 | ((slot_id as u32) << 24),
    }
}

// ---------------------------------------------------------------------------
// Transfer TRB builders (for EP0 control transfers and interrupt transfers)
// ---------------------------------------------------------------------------

/// Build a Setup Stage TRB for a control transfer.
/// `setup_packet`: 8 bytes of USB setup data packed as u64 (little-endian).
/// `trt`: Transfer Type — 0=No Data, 2=OUT Data, 3=IN Data.
pub fn trb_setup_stage(setup_packet: u64, trt: u8) -> Trb {
    Trb {
        param: setup_packet,
        status: 8, // TRB Transfer Length = 8 (setup packet size)
        // Type=SETUP_STAGE(2), IDT=1 (bit 6), TRT in bits 17:16
        control: (TRB_SETUP_STAGE as u32) << 10
            | (1 << 6)  // IDT — Immediate Data
            | ((trt as u32) << 16),
    }
}

/// Build a Data Stage TRB for a control transfer.
/// `dir_in`: true for IN (device-to-host), false for OUT.
pub fn trb_data_stage(buf_phys: u64, length: u16, dir_in: bool) -> Trb {
    let mut ctrl = (TRB_DATA_STAGE as u32) << 10;
    if dir_in {
        ctrl |= 1 << 16; // DIR = IN
    }
    Trb {
        param: buf_phys,
        status: length as u32,
        control: ctrl,
    }
}

/// Build a Status Stage TRB for a control transfer.
/// `dir_in`: true if status direction is IN (i.e., for OUT/No-Data transfers).
/// Set IOC to get a Transfer Event.
pub fn trb_status_stage(dir_in: bool) -> Trb {
    let mut ctrl = (TRB_STATUS_STAGE as u32) << 10 | (1 << 5); // IOC
    if dir_in {
        ctrl |= 1 << 16; // DIR = IN
    }
    Trb {
        param: 0,
        status: 0,
        control: ctrl,
    }
}

/// Build a Normal TRB for an interrupt IN transfer.
/// Set IOC to get a Transfer Event on completion.
pub fn trb_normal(buf_phys: u64, length: u16) -> Trb {
    Trb {
        param: buf_phys,
        status: length as u32,
        control: (TRB_NORMAL as u32) << 10 | (1 << 5), // IOC
    }
}

// ---------------------------------------------------------------------------
// TrbRing — Producer ring (for Command Ring and Transfer Rings)
// ---------------------------------------------------------------------------

pub struct TrbRing {
    base: *mut Trb,
    phys: u64,
    enqueue: usize,
    pcs: bool, // Producer Cycle State
}

impl TrbRing {
    /// Initialize a TRB ring at the given virtual/physical address.
    /// Zeros all entries and writes a Link TRB at the last slot.
    pub unsafe fn init(virt: *mut u8, phys: u64) -> Self {
        // Zero all entries.
        core::ptr::write_bytes(virt, 0, 4096);

        let base = virt as *mut Trb;

        // Write Link TRB at slot RING_USABLE (index 255).
        let link = base.add(RING_USABLE);
        // param = physical address of ring start (wrap target).
        core::ptr::write_volatile(&mut (*link).param as *mut u64, phys);
        // control: type=LINK, Toggle Cycle bit (bit 1).
        // Cycle bit (bit 0) will be set when we wrap — start as 0 (opposite of PCS=true).
        core::ptr::write_volatile(
            &mut (*link).control as *mut u32,
            ((TRB_LINK as u32) << 10) | (1 << 1), // TC=1, cycle=0
        );

        TrbRing { base, phys, enqueue: 0, pcs: true }
    }

    /// Enqueue a TRB. Sets the cycle bit from PCS. Returns the physical address.
    pub unsafe fn enqueue(&mut self, mut trb: Trb) -> u64 {
        // Set or clear cycle bit based on PCS.
        if self.pcs {
            trb.control |= 1; // set cycle bit
        } else {
            trb.control &= !1; // clear cycle bit
        }

        let slot_phys = self.phys + (self.enqueue as u64) * 16;
        core::ptr::write_volatile(self.base.add(self.enqueue), trb);

        self.enqueue += 1;
        if self.enqueue >= RING_USABLE {
            // We've reached the Link TRB — toggle its cycle bit and wrap.
            let link = self.base.add(RING_USABLE);
            let mut link_ctrl = core::ptr::read_volatile(&(*link).control as *const u32);
            // Clear old cycle bit, set current PCS.
            link_ctrl = (link_ctrl & !1) | (self.pcs as u32);
            core::ptr::write_volatile(&mut (*link).control as *mut u32, link_ctrl);
            self.enqueue = 0;
            self.pcs = !self.pcs; // Toggle PCS
        }

        slot_phys
    }

    /// Get the physical address of the ring base.
    pub fn phys(&self) -> u64 {
        self.phys
    }
}

// ---------------------------------------------------------------------------
// EventRing — Consumer ring (for Event Ring)
// ---------------------------------------------------------------------------

pub struct EventRing {
    base: *const Trb,
    phys: u64,
    dequeue: usize,
    ccs: bool, // Consumer Cycle State
}

impl EventRing {
    /// Initialize an event ring at the given virtual/physical address.
    pub unsafe fn init(virt: *mut u8, phys: u64) -> Self {
        core::ptr::write_bytes(virt, 0, 4096);
        EventRing {
            base: virt as *const Trb,
            phys,
            dequeue: 0,
            ccs: true,
        }
    }

    /// Poll the next event. Returns Some(trb) if a new event is available.
    pub unsafe fn poll(&self) -> Option<Trb> {
        let trb = core::ptr::read_volatile(self.base.add(self.dequeue));
        if trb.cycle() == self.ccs {
            Some(trb)
        } else {
            None
        }
    }

    /// Advance the dequeue pointer after consuming an event.
    pub fn advance(&mut self) {
        self.dequeue += 1;
        if self.dequeue >= RING_SIZE {
            self.dequeue = 0;
            self.ccs = !self.ccs;
        }
    }

    /// Get the physical address of the current dequeue position (for ERDP writeback).
    pub fn dequeue_phys(&self) -> u64 {
        self.phys + (self.dequeue as u64) * 16
    }
}

// ---------------------------------------------------------------------------
// ERST entry (Event Ring Segment Table)
// ---------------------------------------------------------------------------

/// Event Ring Segment Table Entry (16 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErstEntry {
    pub ring_segment_base: u64,
    pub ring_segment_size: u32,
    _reserved: u32,
}

const _: () = assert!(core::mem::size_of::<ErstEntry>() == 16);

impl ErstEntry {
    pub fn new(base_phys: u64, size: u32) -> Self {
        ErstEntry {
            ring_segment_base: base_phys,
            ring_segment_size: size,
            _reserved: 0,
        }
    }
}
