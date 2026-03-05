//! USB Mass Storage device state machine and high-level I/O interface.
//!
//! This module provides a `MassStorageDevice` that tracks device state,
//! builds CBW/CSW pairs, and provides a sector-level read/write interface
//! matching the NVMe driver style.

use crate::bbb::{Cbw, Csw, CswError, CBW_SIZE, CSW_SIZE};
use crate::scsi;

/// Device states.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// Not initialized.
    Uninit,
    /// Ready for commands.
    Ready,
    /// Needs reset recovery.
    NeedsReset,
    /// Error — device returned persistent errors.
    Error,
}

/// USB Mass Storage device representation.
///
/// Stateless with respect to USB transport — the caller is responsible
/// for sending/receiving CBW/CSW/data on the correct bulk endpoints.
pub struct MassStorageDevice {
    /// Current device state.
    pub state: DeviceState,
    /// Logical Unit Number (usually 0).
    pub lun: u8,
    /// Maximum LUN supported (from GET_MAX_LUN).
    pub max_lun: u8,
    /// Next command tag (auto-incrementing).
    pub next_tag: u32,
    /// Block size in bytes (from READ CAPACITY, usually 512).
    pub block_size: u32,
    /// Total number of blocks.
    pub total_blocks: u64,
    /// Device vendor (from INQUIRY).
    pub vendor: [u8; 8],
    /// Device product (from INQUIRY).
    pub product: [u8; 16],
    /// Whether the device has removable media.
    pub removable: bool,
}

/// Prepared command — a CBW and expected data transfer details.
pub struct PreparedCommand {
    /// The CBW to send on Bulk-OUT.
    pub cbw: Cbw,
    /// Serialized CBW bytes.
    pub cbw_bytes: [u8; CBW_SIZE],
    /// Expected data direction: true = Data-In, false = Data-Out, ignored if no data.
    pub data_in: bool,
    /// Expected data transfer length in bytes (0 for no data phase).
    pub data_length: u32,
    /// Tag for CSW validation.
    pub tag: u32,
}

impl MassStorageDevice {
    /// Create a new uninitialized device.
    pub const fn new() -> Self {
        Self {
            state: DeviceState::Uninit,
            lun: 0,
            max_lun: 0,
            next_tag: 1,
            block_size: 512,
            total_blocks: 0,
            vendor: [0; 8],
            product: [0; 16],
            removable: false,
        }
    }

    /// Allocate the next command tag.
    fn alloc_tag(&mut self) -> u32 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        if self.next_tag == 0 {
            self.next_tag = 1; // Avoid tag 0.
        }
        tag
    }

    /// Prepare a TEST UNIT READY command.
    pub fn prepare_test_unit_ready(&mut self) -> PreparedCommand {
        let tag = self.alloc_tag();
        let (cdb, cdb_len) = scsi::test_unit_ready();
        let cbw = Cbw::no_data(tag, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: false,
            data_length: 0,
            tag,
        }
    }

    /// Prepare an INQUIRY command.
    /// Expects 36 bytes of data back.
    pub fn prepare_inquiry(&mut self) -> PreparedCommand {
        let tag = self.alloc_tag();
        let alloc_len = 36u8;
        let (cdb, cdb_len) = scsi::inquiry(alloc_len);
        let cbw = Cbw::data_in(tag, alloc_len as u32, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: true,
            data_length: alloc_len as u32,
            tag,
        }
    }

    /// Process an INQUIRY response and update device info.
    pub fn process_inquiry_response(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let resp = scsi::InquiryResponse::from_bytes(data)
            .ok_or("USB-Storage: INQUIRY response too short")?;
        self.vendor = resp.vendor;
        self.product = resp.product;
        self.removable = resp.removable;
        Ok(())
    }

    /// Prepare a READ CAPACITY (10) command.
    /// Expects 8 bytes of data back.
    pub fn prepare_read_capacity(&mut self) -> PreparedCommand {
        let tag = self.alloc_tag();
        let (cdb, cdb_len) = scsi::read_capacity_10();
        let cbw = Cbw::data_in(tag, 8, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: true,
            data_length: 8,
            tag,
        }
    }

    /// Process a READ CAPACITY response and update device geometry.
    pub fn process_read_capacity_response(&mut self, data: &[u8]) -> Result<(), &'static str> {
        let resp = scsi::ReadCapacity10Response::from_bytes(data)
            .ok_or("USB-Storage: READ CAPACITY response too short")?;
        self.block_size = resp.block_length;
        self.total_blocks = resp.total_blocks();
        self.state = DeviceState::Ready;
        Ok(())
    }

    /// Prepare a REQUEST SENSE command.
    /// Expects 18 bytes of data back.
    pub fn prepare_request_sense(&mut self) -> PreparedCommand {
        let tag = self.alloc_tag();
        let (cdb, cdb_len) = scsi::request_sense(18);
        let cbw = Cbw::data_in(tag, 18, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: true,
            data_length: 18,
            tag,
        }
    }

    /// Process a REQUEST SENSE response.
    pub fn process_sense_response(&self, data: &[u8]) -> Option<scsi::SenseData> {
        scsi::SenseData::from_bytes(data)
    }

    /// Prepare a READ (10) command for reading sectors.
    ///
    /// - `lba`: Starting logical block address (32-bit).
    /// - `count`: Number of blocks to read (max 65535).
    pub fn prepare_read(&mut self, lba: u32, count: u16) -> PreparedCommand {
        let tag = self.alloc_tag();
        let data_len = count as u32 * self.block_size;
        let (cdb, cdb_len) = scsi::read_10(lba, count);
        let cbw = Cbw::data_in(tag, data_len, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: true,
            data_length: data_len,
            tag,
        }
    }

    /// Prepare a WRITE (10) command for writing sectors.
    ///
    /// - `lba`: Starting logical block address (32-bit).
    /// - `count`: Number of blocks to write (max 65535).
    pub fn prepare_write(&mut self, lba: u32, count: u16) -> PreparedCommand {
        let tag = self.alloc_tag();
        let data_len = count as u32 * self.block_size;
        let (cdb, cdb_len) = scsi::write_10(lba, count);
        let cbw = Cbw::data_out(tag, data_len, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: false,
            data_length: data_len,
            tag,
        }
    }

    /// Prepare a SYNCHRONIZE CACHE command (flush).
    pub fn prepare_sync_cache(&mut self) -> PreparedCommand {
        let tag = self.alloc_tag();
        let (cdb, cdb_len) = scsi::sync_cache_10();
        let cbw = Cbw::no_data(tag, self.lun, &cdb, cdb_len);
        PreparedCommand {
            cbw_bytes: cbw.to_bytes(),
            cbw,
            data_in: false,
            data_length: 0,
            tag,
        }
    }

    /// Validate a received CSW against a prepared command.
    pub fn validate_csw(&mut self, csw_bytes: &[u8; CSW_SIZE], expected_tag: u32) -> Result<(), CswError> {
        let csw = Csw::from_bytes(csw_bytes);
        let result = csw.validate(expected_tag);
        if let Err(CswError::PhaseError) = result {
            self.state = DeviceState::NeedsReset;
        }
        result
    }

    /// Mark the device as needing reset recovery.
    pub fn mark_needs_reset(&mut self) {
        self.state = DeviceState::NeedsReset;
    }

    /// Mark reset recovery complete.
    pub fn reset_complete(&mut self) {
        if self.state == DeviceState::NeedsReset {
            self.state = DeviceState::Ready;
        }
    }
}

// ---------------------------------------------------------------------------
// Reset Recovery protocol steps
// ---------------------------------------------------------------------------

/// Reset recovery sequence (caller must execute these USB control transfers):
///
/// 1. Bulk-Only Mass Storage Reset (class request 0xFF to interface).
/// 2. Clear Feature ENDPOINT_HALT on Bulk-IN endpoint.
/// 3. Clear Feature ENDPOINT_HALT on Bulk-OUT endpoint.
///
/// This module provides the setup packet bytes for each step.

/// Build the USB setup packet for Bulk-Only Mass Storage Reset.
///
/// - `interface`: The USB interface number.
///
/// Returns 8-byte setup packet (little-endian).
pub fn reset_recovery_setup(interface: u16) -> [u8; 8] {
    [
        crate::bbb::BOMSR_REQUEST_TYPE,
        crate::bbb::BOMSR_REQUEST,
        0, 0,                              // wValue = 0
        (interface & 0xFF) as u8,
        ((interface >> 8) & 0xFF) as u8,   // wIndex = interface
        0, 0,                              // wLength = 0
    ]
}

/// Build the USB setup packet for Clear Feature (ENDPOINT_HALT).
///
/// - `endpoint`: The endpoint address (e.g., 0x81 for Bulk-IN, 0x02 for Bulk-OUT).
///
/// Returns 8-byte setup packet.
pub fn clear_halt_setup(endpoint: u8) -> [u8; 8] {
    [
        crate::bbb::CLEAR_FEATURE_REQUEST_TYPE,
        crate::bbb::CLEAR_FEATURE_REQUEST,
        0, 0,             // wValue = ENDPOINT_HALT (0)
        endpoint, 0,      // wIndex = endpoint address
        0, 0,             // wLength = 0
    ]
}
