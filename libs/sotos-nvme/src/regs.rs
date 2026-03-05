//! NVMe controller MMIO register offsets and volatile access helpers.

/// Controller Capabilities (64-bit, read-only).
pub const REG_CAP: usize = 0x00;
/// Version (32-bit, read-only).
pub const REG_VS: usize = 0x08;
/// Interrupt Mask Set (32-bit, read-write).
pub const REG_INTMS: usize = 0x0C;
/// Interrupt Mask Clear (32-bit, read-write).
pub const REG_INTMC: usize = 0x10;
/// Controller Configuration (32-bit, read-write).
pub const REG_CC: usize = 0x14;
/// Controller Status (32-bit, read-only).
pub const REG_CSTS: usize = 0x1C;
/// Admin Queue Attributes (32-bit, read-write).
pub const REG_AQA: usize = 0x24;
/// Admin Submission Queue Base Address (64-bit, read-write).
pub const REG_ASQ: usize = 0x28;
/// Admin Completion Queue Base Address (64-bit, read-write).
pub const REG_ACQ: usize = 0x30;

/// CC.EN bit — controller enable.
pub const CC_EN: u32 = 1 << 0;
/// CC.CSS = NVM command set (bits 6:4 = 0).
pub const CC_CSS_NVM: u32 = 0 << 4;
/// CC.MPS = 4 KiB pages (bits 10:7 = 0, meaning 2^(12+0) = 4096).
pub const CC_MPS_4K: u32 = 0 << 7;
/// CC.AMS = Round Robin (bits 13:11 = 0).
pub const CC_AMS_RR: u32 = 0 << 11;
/// CC.IOSQES = 6 (64 bytes, bits 19:16).
pub const CC_IOSQES_64: u32 = 6 << 16;
/// CC.IOCQES = 4 (16 bytes, bits 23:20).
pub const CC_IOCQES_16: u32 = 4 << 20;

/// CSTS.RDY bit — controller ready.
pub const CSTS_RDY: u32 = 1 << 0;

/// Volatile read of a 32-bit MMIO register.
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn read32(base: *const u8, offset: usize) -> u32 {
    let ptr = base.add(offset) as *const u32;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile write of a 32-bit MMIO register.
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn write32(base: *mut u8, offset: usize, val: u32) {
    let ptr = base.add(offset) as *mut u32;
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Volatile read of a 64-bit MMIO register.
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn read64(base: *const u8, offset: usize) -> u64 {
    let ptr = base.add(offset) as *const u64;
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Volatile write of a 64-bit MMIO register.
///
/// # Safety
/// `base` must point to valid MMIO memory (UC-mapped).
#[inline]
pub unsafe fn write64(base: *mut u8, offset: usize, val: u64) {
    let ptr = base.add(offset) as *mut u64;
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Extract MQES (Maximum Queue Entries Supported) from CAP register.
/// Returns 0-based value (actual max = MQES + 1).
pub fn cap_mqes(cap: u64) -> u16 {
    (cap & 0xFFFF) as u16
}

/// Extract DSTRD (Doorbell Stride) from CAP register.
/// Doorbell register offset stride = 2^(2 + DSTRD) bytes.
pub fn cap_dstrd(cap: u64) -> u8 {
    ((cap >> 32) & 0xF) as u8
}

/// Calculate the Submission Queue y Tail Doorbell offset.
/// Formula: 0x1000 + (2y * (4 << DSTRD))
pub fn sq_doorbell_offset(qid: u16, dstrd: u8) -> usize {
    0x1000 + (2 * qid as usize) * (4 << dstrd as usize)
}

/// Calculate the Completion Queue y Head Doorbell offset.
/// Formula: 0x1000 + (2y + 1) * (4 << DSTRD)
pub fn cq_doorbell_offset(qid: u16, dstrd: u8) -> usize {
    0x1000 + (2 * qid as usize + 1) * (4 << dstrd as usize)
}
