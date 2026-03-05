//! AHCI I/O operations: DMA read/write sectors using 48-bit LBA.

use crate::cmd::{CommandHeader, CommandTable, PrdtEntry, CFL_H2D, CH_FLAG_WRITE, CH_FLAG_CLEAR_BSY};
use crate::fis::FisRegH2D;
use crate::port::{self, WaitFn};

/// Maximum sectors per single DMA command (limited by PRDT entries).
/// With 8 PRDT entries, each up to 4 MB, and 512-byte sectors:
/// 8 * 4 MB / 512 = 65536 sectors. Limit to 128 for simplicity (64 KiB).
pub const MAX_SECTORS_PER_CMD: u16 = 128;

/// Issue a DMA read command on a port.
///
/// - `hba_base`: HBA MMIO base.
/// - `port_num`: Port number.
/// - `slot`: Command slot to use (usually 0).
/// - `lba`: Starting 48-bit LBA.
/// - `count`: Number of 512-byte sectors to read.
/// - `cl_virt`: Virtual address of the Command List for this port.
/// - `ct_virt`: Virtual address of the Command Table for this slot.
/// - `ct_phys`: Physical address of the Command Table.
/// - `buf_phys`: Physical address of the destination buffer.
/// - `wait`: Wait callback.
///
/// # Safety
/// All pointers and physical addresses must be valid.
pub unsafe fn read_sectors(
    hba_base: *mut u8,
    port_num: u8,
    slot: u8,
    lba: u64,
    count: u16,
    cl_virt: *mut u8,
    ct_virt: *mut u8,
    ct_phys: u64,
    buf_phys: u64,
    wait: WaitFn,
) -> Result<(), &'static str> {
    if count == 0 || count > MAX_SECTORS_PER_CMD {
        return Err("AHCI: invalid sector count");
    }

    // Wait for port to not be busy.
    unsafe { port::wait_busy(hba_base as *const u8, port_num, wait)? };

    let byte_count = count as u32 * 512;

    // Set up command header.
    let hdr = unsafe { &mut *(cl_virt as *mut CommandHeader).add(slot as usize) };
    // CFL=5, Read, PRDTL=1, Clear BSY.
    hdr.flags_cfl_prdtl = CFL_H2D | CH_FLAG_CLEAR_BSY | (1u32 << 16);
    hdr.prdbc = 0;
    hdr.ctba = ct_phys as u32;
    hdr.ctbau = (ct_phys >> 32) as u32;

    // Set up command table.
    let ct = unsafe { &mut *(ct_virt as *mut CommandTable) };
    unsafe { core::ptr::write_bytes(ct as *mut CommandTable as *mut u8, 0, core::mem::size_of::<CommandTable>()) };

    // Write READ DMA EXT FIS.
    let fis = FisRegH2D::read_dma_ext(lba, count);
    ct.set_cfis(&fis);

    // Set PRDT: single entry covering all sectors.
    ct.prdt[0] = PrdtEntry::new(buf_phys, byte_count, true);

    // Clear port interrupts.
    unsafe { port::clear_interrupts(hba_base, port_num) };

    // Issue command.
    unsafe { port::issue_command(hba_base, port_num, slot) };

    // Wait for completion.
    unsafe { port::wait_command(hba_base, port_num, slot, wait) }
}

/// Issue a DMA write command on a port.
///
/// Parameters are the same as `read_sectors`.
///
/// # Safety
/// All pointers and physical addresses must be valid.
pub unsafe fn write_sectors(
    hba_base: *mut u8,
    port_num: u8,
    slot: u8,
    lba: u64,
    count: u16,
    cl_virt: *mut u8,
    ct_virt: *mut u8,
    ct_phys: u64,
    buf_phys: u64,
    wait: WaitFn,
) -> Result<(), &'static str> {
    if count == 0 || count > MAX_SECTORS_PER_CMD {
        return Err("AHCI: invalid sector count");
    }

    // Wait for port to not be busy.
    unsafe { port::wait_busy(hba_base as *const u8, port_num, wait)? };

    let byte_count = count as u32 * 512;

    // Set up command header.
    let hdr = unsafe { &mut *(cl_virt as *mut CommandHeader).add(slot as usize) };
    // CFL=5, Write, PRDTL=1, Clear BSY.
    hdr.flags_cfl_prdtl = CFL_H2D | CH_FLAG_WRITE | CH_FLAG_CLEAR_BSY | (1u32 << 16);
    hdr.prdbc = 0;
    hdr.ctba = ct_phys as u32;
    hdr.ctbau = (ct_phys >> 32) as u32;

    // Set up command table.
    let ct = unsafe { &mut *(ct_virt as *mut CommandTable) };
    unsafe { core::ptr::write_bytes(ct as *mut CommandTable as *mut u8, 0, core::mem::size_of::<CommandTable>()) };

    // Write WRITE DMA EXT FIS.
    let fis = FisRegH2D::write_dma_ext(lba, count);
    ct.set_cfis(&fis);

    // Set PRDT: single entry covering all sectors.
    ct.prdt[0] = PrdtEntry::new(buf_phys, byte_count, true);

    // Clear port interrupts.
    unsafe { port::clear_interrupts(hba_base, port_num) };

    // Issue command.
    unsafe { port::issue_command(hba_base, port_num, slot) };

    // Wait for completion.
    unsafe { port::wait_command(hba_base, port_num, slot, wait) }
}

/// Issue a FLUSH CACHE EXT command on a port.
///
/// # Safety
/// All pointers must be valid.
pub unsafe fn flush(
    hba_base: *mut u8,
    port_num: u8,
    slot: u8,
    cl_virt: *mut u8,
    ct_virt: *mut u8,
    ct_phys: u64,
    wait: WaitFn,
) -> Result<(), &'static str> {
    unsafe { port::wait_busy(hba_base as *const u8, port_num, wait)? };

    let hdr = unsafe { &mut *(cl_virt as *mut CommandHeader).add(slot as usize) };
    hdr.flags_cfl_prdtl = CFL_H2D | CH_FLAG_CLEAR_BSY; // PRDTL = 0
    hdr.prdbc = 0;
    hdr.ctba = ct_phys as u32;
    hdr.ctbau = (ct_phys >> 32) as u32;

    let ct = unsafe { &mut *(ct_virt as *mut CommandTable) };
    unsafe { core::ptr::write_bytes(ct as *mut CommandTable as *mut u8, 0, core::mem::size_of::<CommandTable>()) };

    let fis = FisRegH2D::flush_ext();
    ct.set_cfis(&fis);

    unsafe { port::clear_interrupts(hba_base, port_num) };
    unsafe { port::issue_command(hba_base, port_num, slot) };
    unsafe { port::wait_command(hba_base, port_num, slot, wait) }
}
