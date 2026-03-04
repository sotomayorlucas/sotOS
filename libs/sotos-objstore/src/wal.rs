//! Write-Ahead Log for atomic multi-sector metadata updates.

use sotos_virtio::blk::VirtioBlk;
use crate::layout::*;

/// Begin a new WAL transaction (in-memory only).
pub fn begin(wal: &mut WalHeader) {
    wal.seq += 1;
    wal.entry_count = 0;
    wal.committed = 0;
}

/// Stage a sector image into the WAL payload buffer.
/// `data` must be exactly 512 bytes.
pub fn stage(
    wal: &mut WalHeader,
    wal_buf: &mut [[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
    target_sector: u32,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), &'static str> {
    let idx = wal.entry_count as usize;
    if idx >= WAL_MAX_ENTRIES {
        return Err("WAL full");
    }
    wal_buf[idx].copy_from_slice(data);
    wal.targets[idx] = target_sector;
    wal.entry_count += 1;
    Ok(())
}

/// Commit the WAL transaction to disk.
///
/// Phase 1: Write payload sectors (WAL sectors 2-5).
/// Phase 2: Write WAL header with committed=1 (commit point).
/// Phase 3: Apply payload to actual target sectors.
/// Phase 4: Write WAL header with committed=2 (applied).
pub fn commit(
    blk: &mut VirtioBlk,
    wal: &mut WalHeader,
    wal_buf: &[[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
) -> Result<(), &'static str> {
    let count = wal.entry_count as usize;
    if count == 0 {
        return Ok(());
    }

    // Phase 1: Write WAL payload sectors.
    for i in 0..count {
        write_sector_from(blk, SECTOR_WAL_PAYLOAD + i as u32, &wal_buf[i])?;
    }

    // Phase 2: Write WAL header with committed=1.
    wal.committed = 1;
    write_wal_header(blk, wal)?;

    // Phase 3: Apply — write payload to target sectors.
    for i in 0..count {
        write_sector_from(blk, wal.targets[i], &wal_buf[i])?;
    }

    // Phase 4: Mark WAL as applied.
    wal.committed = 2;
    write_wal_header(blk, wal)?;

    Ok(())
}

/// Replay the WAL if a committed-but-not-applied transaction exists.
/// Returns true if a replay was performed.
pub fn replay(
    blk: &mut VirtioBlk,
    wal: &mut WalHeader,
    wal_buf: &mut [[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
) -> Result<bool, &'static str> {
    // Read WAL header from disk.
    read_sector_into(blk, SECTOR_WAL_HEADER, unsafe {
        &mut *(wal as *mut WalHeader as *mut [u8; SECTOR_SIZE])
    })?;

    if wal.magic != WAL_MAGIC {
        // No valid WAL — initialize it.
        *wal = WalHeader::zeroed();
        wal.magic = WAL_MAGIC;
        return Ok(false);
    }

    match wal.committed {
        0 => {
            // Incomplete — discard.
            Ok(false)
        }
        1 => {
            // Committed but not applied — replay.
            let count = wal.entry_count as usize;
            // Read WAL payload sectors.
            for i in 0..count {
                read_sector_into(blk, SECTOR_WAL_PAYLOAD + i as u32, &mut wal_buf[i])?;
            }
            // Apply to target sectors.
            for i in 0..count {
                write_sector_from(blk, wal.targets[i], &wal_buf[i])?;
            }
            // Mark applied.
            wal.committed = 2;
            write_wal_header(blk, wal)?;
            Ok(true)
        }
        _ => {
            // Already applied (2) or unknown — nothing to do.
            Ok(false)
        }
    }
}

/// Write a 512-byte buffer to a sector via the blk data buffer.
fn write_sector_from(
    blk: &mut VirtioBlk,
    sector: u32,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), &'static str> {
    let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
    dst.copy_from_slice(data);
    blk.write_sector(sector as u64)
}

/// Read a sector into a 512-byte buffer via the blk data buffer.
fn read_sector_into(
    blk: &mut VirtioBlk,
    sector: u32,
    buf: &mut [u8; SECTOR_SIZE],
) -> Result<(), &'static str> {
    blk.read_sector(sector as u64)?;
    let src = unsafe { core::slice::from_raw_parts(blk.data_ptr(), SECTOR_SIZE) };
    buf.copy_from_slice(src);
    Ok(())
}

/// Serialize the WAL header struct and write to disk.
fn write_wal_header(
    blk: &mut VirtioBlk,
    wal: &WalHeader,
) -> Result<(), &'static str> {
    // Copy struct bytes into blk data buffer, then write.
    let dst = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), SECTOR_SIZE) };
    unsafe {
        core::ptr::copy_nonoverlapping(
            wal as *const WalHeader as *const u8,
            dst.as_mut_ptr(),
            SECTOR_SIZE,
        );
    }
    blk.write_sector(SECTOR_WAL_HEADER as u64)
}
