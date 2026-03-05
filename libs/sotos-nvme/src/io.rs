//! NVMe I/O operations: read and write sectors.

use crate::cmd;
use crate::controller::{NvmeController, WaitFn};

/// Maximum pages in a single PRP List transfer (limited by a single PRP List page).
/// A 4 KiB PRP List page holds 512 entries (each u64 = 8 bytes).
pub const MAX_PRP_LIST_ENTRIES: usize = 512;

impl NvmeController {
    /// Read sectors from namespace 1 (single page, backward compatible).
    ///
    /// - `lba`: Starting logical block address.
    /// - `count`: Number of sectors to read (max depends on LBA size; 1 for single-page PRP).
    /// - `buf_phys`: Physical address of the destination buffer (must be page-aligned for DMA).
    pub fn read_sectors(&mut self, lba: u64, count: u16, buf_phys: u64, wait: WaitFn) -> Result<(), &'static str> {
        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_read(1, lba, count - 1, buf_phys); // NLB is 0-based
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Write sectors to namespace 1 (single page, backward compatible).
    ///
    /// - `lba`: Starting logical block address.
    /// - `count`: Number of sectors to write (1 for single-page PRP).
    /// - `buf_phys`: Physical address of the source buffer (must be page-aligned for DMA).
    pub fn write_sectors(&mut self, lba: u64, count: u16, buf_phys: u64, wait: WaitFn) -> Result<(), &'static str> {
        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_write(1, lba, count - 1, buf_phys); // NLB is 0-based
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Read multiple pages worth of sectors using PRP List.
    ///
    /// - `lba`: Starting LBA.
    /// - `count`: Number of sectors (0-based passed to HW).
    /// - `page_phys`: Array of physical page addresses (page-aligned).
    /// - `num_pages`: How many pages in the transfer.
    /// - `prp_list_phys`: Physical address of a page to use as PRP List (if > 2 pages).
    /// - `prp_list_virt`: Virtual address of the PRP List page.
    pub fn read_sectors_prp(
        &mut self,
        lba: u64,
        count: u16,
        page_phys: &[u64],
        prp_list_phys: u64,
        prp_list_virt: *mut u64,
        wait: WaitFn,
    ) -> Result<(), &'static str> {
        if page_phys.is_empty() {
            return Err("NVMe: empty page list");
        }

        let prp1 = page_phys[0];
        let prp2 = if page_phys.len() == 1 {
            0
        } else if page_phys.len() == 2 {
            page_phys[1]
        } else {
            // Build PRP List: page_phys[1..] entries in the PRP List page.
            let list_entries = page_phys.len() - 1;
            if list_entries > MAX_PRP_LIST_ENTRIES {
                return Err("NVMe: too many pages for PRP List");
            }
            for i in 0..list_entries {
                unsafe { core::ptr::write_volatile(prp_list_virt.add(i), page_phys[i + 1]); }
            }
            prp_list_phys
        };

        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_read_prp(1, lba, count, prp1, prp2);
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Write multiple pages worth of sectors using PRP List.
    pub fn write_sectors_prp(
        &mut self,
        lba: u64,
        count: u16,
        page_phys: &[u64],
        prp_list_phys: u64,
        prp_list_virt: *mut u64,
        wait: WaitFn,
    ) -> Result<(), &'static str> {
        if page_phys.is_empty() {
            return Err("NVMe: empty page list");
        }

        let prp1 = page_phys[0];
        let prp2 = if page_phys.len() == 1 {
            0
        } else if page_phys.len() == 2 {
            page_phys[1]
        } else {
            let list_entries = page_phys.len() - 1;
            if list_entries > MAX_PRP_LIST_ENTRIES {
                return Err("NVMe: too many pages for PRP List");
            }
            for i in 0..list_entries {
                unsafe { core::ptr::write_volatile(prp_list_virt.add(i), page_phys[i + 1]); }
            }
            prp_list_phys
        };

        let sq = self.io_sq.as_mut().ok_or("NVMe: I/O SQ not initialized")?;
        let entry = cmd::io_write_prp(1, lba, count, prp1, prp2);
        let _cid = sq.submit(entry);
        self.ring_io_sq_doorbell();
        self.poll_io_completion(wait)
    }

    /// Poll I/O completion queue for the next CQE.
    fn poll_io_completion(&mut self, wait: WaitFn) -> Result<(), &'static str> {
        for _ in 0..10_000_000 {
            let cq = self.io_cq.as_mut().ok_or("NVMe: I/O CQ not initialized")?;
            if let Some(cqe) = cq.poll() {
                cq.advance();
                self.ring_io_cq_doorbell();
                if cqe.status() != 0 {
                    return Err("NVMe: I/O operation failed");
                }
                return Ok(());
            }
            wait();
        }
        Err("NVMe: I/O timeout")
    }
}
