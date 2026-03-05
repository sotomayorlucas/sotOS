//! Block device trait and NVMe IPC backend for the ObjectStore.
//!
//! Provides a `BlockDevice` trait that abstracts over VirtioBlk and NVMe
//! (via IPC to the NVMe service process). This allows the ObjectStore to
//! use either backend without code changes.

use sotos_virtio::blk::VirtioBlk;
use sotos_common::sys;

/// Block device trait — unified interface for sector-level I/O.
pub trait BlockDevice {
    /// Read a single 512-byte sector into `buf`.
    fn read_sector(&mut self, sector: u32, buf: &mut [u8; 512]);
    /// Write a single 512-byte sector from `buf`.
    fn write_sector(&mut self, sector: u32, buf: &[u8; 512]);
    /// Return disk capacity in sectors.
    fn capacity(&self) -> u64;
    /// Return a pointer to the internal data buffer (for VirtioBlk compatibility).
    fn data_ptr(&self) -> *const u8;
    /// Return a mutable pointer to the internal data buffer.
    fn data_ptr_mut(&self) -> *mut u8;
    /// Read a sector using the internal data buffer (VirtioBlk-style).
    fn read_sector_buf(&mut self, sector: u64) -> Result<(), &'static str>;
    /// Write a sector using the internal data buffer (VirtioBlk-style).
    fn write_sector_buf(&mut self, sector: u64) -> Result<(), &'static str>;
}

/// VirtioBlk implementation of BlockDevice.
impl BlockDevice for VirtioBlk {
    fn read_sector(&mut self, sector: u32, buf: &mut [u8; 512]) {
        if self.read_sector(sector as u64).is_ok() {
            unsafe {
                core::ptr::copy_nonoverlapping(self.data_ptr(), buf.as_mut_ptr(), 512);
            }
        }
    }

    fn write_sector(&mut self, sector: u32, buf: &[u8; 512]) {
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), self.data_ptr_mut(), 512);
        }
        let _ = VirtioBlk::write_sector(self, sector as u64);
    }

    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn data_ptr(&self) -> *const u8 {
        VirtioBlk::data_ptr(self)
    }

    fn data_ptr_mut(&self) -> *mut u8 {
        VirtioBlk::data_ptr_mut(self)
    }

    fn read_sector_buf(&mut self, sector: u64) -> Result<(), &'static str> {
        VirtioBlk::read_sector(self, sector)
    }

    fn write_sector_buf(&mut self, sector: u64) -> Result<(), &'static str> {
        VirtioBlk::write_sector(self, sector)
    }
}

// ---------------------------------------------------------------
// NVMe IPC Backend
// ---------------------------------------------------------------

/// IPC message tags for NVMe service requests.
const NVME_IPC_READ: u64 = 1;
const NVME_IPC_WRITE: u64 = 2;
const NVME_IPC_CAPACITY: u64 = 3;

/// NVMe IPC backend — sends read/write requests to the NVMe service process
/// via synchronous IPC endpoints.
pub struct NvmeIpcBackend {
    /// Endpoint capability for communicating with the NVMe service.
    ep_cap: u64,
    /// Shared data buffer virtual address (must be mapped in both address spaces).
    data_buf_vaddr: u64,
    /// Cached disk capacity in sectors.
    cached_capacity: u64,
}

impl NvmeIpcBackend {
    /// Create a new NVMe IPC backend.
    ///
    /// - `ep_cap`: IPC endpoint capability for the NVMe service.
    /// - `data_buf_vaddr`: Virtual address of the shared data buffer (4 KiB page).
    pub fn new(ep_cap: u64, data_buf_vaddr: u64) -> Self {
        let mut backend = NvmeIpcBackend {
            ep_cap,
            data_buf_vaddr,
            cached_capacity: 0,
        };
        // Query capacity from the NVMe service.
        backend.cached_capacity = backend.query_capacity();
        backend
    }

    /// Query disk capacity from the NVMe service.
    fn query_capacity(&self) -> u64 {
        let msg = sotos_common::IpcMsg {
            tag: NVME_IPC_CAPACITY,
            regs: [0; 8],
        };
        match sys::call(self.ep_cap, &msg) {
            Ok(reply) => reply.regs[0],
            Err(_) => 0,
        }
    }
}

impl BlockDevice for NvmeIpcBackend {
    fn read_sector(&mut self, sector: u32, buf: &mut [u8; 512]) {
        let msg = sotos_common::IpcMsg {
            tag: NVME_IPC_READ,
            regs: [sector as u64, 0, 0, 0, 0, 0, 0, 0],
        };
        if sys::call(self.ep_cap, &msg).is_ok() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.data_buf_vaddr as *const u8,
                    buf.as_mut_ptr(),
                    512,
                );
            }
        }
    }

    fn write_sector(&mut self, sector: u32, buf: &[u8; 512]) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                self.data_buf_vaddr as *mut u8,
                512,
            );
        }
        let msg = sotos_common::IpcMsg {
            tag: NVME_IPC_WRITE,
            regs: [sector as u64, 0, 0, 0, 0, 0, 0, 0],
        };
        let _ = sys::call(self.ep_cap, &msg);
    }

    fn capacity(&self) -> u64 {
        self.cached_capacity
    }

    fn data_ptr(&self) -> *const u8 {
        self.data_buf_vaddr as *const u8
    }

    fn data_ptr_mut(&self) -> *mut u8 {
        self.data_buf_vaddr as *mut u8
    }

    fn read_sector_buf(&mut self, sector: u64) -> Result<(), &'static str> {
        let msg = sotos_common::IpcMsg {
            tag: NVME_IPC_READ,
            regs: [sector, 0, 0, 0, 0, 0, 0, 0],
        };
        sys::call(self.ep_cap, &msg).map_err(|_| "NVMe IPC read failed")?;
        Ok(())
    }

    fn write_sector_buf(&mut self, sector: u64) -> Result<(), &'static str> {
        let msg = sotos_common::IpcMsg {
            tag: NVME_IPC_WRITE,
            regs: [sector, 0, 0, 0, 0, 0, 0, 0],
        };
        sys::call(self.ep_cap, &msg).map_err(|_| "NVMe IPC write failed")?;
        Ok(())
    }
}
