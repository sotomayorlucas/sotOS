//! ObjectStore — transactional named blob storage on top of virtio-blk.

use sotos_common::sys;
use sotos_virtio::blk::VirtioBlk;
use crate::layout::*;
use crate::bitmap;
use crate::wal;

/// Virtual address where ObjectStore is placed (3 pages).
const STORE_VADDR: u64 = 0xD00000;
/// Virtual address for VFS temp buffer (1 page).
pub const TEMP_BUF_VADDR: u64 = 0xD03000;

/// WRITABLE flag for map syscall.
const MAP_WRITABLE: u64 = 2;

/// Maximum data size for an object (limited by temp buffer = 1 page).
pub const MAX_OBJ_SIZE: usize = 4096;

/// The in-memory object store state.
#[repr(C)]
pub struct ObjectStore {
    pub blk: VirtioBlk,
    pub sb: Superblock,
    pub dir: [DirEntry; DIR_ENTRY_COUNT],
    pub bitmap: [u8; BITMAP_BYTES],
    pub wal: WalHeader,
    pub wal_buf: [[u8; SECTOR_SIZE]; WAL_MAX_ENTRIES],
    pub sector_buf: [u8; SECTOR_SIZE],
}

fn dbg(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn dbg_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

/// Track whether pages have been allocated (static flag).
static mut PAGES_INITIALIZED: bool = false;

/// Allocate and map pages for the ObjectStore + temp buffer.
/// Idempotent — only allocates on first call.
fn init_pages() -> Result<(), &'static str> {
    unsafe {
        if PAGES_INITIALIZED {
            return Ok(());
        }
        PAGES_INITIALIZED = true;
    }
    // 3 pages for ObjectStore at 0xD00000.
    for i in 0..3u64 {
        let frame = sys::frame_alloc().map_err(|_| "frame_alloc for store")?;
        sys::map(STORE_VADDR + i * 4096, frame, MAP_WRITABLE).map_err(|_| "map store page")?;
    }
    // 1 page for temp buffer at 0xD03000.
    let frame = sys::frame_alloc().map_err(|_| "frame_alloc for temp")?;
    sys::map(TEMP_BUF_VADDR, frame, MAP_WRITABLE).map_err(|_| "map temp page")?;
    Ok(())
}

impl ObjectStore {
    /// Format a new filesystem on the disk and return a reference to the in-memory store.
    pub fn format(blk: VirtioBlk) -> Result<&'static mut Self, &'static str> {
        init_pages()?;

        let store = unsafe { &mut *(STORE_VADDR as *mut ObjectStore) };

        // Initialize all fields.
        store.blk = blk;

        let total_sectors = store.blk.capacity as u32;
        let data_count = if total_sectors > SECTOR_DATA {
            total_sectors - SECTOR_DATA
        } else {
            return Err("disk too small");
        };

        // Initialize superblock.
        store.sb = Superblock::zeroed();
        store.sb.magic = SUPERBLOCK_MAGIC;
        store.sb.version = FS_VERSION;
        store.sb.total_sectors = total_sectors;
        store.sb.data_start = SECTOR_DATA;
        store.sb.data_count = data_count;
        store.sb.bitmap_start = SECTOR_BITMAP;
        store.sb.dir_start = SECTOR_DIR;
        store.sb.dir_sectors = DIR_SECTORS;
        store.sb.next_oid = 1;
        store.sb.obj_count = 0;

        // Clear directory.
        store.dir = [DirEntry::zeroed(); DIR_ENTRY_COUNT];

        // Clear bitmap.
        store.bitmap = [0u8; BITMAP_BYTES];

        // Initialize WAL.
        store.wal = WalHeader::zeroed();
        store.wal.magic = WAL_MAGIC;

        // Clear WAL buffers.
        store.wal_buf = [[0u8; SECTOR_SIZE]; WAL_MAX_ENTRIES];
        store.sector_buf = [0u8; SECTOR_SIZE];

        // Write everything to disk.
        store.flush_superblock()?;
        store.flush_bitmap()?;
        store.flush_dir()?;
        store.flush_wal_header()?;

        dbg(b"OBJSTORE: formatted, ");
        dbg_u64(data_count as u64);
        dbg(b" data blocks\n");

        Ok(store)
    }

    /// Mount an existing filesystem from disk.
    pub fn mount(blk: VirtioBlk) -> Result<&'static mut Self, &'static str> {
        init_pages()?;

        let store = unsafe { &mut *(STORE_VADDR as *mut ObjectStore) };
        store.blk = blk;

        // Read superblock.
        store.blk.read_sector(SECTOR_SUPERBLOCK as u64)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                store.blk.data_ptr(),
                &mut store.sb as *mut Superblock as *mut u8,
                SECTOR_SIZE,
            );
        }
        if store.sb.magic != SUPERBLOCK_MAGIC {
            return Err("bad superblock magic");
        }
        if store.sb.version != FS_VERSION {
            return Err("unsupported version");
        }

        // WAL replay.
        let replayed = wal::replay(&mut store.blk, &mut store.wal, &mut store.wal_buf)?;
        if replayed {
            // Re-read superblock after replay (it may have been updated).
            store.blk.read_sector(SECTOR_SUPERBLOCK as u64)?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    store.blk.data_ptr(),
                    &mut store.sb as *mut Superblock as *mut u8,
                    SECTOR_SIZE,
                );
            }
        }

        // Read bitmap.
        store.read_bitmap()?;

        // Read directory.
        store.read_dir()?;

        Ok(store)
    }

    /// Create a new object with the given name and data. Returns the OID.
    pub fn create(&mut self, name: &[u8], data: &[u8]) -> Result<u64, &'static str> {
        if name.is_empty() || name.len() >= MAX_NAME_LEN {
            return Err("invalid name length");
        }
        if data.len() > MAX_OBJ_SIZE {
            return Err("data too large");
        }

        // Check for duplicate name.
        if self.find(name).is_some() {
            return Err("name already exists");
        }

        // Find free directory slot.
        let slot = self.dir.iter().position(|e| e.is_free())
            .ok_or("directory full")?;

        // Allocate data blocks.
        let sector_count = sectors_for(data.len());
        let sector_start = if sector_count > 0 {
            bitmap::alloc_blocks(&mut self.bitmap, self.sb.data_count, sector_count)
                .ok_or("no space")?
        } else {
            0
        };

        // Write data sectors.
        self.write_data(sector_start, data)?;

        // Fill directory entry.
        let oid = self.sb.next_oid;
        self.dir[slot] = DirEntry::zeroed();
        self.dir[slot].oid = oid;
        let copy_len = name.len().min(MAX_NAME_LEN - 1);
        self.dir[slot].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.dir[slot].size = data.len() as u64;
        self.dir[slot].sector_start = sector_start;
        self.dir[slot].sector_count = sector_count;
        self.dir[slot].created_tick = sys::rdtsc() as u32;
        self.dir[slot].modified_tick = self.dir[slot].created_tick;

        // Update superblock.
        self.sb.next_oid += 1;
        self.sb.obj_count += 1;

        // WAL commit: bitmap sector(s) + directory sector + superblock.
        self.wal_commit_metadata(slot)?;

        Ok(oid)
    }

    /// Read an object by OID into `buf`. Returns bytes read.
    pub fn read_obj(&mut self, oid: u64, buf: &mut [u8]) -> Result<usize, &'static str> {
        let slot = self.find_slot(oid).ok_or("object not found")?;
        let entry = &self.dir[slot];
        let size = entry.size as usize;
        if buf.len() < size {
            return Err("buffer too small");
        }

        self.read_data(entry.sector_start, entry.sector_count, &mut buf[..size])?;
        Ok(size)
    }

    /// Overwrite an object's data.
    pub fn write_obj(&mut self, oid: u64, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > MAX_OBJ_SIZE {
            return Err("data too large");
        }

        let slot = self.find_slot(oid).ok_or("object not found")?;

        // Free old blocks.
        let old_start = self.dir[slot].sector_start;
        let old_count = self.dir[slot].sector_count;
        if old_count > 0 {
            bitmap::free_blocks(&mut self.bitmap, old_start, old_count);
        }

        // Allocate new blocks.
        let new_count = sectors_for(data.len());
        let new_start = if new_count > 0 {
            bitmap::alloc_blocks(&mut self.bitmap, self.sb.data_count, new_count)
                .ok_or("no space")?
        } else {
            0
        };

        // Write new data.
        self.write_data(new_start, data)?;

        // Update directory entry.
        self.dir[slot].size = data.len() as u64;
        self.dir[slot].sector_start = new_start;
        self.dir[slot].sector_count = new_count;
        self.dir[slot].modified_tick = sys::rdtsc() as u32;

        // WAL commit.
        self.wal_commit_metadata(slot)?;

        Ok(())
    }

    /// Delete an object by OID.
    pub fn delete(&mut self, oid: u64) -> Result<(), &'static str> {
        let slot = self.find_slot(oid).ok_or("object not found")?;

        // Free data blocks.
        let start = self.dir[slot].sector_start;
        let count = self.dir[slot].sector_count;
        if count > 0 {
            bitmap::free_blocks(&mut self.bitmap, start, count);
        }

        // Clear directory entry.
        self.dir[slot] = DirEntry::zeroed();

        // Update superblock.
        self.sb.obj_count -= 1;

        // WAL commit.
        self.wal_commit_metadata(slot)?;

        Ok(())
    }

    /// Find an object by name. Returns OID or None.
    pub fn find(&self, name: &[u8]) -> Option<u64> {
        for entry in &self.dir {
            if !entry.is_free() && entry.name_as_str() == name {
                return Some(entry.oid);
            }
        }
        None
    }

    /// Get a copy of a directory entry by OID.
    pub fn stat(&self, oid: u64) -> Option<DirEntry> {
        self.find_slot(oid).map(|i| self.dir[i])
    }

    /// List all live objects. Returns count written.
    pub fn list(&self, out: &mut [DirEntry]) -> usize {
        let mut n = 0;
        for entry in &self.dir {
            if !entry.is_free() {
                if n < out.len() {
                    out[n] = *entry;
                }
                n += 1;
            }
        }
        n
    }

    /// Get the VirtioBlk device back (consumes the store logically, but since
    /// it's at a fixed address we just return the inner blk by-value equivalent).
    /// Caller must not use the store after this.
    pub fn into_blk(&mut self) -> VirtioBlk {
        // Safety: we move the blk out, replacing with a zeroed placeholder.
        // Caller must not use `self` after this.
        let blk_ptr = &self.blk as *const VirtioBlk;
        unsafe { core::ptr::read(blk_ptr) }
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    fn find_slot(&self, oid: u64) -> Option<usize> {
        self.dir.iter().position(|e| e.oid == oid)
    }

    /// Write data to consecutive sectors in the data region.
    fn write_data(&mut self, start_block: u32, data: &[u8]) -> Result<(), &'static str> {
        let count = sectors_for(data.len());
        for i in 0..count {
            let offset = i as usize * SECTOR_SIZE;
            let end = (offset + SECTOR_SIZE).min(data.len());

            // Clear sector buffer.
            self.sector_buf = [0u8; SECTOR_SIZE];

            if offset < data.len() {
                let len = end - offset;
                self.sector_buf[..len].copy_from_slice(&data[offset..offset + len]);
            }

            let abs_sector = self.sb.data_start + start_block + i;
            let dst = unsafe {
                core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE)
            };
            dst.copy_from_slice(&self.sector_buf);
            self.blk.write_sector(abs_sector as u64)?;
        }
        Ok(())
    }

    /// Read data from consecutive sectors in the data region.
    fn read_data(&mut self, start_block: u32, block_count: u32, buf: &mut [u8]) -> Result<(), &'static str> {
        for i in 0..block_count {
            let abs_sector = self.sb.data_start + start_block + i;
            self.blk.read_sector(abs_sector as u64)?;

            let offset = i as usize * SECTOR_SIZE;
            let remaining = buf.len() - offset;
            let copy_len = remaining.min(SECTOR_SIZE);

            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), copy_len) };
            buf[offset..offset + copy_len].copy_from_slice(src);
        }
        Ok(())
    }

    /// WAL-commit metadata changes (bitmap + directory entry sector + superblock).
    fn wal_commit_metadata(&mut self, dir_slot: usize) -> Result<(), &'static str> {
        wal::begin(&mut self.wal);

        // Stage superblock.
        let sb_buf = unsafe {
            &*((&self.sb as *const Superblock) as *const [u8; SECTOR_SIZE])
        };
        wal::stage(&mut self.wal, &mut self.wal_buf, SECTOR_SUPERBLOCK, sb_buf)?;

        // Stage directory sector containing the modified slot.
        let dir_sector_idx = dir_slot / DIR_ENTRIES_PER_SECTOR;
        let dir_abs_sector = SECTOR_DIR + dir_sector_idx as u32;
        let dir_buf = self.serialize_dir_sector(dir_sector_idx);
        wal::stage(&mut self.wal, &mut self.wal_buf, dir_abs_sector, &dir_buf)?;

        // Stage bitmap sector(s) — always write both.
        for i in 0..BITMAP_SECTORS {
            let bmp_offset = i as usize * SECTOR_SIZE;
            let mut bmp_buf = [0u8; SECTOR_SIZE];
            bmp_buf.copy_from_slice(&self.bitmap[bmp_offset..bmp_offset + SECTOR_SIZE]);
            wal::stage(&mut self.wal, &mut self.wal_buf, SECTOR_BITMAP + i, &bmp_buf)?;
        }

        wal::commit(&mut self.blk, &mut self.wal, &self.wal_buf)?;
        Ok(())
    }

    /// Serialize one directory sector (4 entries) into a 512-byte buffer.
    fn serialize_dir_sector(&self, sector_idx: usize) -> [u8; SECTOR_SIZE] {
        let mut buf = [0u8; SECTOR_SIZE];
        let base = sector_idx * DIR_ENTRIES_PER_SECTOR;
        for i in 0..DIR_ENTRIES_PER_SECTOR {
            let entry = &self.dir[base + i];
            let offset = i * 128;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    entry as *const DirEntry as *const u8,
                    buf[offset..].as_mut_ptr(),
                    128,
                );
            }
        }
        buf
    }

    /// Flush superblock to disk (non-WAL, for format).
    fn flush_superblock(&mut self) -> Result<(), &'static str> {
        let dst = unsafe {
            core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE)
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &self.sb as *const Superblock as *const u8,
                dst.as_mut_ptr(),
                SECTOR_SIZE,
            );
        }
        self.blk.write_sector(SECTOR_SUPERBLOCK as u64)
    }

    /// Flush bitmap to disk (non-WAL, for format).
    fn flush_bitmap(&mut self) -> Result<(), &'static str> {
        for i in 0..BITMAP_SECTORS {
            let offset = i as usize * SECTOR_SIZE;
            let dst = unsafe {
                core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE)
            };
            dst.copy_from_slice(&self.bitmap[offset..offset + SECTOR_SIZE]);
            self.blk.write_sector((SECTOR_BITMAP + i) as u64)?;
        }
        Ok(())
    }

    /// Flush all directory sectors to disk (non-WAL, for format).
    fn flush_dir(&mut self) -> Result<(), &'static str> {
        for s in 0..DIR_SECTORS as usize {
            let buf = self.serialize_dir_sector(s);
            let dst = unsafe {
                core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE)
            };
            dst.copy_from_slice(&buf);
            self.blk.write_sector((SECTOR_DIR + s as u32) as u64)?;
        }
        Ok(())
    }

    /// Flush WAL header to disk (non-WAL, for format).
    fn flush_wal_header(&mut self) -> Result<(), &'static str> {
        let dst = unsafe {
            core::slice::from_raw_parts_mut(self.blk.data_ptr_mut(), SECTOR_SIZE)
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                &self.wal as *const WalHeader as *const u8,
                dst.as_mut_ptr(),
                SECTOR_SIZE,
            );
        }
        self.blk.write_sector(SECTOR_WAL_HEADER as u64)
    }

    /// Read bitmap from disk into memory.
    fn read_bitmap(&mut self) -> Result<(), &'static str> {
        for i in 0..BITMAP_SECTORS {
            self.blk.read_sector((SECTOR_BITMAP + i) as u64)?;
            let offset = i as usize * SECTOR_SIZE;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
            self.bitmap[offset..offset + SECTOR_SIZE].copy_from_slice(src);
        }
        Ok(())
    }

    /// Read all directory sectors from disk into memory.
    fn read_dir(&mut self) -> Result<(), &'static str> {
        for s in 0..DIR_SECTORS as usize {
            self.blk.read_sector((SECTOR_DIR + s as u32) as u64)?;
            let src = unsafe { core::slice::from_raw_parts(self.blk.data_ptr(), SECTOR_SIZE) };
            let base = s * DIR_ENTRIES_PER_SECTOR;
            for i in 0..DIR_ENTRIES_PER_SECTOR {
                let offset = i * 128;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src[offset..].as_ptr(),
                        &mut self.dir[base + i] as *mut DirEntry as *mut u8,
                        128,
                    );
                }
            }
        }
        Ok(())
    }
}

/// Calculate number of sectors needed for `size` bytes.
fn sectors_for(size: usize) -> u32 {
    if size == 0 {
        0
    } else {
        ((size + SECTOR_SIZE - 1) / SECTOR_SIZE) as u32
    }
}
