//! Block allocation bitmap — pure functions on a byte array.

use crate::layout::BITMAP_BYTES;

/// Allocate `count` contiguous free blocks from the bitmap.
/// Returns the starting block index, or None if not enough space.
pub fn alloc_blocks(bitmap: &mut [u8; BITMAP_BYTES], max_blocks: u32, count: u32) -> Option<u32> {
    if count == 0 {
        return None;
    }
    let mut run_start: u32 = 0;
    let mut run_len: u32 = 0;

    for bit in 0..max_blocks {
        let byte_idx = (bit / 8) as usize;
        let bit_idx = bit % 8;
        if bitmap[byte_idx] & (1 << bit_idx) != 0 {
            // Block is allocated, reset run.
            run_start = bit + 1;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len == count {
                // Mark blocks as allocated.
                for b in run_start..run_start + count {
                    let bi = (b / 8) as usize;
                    let bb = b % 8;
                    bitmap[bi] |= 1 << bb;
                }
                return Some(run_start);
            }
        }
    }
    None
}

/// Free `count` blocks starting at `start`.
pub fn free_blocks(bitmap: &mut [u8; BITMAP_BYTES], start: u32, count: u32) {
    for b in start..start + count {
        let byte_idx = (b / 8) as usize;
        let bit_idx = b % 8;
        bitmap[byte_idx] &= !(1 << bit_idx);
    }
}

/// Count the number of free blocks in the bitmap.
pub fn count_free(bitmap: &[u8; BITMAP_BYTES], max_blocks: u32) -> u32 {
    let mut free = 0u32;
    for bit in 0..max_blocks {
        let byte_idx = (bit / 8) as usize;
        let bit_idx = bit % 8;
        if bitmap[byte_idx] & (1 << bit_idx) == 0 {
            free += 1;
        }
    }
    free
}
