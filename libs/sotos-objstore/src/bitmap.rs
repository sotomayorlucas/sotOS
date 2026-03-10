//! Block allocation bitmap — pure functions on a byte array.

use crate::layout::BITMAP_BYTES;

/// Allocate `count` contiguous free blocks from the bitmap.
/// Returns the starting block index, or None if not enough space.
pub fn alloc_blocks(bitmap: &mut [u8; BITMAP_BYTES], max_blocks: u32, count: u32) -> Option<u32> {
    if count == 0 {
        return None;
    }
    // Clamp to bitmap capacity to prevent out-of-bounds access
    let max_blocks = max_blocks.min((BITMAP_BYTES as u32) * 8);
    let mut run_start: u32 = 0;
    let mut run_len: u32 = 0;
    let mut bit: u32 = 0;

    while bit < max_blocks {
        let byte_idx = (bit / 8) as usize;
        let b = bitmap[byte_idx];
        // Fast skip: entire byte allocated
        if b == 0xFF && bit % 8 == 0 {
            run_start = bit + 8;
            run_len = 0;
            bit += 8;
            continue;
        }
        let bit_idx = bit % 8;
        if b & (1 << bit_idx) != 0 {
            run_start = bit + 1;
            run_len = 0;
        } else {
            run_len += 1;
            if run_len == count {
                for bl in run_start..run_start + count {
                    let bi = (bl / 8) as usize;
                    let bb = bl % 8;
                    bitmap[bi] |= 1 << bb;
                }
                return Some(run_start);
            }
        }
        bit += 1;
    }
    None
}

/// Free `count` blocks starting at `start`.
pub fn free_blocks(bitmap: &mut [u8; BITMAP_BYTES], start: u32, count: u32) {
    let cap = (BITMAP_BYTES as u32) * 8;
    for b in start..start + count {
        if b >= cap { break; }
        let byte_idx = (b / 8) as usize;
        let bit_idx = b % 8;
        bitmap[byte_idx] &= !(1 << bit_idx);
    }
}

/// Count the number of free blocks in the bitmap (byte-level optimization).
pub fn count_free(bitmap: &[u8; BITMAP_BYTES], max_blocks: u32) -> u32 {
    let max_blocks = max_blocks.min((BITMAP_BYTES as u32) * 8);
    let full_bytes = (max_blocks / 8) as usize;
    let mut free = 0u32;
    // Count full bytes using popcount
    for i in 0..full_bytes {
        free += 8 - (bitmap[i].count_ones());
    }
    // Count remaining bits
    let remaining = max_blocks % 8;
    if remaining > 0 {
        let last_byte = bitmap[full_bytes];
        for bit in 0..remaining {
            if last_byte & (1 << bit) == 0 {
                free += 1;
            }
        }
    }
    free
}
