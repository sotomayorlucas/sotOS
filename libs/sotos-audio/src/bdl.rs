//! Buffer Descriptor List (BDL) structures for AC'97 DMA transfers.
//!
//! The BDL is an array of up to 32 buffer descriptor entries. Each entry
//! points to a DMA buffer and specifies its length and flags.

/// Maximum number of entries in a Buffer Descriptor List.
pub const BDL_MAX_ENTRIES: usize = 32;

/// Maximum number of samples per buffer descriptor (0xFFFE = 65534).
/// Each sample is 16-bit stereo = 4 bytes, so max buffer = 65534 * 2 = 130068 bytes.
/// The count field is in samples (16-bit words), not bytes.
pub const BD_MAX_SAMPLES: u16 = 0xFFFE;

/// Buffer Descriptor Entry (8 bytes).
///
/// Each entry in the BDL describes one DMA buffer:
/// - `buf_addr`: 32-bit physical address of the audio data buffer.
/// - `cmd_len`: bits 15:0 = buffer length in samples (16-bit words),
///   bit 30 = BUP (buffer underrun policy: 0=last valid, 1=zero),
///   bit 31 = IOC (interrupt on completion).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BufferDescriptor {
    /// Physical address of the audio data buffer (must be aligned to sample size).
    pub buf_addr: u32,
    /// Bit 15:0 = number of samples (16-bit words) in this buffer.
    /// Bit 30 = BUP: Buffer Underrun Policy (1 = transmit zeros on underrun).
    /// Bit 31 = IOC: Interrupt On Completion.
    pub cmd_len: u32,
}

const _: () = assert!(core::mem::size_of::<BufferDescriptor>() == 8);

/// IOC (Interrupt On Completion) flag in `cmd_len`.
pub const BD_IOC: u32 = 1 << 31;
/// BUP (Buffer Underrun Policy) flag in `cmd_len`.
pub const BD_BUP: u32 = 1 << 30;

impl BufferDescriptor {
    /// Create a zeroed buffer descriptor.
    pub const fn zeroed() -> Self {
        Self { buf_addr: 0, cmd_len: 0 }
    }

    /// Create a new buffer descriptor.
    ///
    /// - `phys_addr`: Physical address of the audio data buffer.
    /// - `sample_count`: Number of 16-bit samples in the buffer.
    /// - `ioc`: If true, generate an interrupt when this buffer completes.
    /// - `bup`: If true, transmit zeros on buffer underrun instead of last valid.
    pub const fn new(phys_addr: u32, sample_count: u16, ioc: bool, bup: bool) -> Self {
        let mut flags = sample_count as u32;
        if ioc {
            flags |= BD_IOC;
        }
        if bup {
            flags |= BD_BUP;
        }
        Self {
            buf_addr: phys_addr,
            cmd_len: flags,
        }
    }

    /// Extract the sample count from this descriptor.
    pub const fn sample_count(&self) -> u16 {
        (self.cmd_len & 0xFFFF) as u16
    }

    /// Check whether IOC is set.
    pub const fn has_ioc(&self) -> bool {
        self.cmd_len & BD_IOC != 0
    }

    /// Check whether BUP is set.
    pub const fn has_bup(&self) -> bool {
        self.cmd_len & BD_BUP != 0
    }
}

/// Buffer Descriptor List — a fixed-size array of 32 entries.
///
/// The BDL must reside in physically contiguous memory accessible by DMA.
/// Total size = 32 * 8 = 256 bytes.
#[repr(C, align(8))]
pub struct Bdl {
    pub entries: [BufferDescriptor; BDL_MAX_ENTRIES],
}

const _: () = assert!(core::mem::size_of::<Bdl>() == 256);

impl Bdl {
    /// Create a zeroed BDL.
    pub const fn zeroed() -> Self {
        Self {
            entries: [BufferDescriptor::zeroed(); BDL_MAX_ENTRIES],
        }
    }

    /// Set up a ring of `count` buffer descriptors, each pointing to consecutive
    /// DMA buffers starting at `base_phys` with stride `buf_size_bytes`.
    ///
    /// - `count`: Number of buffers to use (1..=32).
    /// - `base_phys`: Physical address of the first audio buffer.
    /// - `buf_size_bytes`: Size of each buffer in bytes (must be even for 16-bit samples).
    /// - `ioc_mask`: Bitmask of which buffer indices should generate interrupts.
    ///
    /// Returns the number of entries configured.
    pub fn setup_ring(
        &mut self,
        count: usize,
        base_phys: u32,
        buf_size_bytes: u32,
        ioc_mask: u32,
    ) -> usize {
        let n = if count > BDL_MAX_ENTRIES { BDL_MAX_ENTRIES } else { count };
        // Sample count = bytes / 2 (each sample is one 16-bit word).
        let samples_per_buf = (buf_size_bytes / 2) as u16;

        for i in 0..n {
            let addr = base_phys + (i as u32) * buf_size_bytes;
            let ioc = (ioc_mask & (1 << i)) != 0;
            self.entries[i] = BufferDescriptor::new(addr, samples_per_buf, ioc, false);
        }

        // Zero remaining entries.
        for i in n..BDL_MAX_ENTRIES {
            self.entries[i] = BufferDescriptor::zeroed();
        }

        n
    }
}
