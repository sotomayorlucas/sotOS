//! PCM audio playback using the AC'97 PCM Out channel.
//!
//! Provides a high-level interface for setting up buffer descriptors,
//! starting playback, and handling buffer completion interrupts.

use crate::bdl::{Bdl, BDL_MAX_ENTRIES};
use crate::controller::{Ac97Controller, WaitFn};
use crate::regs;

/// Default number of DMA buffers for double-buffering.
pub const DEFAULT_BUF_COUNT: usize = 2;

/// Audio format descriptor.
#[derive(Clone, Copy)]
pub struct AudioFormat {
    /// Sample rate in Hz (e.g., 48000, 44100).
    pub sample_rate: u16,
    /// Number of channels (1 = mono, 2 = stereo).
    pub channels: u8,
    /// Bits per sample (always 16 for AC'97).
    pub bits_per_sample: u8,
}

impl AudioFormat {
    /// Standard CD quality: 44100 Hz, stereo, 16-bit.
    pub const fn cd_quality() -> Self {
        Self { sample_rate: 44100, channels: 2, bits_per_sample: 16 }
    }

    /// Default AC'97 format: 48000 Hz, stereo, 16-bit.
    pub const fn default_48k() -> Self {
        Self { sample_rate: 48000, channels: 2, bits_per_sample: 16 }
    }

    /// Bytes per sample frame (channels * bits_per_sample / 8).
    pub const fn frame_size(&self) -> usize {
        (self.channels as usize) * (self.bits_per_sample as usize / 8)
    }

    /// Calculate the number of bytes per second.
    pub const fn bytes_per_second(&self) -> u32 {
        self.sample_rate as u32 * self.frame_size() as u32
    }
}

/// Playback state machine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PlaybackState {
    /// Stopped / not configured.
    Stopped,
    /// Configured and ready to play.
    Ready,
    /// Actively playing.
    Playing,
    /// Paused (DMA halted, can resume).
    Paused,
}

/// PCM Out playback manager.
pub struct PcmPlayback {
    /// Number of active buffer descriptors.
    pub buf_count: usize,
    /// Size of each audio buffer in bytes.
    pub buf_size: u32,
    /// Current playback state.
    pub state: PlaybackState,
    /// Index of the next buffer to fill (for double-buffering).
    pub fill_index: usize,
    /// Total buffers completed (for statistics).
    pub buffers_completed: u64,
}

impl PcmPlayback {
    /// Create a new playback manager.
    pub const fn new() -> Self {
        Self {
            buf_count: 0,
            buf_size: 0,
            state: PlaybackState::Stopped,
            fill_index: 0,
            buffers_completed: 0,
        }
    }

    /// Configure playback with a BDL and DMA buffers.
    ///
    /// - `ctrl`: AC'97 controller reference.
    /// - `bdl`: Buffer Descriptor List to configure.
    /// - `buf_count`: Number of DMA buffers to use (1..=32).
    /// - `buf_base_phys`: Physical address of the first DMA buffer.
    /// - `buf_size`: Size of each buffer in bytes (must be even).
    /// - `bdl_phys`: Physical address of the BDL itself.
    /// - `wait`: Wait callback.
    ///
    /// # Safety
    /// Caller must ensure BDL and buffer memory is valid and DMA-accessible.
    pub unsafe fn configure(
        &mut self,
        ctrl: &Ac97Controller,
        bdl: &mut Bdl,
        buf_count: usize,
        buf_base_phys: u32,
        buf_size: u32,
        bdl_phys: u32,
        wait: WaitFn,
    ) -> Result<(), &'static str> {
        if buf_count == 0 || buf_count > BDL_MAX_ENTRIES {
            return Err("AC97: invalid buffer count");
        }
        if buf_size == 0 || buf_size & 1 != 0 {
            return Err("AC97: buffer size must be non-zero and even");
        }

        // Reset the PCM Out channel.
        unsafe { ctrl.reset_channel(regs::BM_PCM_OUT, wait) };

        // Configure the BDL: all buffers generate IOC.
        let ioc_mask = (1u32 << buf_count) - 1; // IOC on every buffer
        bdl.setup_ring(buf_count, buf_base_phys, buf_size, ioc_mask);

        // Set BDL base address.
        unsafe { ctrl.set_bdl(regs::BM_PCM_OUT, bdl_phys) };

        // Set Last Valid Index.
        unsafe { ctrl.set_lvi(regs::BM_PCM_OUT, (buf_count - 1) as u8) };

        self.buf_count = buf_count;
        self.buf_size = buf_size;
        self.fill_index = 0;
        self.state = PlaybackState::Ready;

        Ok(())
    }

    /// Start PCM playback (begin DMA).
    ///
    /// # Safety
    /// Caller must ensure buffers contain valid audio data.
    pub unsafe fn start(&mut self, ctrl: &Ac97Controller) -> Result<(), &'static str> {
        if self.state != PlaybackState::Ready && self.state != PlaybackState::Paused {
            return Err("AC97: not ready to play");
        }

        unsafe { ctrl.start_dma(regs::BM_PCM_OUT, true, true) };
        self.state = PlaybackState::Playing;
        Ok(())
    }

    /// Pause PCM playback (stop DMA without resetting).
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn pause(&mut self, ctrl: &Ac97Controller) -> Result<(), &'static str> {
        if self.state != PlaybackState::Playing {
            return Err("AC97: not playing");
        }

        unsafe { ctrl.stop_dma(regs::BM_PCM_OUT) };
        self.state = PlaybackState::Paused;
        Ok(())
    }

    /// Stop playback completely.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn stop(&mut self, ctrl: &Ac97Controller, wait: WaitFn) {
        unsafe { ctrl.reset_channel(regs::BM_PCM_OUT, wait) };
        self.state = PlaybackState::Stopped;
        self.fill_index = 0;
    }

    /// Handle a PCM Out interrupt. Returns the index of the completed buffer,
    /// or None if no buffer completion occurred.
    ///
    /// Clears the interrupt status bits and advances the fill index.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn handle_interrupt(&mut self, ctrl: &Ac97Controller) -> Option<usize> {
        let sr = unsafe { ctrl.channel_status(regs::BM_PCM_OUT) };

        if sr & regs::SR_BCIS != 0 {
            // Buffer completion interrupt — clear it.
            unsafe { ctrl.ack_status(regs::BM_PCM_OUT, regs::SR_BCIS) };

            let completed = self.fill_index;
            self.fill_index = (self.fill_index + 1) % self.buf_count;
            self.buffers_completed += 1;

            return Some(completed);
        }

        if sr & regs::SR_LVBCI != 0 {
            // Last Valid Buffer Completion — clear it.
            unsafe { ctrl.ack_status(regs::BM_PCM_OUT, regs::SR_LVBCI) };

            // For continuous playback, reset LVI to loop the ring.
            if self.state == PlaybackState::Playing {
                unsafe {
                    ctrl.set_lvi(regs::BM_PCM_OUT, (self.buf_count - 1) as u8);
                }
            }
        }

        if sr & regs::SR_FIFOE != 0 {
            // FIFO error — clear it.
            unsafe { ctrl.ack_status(regs::BM_PCM_OUT, regs::SR_FIFOE) };
        }

        None
    }

    /// Get the current DMA position: which buffer index is being played.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn current_buffer(&self, ctrl: &Ac97Controller) -> u8 {
        unsafe { ctrl.current_index(regs::BM_PCM_OUT) }
    }

    /// Check if the DMA engine is halted.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn is_halted(&self, ctrl: &Ac97Controller) -> bool {
        let sr = unsafe { ctrl.channel_status(regs::BM_PCM_OUT) };
        sr & regs::SR_DCH != 0
    }
}
