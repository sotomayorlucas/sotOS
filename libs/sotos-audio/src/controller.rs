//! AC'97 Bus Master controller initialization and channel management.

use crate::regs;
use crate::mixer::Ac97Mixer;

/// Wait callback — called while spinning for controller state changes.
pub type WaitFn = fn();

/// AC'97 controller state.
pub struct Ac97Controller {
    /// Bus Master base I/O port (NABMBAR, typically from PCI BAR1).
    pub bm_base: u16,
    /// Mixer handle.
    pub mixer: Ac97Mixer,
    /// Whether VRA (Variable Rate Audio) is enabled.
    pub vra_enabled: bool,
    /// Current PCM output sample rate.
    pub sample_rate: u16,
}

/// Result of controller initialization.
pub struct Ac97InitResult {
    /// Codec vendor ID.
    pub vendor_id: u32,
    /// Whether VRA is supported.
    pub vra_supported: bool,
    /// Whether VRA was enabled.
    pub vra_enabled: bool,
    /// Actual sample rate configured.
    pub sample_rate: u16,
}

impl Ac97Controller {
    /// Initialize the AC'97 controller.
    ///
    /// Performs the full initialization sequence:
    /// 1. Cold reset via Global Control register.
    /// 2. Wait for Primary Codec Ready in Global Status.
    /// 3. Reset the codec via mixer.
    /// 4. Unmute master and PCM output volumes.
    /// 5. Attempt to enable VRA and set desired sample rate.
    ///
    /// - `bm_base`: Bus Master I/O port base (NABMBAR from PCI BAR1).
    /// - `mixer_base`: Mixer I/O port base (NAMBAR from PCI BAR0).
    /// - `desired_rate`: Desired sample rate (e.g., 48000 or 44100).
    /// - `wait`: Callback for yielding while waiting.
    ///
    /// # Safety
    /// Caller must have I/O port access permission for both port ranges.
    pub unsafe fn init(
        bm_base: u16,
        mixer_base: u16,
        desired_rate: u16,
        wait: WaitFn,
    ) -> Result<(Self, Ac97InitResult), &'static str> {
        let mixer = Ac97Mixer::new(mixer_base);

        // 1. Perform cold reset: clear GC_COLD_RESET, wait, then set it.
        let gc = unsafe { regs::ind(bm_base + regs::BM_GLOB_CTRL) };
        unsafe { regs::outd(bm_base + regs::BM_GLOB_CTRL, gc & !regs::GC_COLD_RESET) };

        // Wait a bit for reset to take effect.
        for _ in 0..10_000 {
            wait();
        }

        // De-assert cold reset and enable interrupts.
        unsafe {
            regs::outd(
                bm_base + regs::BM_GLOB_CTRL,
                regs::GC_COLD_RESET | regs::GC_GIE,
            );
        }

        // 2. Wait for Primary Codec Ready.
        let mut ready = false;
        for _ in 0..1_000_000 {
            let gs = unsafe { regs::ind(bm_base + regs::BM_GLOB_STS) };
            if gs & regs::GS_PRIMARY_READY != 0 {
                ready = true;
                break;
            }
            wait();
        }
        if !ready {
            return Err("AC97: primary codec not ready");
        }

        // 3. Reset the codec.
        unsafe { mixer.reset() };

        // Small delay after codec reset.
        for _ in 0..10_000 {
            wait();
        }

        // Read vendor ID.
        let vendor_id = unsafe { mixer.vendor_id() };

        // 4. Unmute master and PCM output volumes.
        unsafe {
            mixer.set_master_volume(crate::mixer::Volume::max());
            mixer.set_pcm_volume(crate::mixer::Volume::max());
        }

        // 5. Try to enable VRA and set sample rate.
        let vra_supported = unsafe { mixer.supports_vra() };
        let mut vra_enabled = false;
        let mut actual_rate = regs::SAMPLE_RATE_48000;

        if vra_supported && desired_rate != regs::SAMPLE_RATE_48000 {
            vra_enabled = unsafe { mixer.enable_vra() };
            if vra_enabled {
                unsafe { mixer.set_sample_rate(desired_rate) };
                actual_rate = unsafe { mixer.get_sample_rate() };
            }
        } else if vra_supported {
            // Even at 48 kHz, enable VRA for explicit rate setting.
            vra_enabled = unsafe { mixer.enable_vra() };
            if vra_enabled {
                unsafe { mixer.set_sample_rate(regs::SAMPLE_RATE_48000) };
                actual_rate = unsafe { mixer.get_sample_rate() };
            }
        }

        let ctrl = Ac97Controller {
            bm_base,
            mixer,
            vra_enabled,
            sample_rate: actual_rate,
        };

        let result = Ac97InitResult {
            vendor_id,
            vra_supported,
            vra_enabled,
            sample_rate: actual_rate,
        };

        Ok((ctrl, result))
    }

    /// Reset a DMA channel.
    ///
    /// - `channel`: One of `BM_PCM_IN`, `BM_PCM_OUT`, or `BM_MIC_IN`.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn reset_channel(&self, channel: u16, wait: WaitFn) {
        let cr_port = self.bm_base + channel + regs::CH_CR;
        let sr_port = self.bm_base + channel + regs::CH_SR;

        // Stop DMA and assert reset.
        unsafe { regs::outb(cr_port, regs::CR_RR) };

        // Wait for DMA Controller Halted.
        for _ in 0..100_000 {
            let sr = unsafe { regs::inw(sr_port) };
            if sr & regs::SR_DCH != 0 {
                break;
            }
            wait();
        }

        // Clear all status bits by writing 1s (RW1C).
        unsafe {
            regs::outw(sr_port, regs::SR_LVBCI | regs::SR_BCIS | regs::SR_FIFOE);
        }
    }

    /// Set the Buffer Descriptor List base address for a channel.
    ///
    /// - `channel`: One of `BM_PCM_IN`, `BM_PCM_OUT`, or `BM_MIC_IN`.
    /// - `bdl_phys`: Physical address of the BDL (256-byte aligned).
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_bdl(&self, channel: u16, bdl_phys: u32) {
        unsafe {
            regs::outd(self.bm_base + channel + regs::CH_BDBAR, bdl_phys);
        }
    }

    /// Set the Last Valid Index for a channel.
    ///
    /// - `channel`: Channel base offset.
    /// - `lvi`: Last valid BD index (0-31).
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_lvi(&self, channel: u16, lvi: u8) {
        unsafe {
            regs::outb(self.bm_base + channel + regs::CH_LVI, lvi & 0x1F);
        }
    }

    /// Start DMA on a channel with interrupt enables.
    ///
    /// - `channel`: Channel base offset.
    /// - `enable_ioc`: Enable per-buffer IOC interrupts.
    /// - `enable_lvi`: Enable Last Valid Buffer interrupt.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn start_dma(&self, channel: u16, enable_ioc: bool, enable_lvi: bool) {
        let mut cr = regs::CR_RPBM;
        if enable_ioc {
            cr |= regs::CR_IOCE;
        }
        if enable_lvi {
            cr |= regs::CR_LVBIE;
        }
        cr |= regs::CR_FEIE; // Always enable FIFO error interrupts.
        unsafe { regs::outb(self.bm_base + channel + regs::CH_CR, cr) };
    }

    /// Stop DMA on a channel.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn stop_dma(&self, channel: u16) {
        let cr_port = self.bm_base + channel + regs::CH_CR;
        let cr = unsafe { regs::inb(cr_port) };
        unsafe { regs::outb(cr_port, cr & !regs::CR_RPBM) };
    }

    /// Read the current index value (CIV) for a channel.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn current_index(&self, channel: u16) -> u8 {
        unsafe { regs::inb(self.bm_base + channel + regs::CH_CIV) }
    }

    /// Read the channel status register.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn channel_status(&self, channel: u16) -> u16 {
        unsafe { regs::inw(self.bm_base + channel + regs::CH_SR) }
    }

    /// Acknowledge (clear) channel status interrupt bits.
    /// Write 1 to the bits you want to clear (RW1C).
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn ack_status(&self, channel: u16, bits: u16) {
        unsafe { regs::outw(self.bm_base + channel + regs::CH_SR, bits) };
    }

    /// Read position in current buffer (number of samples remaining).
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn position_in_buffer(&self, channel: u16) -> u16 {
        unsafe { regs::inw(self.bm_base + channel + regs::CH_PICB) }
    }

    /// Read the Global Status register.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn global_status(&self) -> u32 {
        unsafe { regs::ind(self.bm_base + regs::BM_GLOB_STS) }
    }
}
