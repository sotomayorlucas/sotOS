//! AC'97 Mixer (codec) register access — volume control and sample rate.

use crate::regs;

/// AC'97 mixer access via I/O ports.
pub struct Ac97Mixer {
    /// Mixer base I/O port (NAMBAR, typically from PCI BAR0).
    pub base: u16,
}

/// Volume level (0 = max, 63 = min/mute for master; 31 = min for PCM).
/// The AC'97 uses attenuation-based volume: 0 is loudest.
#[derive(Clone, Copy)]
pub struct Volume {
    /// Left channel attenuation (0-63 for master, 0-31 for PCM).
    pub left: u8,
    /// Right channel attenuation (0-63 for master, 0-31 for PCM).
    pub right: u8,
    /// Mute flag.
    pub mute: bool,
}

impl Volume {
    /// Maximum volume (no attenuation, not muted).
    pub const fn max() -> Self {
        Self { left: 0, right: 0, mute: false }
    }

    /// Muted.
    pub const fn muted() -> Self {
        Self { left: 0, right: 0, mute: true }
    }

    /// Encode as the 16-bit AC'97 master volume register format.
    /// Bits 5:0 = right attenuation, bits 13:8 = left attenuation, bit 15 = mute.
    pub const fn encode_master(&self) -> u16 {
        let mut val = (self.right as u16 & 0x3F) | ((self.left as u16 & 0x3F) << 8);
        if self.mute {
            val |= 1 << 15;
        }
        val
    }

    /// Encode as the 16-bit AC'97 PCM out volume register format.
    /// Bits 4:0 = right attenuation, bits 12:8 = left attenuation, bit 15 = mute.
    pub const fn encode_pcm(&self) -> u16 {
        let mut val = (self.right as u16 & 0x1F) | ((self.left as u16 & 0x1F) << 8);
        if self.mute {
            val |= 1 << 15;
        }
        val
    }

    /// Encode as the 16-bit AC'97 mic volume register format.
    /// Bits 4:0 = gain, bit 6 = 20dB boost, bit 15 = mute.
    pub const fn encode_mic(&self) -> u16 {
        let mut val = self.right as u16 & 0x1F;
        if self.mute {
            val |= 1 << 15;
        }
        val
    }

    /// Decode from a master volume register value.
    pub const fn decode_master(val: u16) -> Self {
        Self {
            right: (val & 0x3F) as u8,
            left: ((val >> 8) & 0x3F) as u8,
            mute: val & (1 << 15) != 0,
        }
    }

    /// Decode from a PCM volume register value.
    pub const fn decode_pcm(val: u16) -> Self {
        Self {
            right: (val & 0x1F) as u8,
            left: ((val >> 8) & 0x1F) as u8,
            mute: val & (1 << 15) != 0,
        }
    }
}

impl Ac97Mixer {
    /// Create a mixer handle from the mixer base I/O port.
    pub const fn new(base: u16) -> Self {
        Self { base }
    }

    /// Read a 16-bit mixer register.
    ///
    /// # Safety
    /// Caller must have I/O port access permission for the mixer port range.
    pub unsafe fn read(&self, offset: u16) -> u16 {
        unsafe { regs::inw(self.base + offset) }
    }

    /// Write a 16-bit mixer register.
    ///
    /// # Safety
    /// Caller must have I/O port access permission for the mixer port range.
    pub unsafe fn write(&self, offset: u16, val: u16) {
        unsafe { regs::outw(self.base + offset, val) }
    }

    /// Reset the codec by writing to the reset register.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn reset(&self) {
        unsafe { self.write(regs::MIX_RESET, 0) };
    }

    /// Read the codec vendor ID (32-bit, from two 16-bit registers).
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn vendor_id(&self) -> u32 {
        let hi = unsafe { self.read(regs::MIX_VENDOR_ID1) } as u32;
        let lo = unsafe { self.read(regs::MIX_VENDOR_ID2) } as u32;
        (hi << 16) | lo
    }

    /// Set master volume.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_master_volume(&self, vol: Volume) {
        unsafe { self.write(regs::MIX_MASTER_VOL, vol.encode_master()) };
    }

    /// Get current master volume.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn get_master_volume(&self) -> Volume {
        Volume::decode_master(unsafe { self.read(regs::MIX_MASTER_VOL) })
    }

    /// Set PCM output volume.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_pcm_volume(&self, vol: Volume) {
        unsafe { self.write(regs::MIX_PCM_OUT_VOL, vol.encode_pcm()) };
    }

    /// Get current PCM output volume.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn get_pcm_volume(&self) -> Volume {
        Volume::decode_pcm(unsafe { self.read(regs::MIX_PCM_OUT_VOL) })
    }

    /// Set microphone volume.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_mic_volume(&self, vol: Volume) {
        unsafe { self.write(regs::MIX_MIC_VOL, vol.encode_mic()) };
    }

    /// Check if Variable Rate Audio (VRA) is supported.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn supports_vra(&self) -> bool {
        let ext_id = unsafe { self.read(regs::MIX_EXT_AUDIO_ID) };
        ext_id & regs::EXT_ID_VRA != 0
    }

    /// Enable Variable Rate Audio (VRA) if supported.
    /// Returns true if VRA was successfully enabled.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn enable_vra(&self) -> bool {
        if !unsafe { self.supports_vra() } {
            return false;
        }
        let ctrl = unsafe { self.read(regs::MIX_EXT_AUDIO_CTRL) };
        unsafe { self.write(regs::MIX_EXT_AUDIO_CTRL, ctrl | regs::EXT_CTRL_VRA) };
        // Verify it stuck.
        let readback = unsafe { self.read(regs::MIX_EXT_AUDIO_CTRL) };
        readback & regs::EXT_CTRL_VRA != 0
    }

    /// Set the front DAC (PCM out) sample rate.
    /// If VRA is not enabled, the codec always uses 48 kHz and this has no effect.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_sample_rate(&self, rate: u16) {
        unsafe { self.write(regs::MIX_FRONT_DAC_RATE, rate) };
    }

    /// Read back the current front DAC sample rate.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn get_sample_rate(&self) -> u16 {
        unsafe { self.read(regs::MIX_FRONT_DAC_RATE) }
    }

    /// Set the ADC (record) sample rate.
    ///
    /// # Safety
    /// Caller must have I/O port access permission.
    pub unsafe fn set_adc_rate(&self, rate: u16) {
        unsafe { self.write(regs::MIX_ADC_RATE, rate) };
    }
}
