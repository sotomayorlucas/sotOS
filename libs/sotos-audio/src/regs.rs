//! AC'97 register definitions and I/O port helpers.
//!
//! The AC'97 controller uses two I/O port regions:
//! - **Mixer Base (NAMBAR)**: Audio codec mixer registers (usually BAR0).
//! - **Bus Master Base (NABMBAR)**: Native Audio Bus Mastering registers (usually BAR1).

// ---------------------------------------------------------------------------
// Mixer Registers (offsets from NAMBAR / Mixer Base)
// ---------------------------------------------------------------------------

/// Reset Register — writing any value resets the codec.
pub const MIX_RESET: u16 = 0x00;
/// Master Volume (16-bit): bits 5:0 = right attenuation, bits 13:8 = left, bit 15 = mute.
pub const MIX_MASTER_VOL: u16 = 0x02;
/// Aux Out Volume (headphone on some codecs).
pub const MIX_AUX_OUT_VOL: u16 = 0x04;
/// Mono Volume.
pub const MIX_MONO_VOL: u16 = 0x06;
/// PC Beep Volume.
pub const MIX_PC_BEEP_VOL: u16 = 0x0A;
/// Phone Volume.
pub const MIX_PHONE_VOL: u16 = 0x0C;
/// Mic Volume (16-bit): bits 4:0 = gain, bit 6 = 20dB boost, bit 15 = mute.
pub const MIX_MIC_VOL: u16 = 0x0E;
/// Line In Volume.
pub const MIX_LINE_IN_VOL: u16 = 0x10;
/// CD Volume.
pub const MIX_CD_VOL: u16 = 0x12;
/// PCM Out Volume (16-bit): bits 4:0 = right atten, bits 12:8 = left, bit 15 = mute.
pub const MIX_PCM_OUT_VOL: u16 = 0x18;
/// Record Select — selects capture source.
pub const MIX_RECORD_SELECT: u16 = 0x1A;
/// Record Gain.
pub const MIX_RECORD_GAIN: u16 = 0x1C;
/// General Purpose — extended features.
pub const MIX_GENERAL_PURPOSE: u16 = 0x20;
/// Powerdown Control/Status.
pub const MIX_POWERDOWN: u16 = 0x26;
/// Extended Audio ID — indicates supported extensions (VRA, etc).
pub const MIX_EXT_AUDIO_ID: u16 = 0x28;
/// Extended Audio Status/Control — enable VRA (Variable Rate Audio), etc.
pub const MIX_EXT_AUDIO_CTRL: u16 = 0x2A;
/// Front DAC sample rate (when VRA enabled).
pub const MIX_FRONT_DAC_RATE: u16 = 0x2C;
/// Surround DAC sample rate (when VRA enabled).
pub const MIX_SURROUND_DAC_RATE: u16 = 0x2E;
/// LFE DAC sample rate (when VRA enabled).
pub const MIX_LFE_DAC_RATE: u16 = 0x30;
/// ADC sample rate (when VRA enabled).
pub const MIX_ADC_RATE: u16 = 0x32;
/// Vendor ID 1 (first 16 bits of codec vendor ID).
pub const MIX_VENDOR_ID1: u16 = 0x7C;
/// Vendor ID 2 (second 16 bits of codec vendor ID).
pub const MIX_VENDOR_ID2: u16 = 0x7E;

// ---------------------------------------------------------------------------
// Extended Audio ID bits (MIX_EXT_AUDIO_ID)
// ---------------------------------------------------------------------------

/// Variable Rate Audio support (bit 0).
pub const EXT_ID_VRA: u16 = 1 << 0;
/// Double Rate Audio support (bit 1).
pub const EXT_ID_DRA: u16 = 1 << 1;

// ---------------------------------------------------------------------------
// Extended Audio Control bits (MIX_EXT_AUDIO_CTRL)
// ---------------------------------------------------------------------------

/// Enable Variable Rate Audio (bit 0).
pub const EXT_CTRL_VRA: u16 = 1 << 0;
/// Enable Double Rate Audio (bit 1).
pub const EXT_CTRL_DRA: u16 = 1 << 1;

// ---------------------------------------------------------------------------
// Bus Master Registers (offsets from NABMBAR / Bus Master Base)
// Each channel (PCM In, PCM Out, Mic In) has a 16-byte register block.
// ---------------------------------------------------------------------------

/// PCM Input channel base offset.
pub const BM_PCM_IN: u16 = 0x00;
/// PCM Output channel base offset.
pub const BM_PCM_OUT: u16 = 0x10;
/// Microphone Input channel base offset.
pub const BM_MIC_IN: u16 = 0x20;

// Per-channel register offsets (add to channel base)

/// Buffer Descriptor List Base Address (32-bit, physical address of BDL).
pub const CH_BDBAR: u16 = 0x00;
/// Current Index Value (8-bit): index of the current BD being processed (0-31).
pub const CH_CIV: u16 = 0x04;
/// Last Valid Index (8-bit): index of the last valid BD (hardware stops after this).
pub const CH_LVI: u16 = 0x05;
/// Status Register (16-bit): interrupt and error status.
pub const CH_SR: u16 = 0x06;
/// Position in Current Buffer (16-bit): number of samples transferred.
pub const CH_PICB: u16 = 0x08;
/// Prefetch Index Value (8-bit): index of the BD being prefetched.
pub const CH_PIV: u16 = 0x0A;
/// Control Register (8-bit): DMA run/pause, reset, interrupt enables.
pub const CH_CR: u16 = 0x0B;

// ---------------------------------------------------------------------------
// Global Control/Status registers (offsets from NABMBAR)
// ---------------------------------------------------------------------------

/// Global Control (32-bit).
pub const BM_GLOB_CTRL: u16 = 0x2C;
/// Global Status (32-bit).
pub const BM_GLOB_STS: u16 = 0x30;

// ---------------------------------------------------------------------------
// Channel Status Register bits (CH_SR)
// ---------------------------------------------------------------------------

/// DMA Controller Halted.
pub const SR_DCH: u16 = 1 << 0;
/// Current Equals Last Valid (end of BDL reached).
pub const SR_CELV: u16 = 1 << 1;
/// Last Valid Buffer Completion Interrupt.
pub const SR_LVBCI: u16 = 1 << 2;
/// Buffer Completion Interrupt Status.
pub const SR_BCIS: u16 = 1 << 3;
/// FIFO Error (overrun/underrun).
pub const SR_FIFOE: u16 = 1 << 4;

// ---------------------------------------------------------------------------
// Channel Control Register bits (CH_CR)
// ---------------------------------------------------------------------------

/// Run/Pause Bus Master — 1 = run DMA, 0 = pause.
pub const CR_RPBM: u8 = 1 << 0;
/// Reset Registers — writing 1 resets the channel (self-clearing).
pub const CR_RR: u8 = 1 << 1;
/// Last Valid Buffer Interrupt Enable.
pub const CR_LVBIE: u8 = 1 << 2;
/// Buffer Completion Interrupt Enable (IOC in each BD).
pub const CR_IOCE: u8 = 1 << 3;
/// FIFO Error Interrupt Enable.
pub const CR_FEIE: u8 = 1 << 4;

// ---------------------------------------------------------------------------
// Global Control bits (BM_GLOB_CTRL)
// ---------------------------------------------------------------------------

/// Global Interrupt Enable.
pub const GC_GIE: u32 = 1 << 0;
/// Cold Reset — writing 0 asserts cold reset, 1 de-asserts.
pub const GC_COLD_RESET: u32 = 1 << 1;
/// Warm Reset — writing 1 initiates warm reset (self-clearing).
pub const GC_WARM_RESET: u32 = 1 << 2;
/// Shut Down — link entering low power.
pub const GC_SHUT_DOWN: u32 = 1 << 3;
/// 2-channel mode (bits 21:20 = 00).
pub const GC_CHAN_2: u32 = 0 << 20;
/// 4-channel mode (bits 21:20 = 01).
pub const GC_CHAN_4: u32 = 1 << 20;
/// 6-channel mode (bits 21:20 = 10).
pub const GC_CHAN_6: u32 = 2 << 20;

// ---------------------------------------------------------------------------
// Global Status bits (BM_GLOB_STS)
// ---------------------------------------------------------------------------

/// Primary Codec Ready.
pub const GS_PRIMARY_READY: u32 = 1 << 8;
/// Secondary Codec Ready.
pub const GS_SECONDARY_READY: u32 = 1 << 9;
/// Bit 28: S/PDIF Secondary Codec Ready.
pub const GS_SPDIF_READY: u32 = 1 << 28;

// ---------------------------------------------------------------------------
// Sample rate constants
// ---------------------------------------------------------------------------

/// Default AC'97 sample rate (48 kHz).
pub const SAMPLE_RATE_48000: u16 = 48000;
/// CD quality sample rate (44.1 kHz) — requires VRA.
pub const SAMPLE_RATE_44100: u16 = 44100;
/// Common lower sample rate (22.05 kHz) — requires VRA.
pub const SAMPLE_RATE_22050: u16 = 22050;
/// Common lower sample rate (16 kHz) — requires VRA.
pub const SAMPLE_RATE_16000: u16 = 16000;
/// Common lower sample rate (11.025 kHz) — requires VRA.
pub const SAMPLE_RATE_11025: u16 = 11025;
/// Common lower sample rate (8 kHz) — requires VRA.
pub const SAMPLE_RATE_8000: u16 = 8000;

// ---------------------------------------------------------------------------
// I/O port helpers
// ---------------------------------------------------------------------------

/// Read a 8-bit value from an I/O port.
///
/// # Safety
/// Caller must have I/O port access permission.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    }
    val
}

/// Write a 8-bit value to an I/O port.
///
/// # Safety
/// Caller must have I/O port access permission.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

/// Read a 16-bit value from an I/O port.
///
/// # Safety
/// Caller must have I/O port access permission.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack));
    }
    val
}

/// Write a 16-bit value to an I/O port.
///
/// # Safety
/// Caller must have I/O port access permission.
#[inline]
pub unsafe fn outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
    }
}

/// Read a 32-bit value from an I/O port.
///
/// # Safety
/// Caller must have I/O port access permission.
#[inline]
pub unsafe fn ind(port: u16) -> u32 {
    let val: u32;
    unsafe {
        core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack));
    }
    val
}

/// Write a 32-bit value to an I/O port.
///
/// # Safety
/// Caller must have I/O port access permission.
#[inline]
pub unsafe fn outd(port: u16, val: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
    }
}
