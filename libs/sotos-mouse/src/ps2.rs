//! PS/2 mouse protocol implementation.
//!
//! Supports both the standard 3-byte PS/2 mouse protocol and the
//! 4-byte IntelliMouse protocol with scroll wheel.

use crate::event::MouseEvent;

// ---------------------------------------------------------------------------
// PS/2 controller ports and commands
// ---------------------------------------------------------------------------

/// PS/2 data port.
pub const PS2_DATA_PORT: u16 = 0x60;
/// PS/2 command/status port.
pub const PS2_CMD_PORT: u16 = 0x64;

/// PS/2 controller command: write to auxiliary (mouse) device.
pub const CMD_WRITE_AUX: u8 = 0xD4;
/// PS/2 controller command: enable auxiliary (mouse) port.
pub const CMD_ENABLE_AUX: u8 = 0xA8;
/// PS/2 controller command: disable auxiliary (mouse) port.
pub const CMD_DISABLE_AUX: u8 = 0xA7;
/// PS/2 controller command: read controller configuration byte.
pub const CMD_READ_CONFIG: u8 = 0x20;
/// PS/2 controller command: write controller configuration byte.
pub const CMD_WRITE_CONFIG: u8 = 0x60;

/// PS/2 status register bit: output buffer full.
pub const STATUS_OUTPUT_FULL: u8 = 1 << 0;
/// PS/2 status register bit: input buffer full.
pub const STATUS_INPUT_FULL: u8 = 1 << 1;
/// PS/2 status register bit: data is from auxiliary device.
pub const STATUS_AUX_DATA: u8 = 1 << 5;

/// PS/2 controller config: enable auxiliary (mouse) IRQ (IRQ12).
pub const CONFIG_AUX_IRQ: u8 = 1 << 1;
/// PS/2 controller config: disable auxiliary clock (bit 5).
pub const CONFIG_AUX_CLOCK_DISABLE: u8 = 1 << 5;

// ---------------------------------------------------------------------------
// Mouse commands (sent via CMD_WRITE_AUX)
// ---------------------------------------------------------------------------

/// Reset mouse.
pub const MOUSE_CMD_RESET: u8 = 0xFF;
/// Set defaults.
pub const MOUSE_CMD_SET_DEFAULTS: u8 = 0xF6;
/// Enable data reporting.
pub const MOUSE_CMD_ENABLE_REPORTING: u8 = 0xF4;
/// Disable data reporting.
pub const MOUSE_CMD_DISABLE_REPORTING: u8 = 0xF5;
/// Set sample rate (followed by rate byte).
pub const MOUSE_CMD_SET_SAMPLE_RATE: u8 = 0xF3;
/// Get device ID.
pub const MOUSE_CMD_GET_ID: u8 = 0xF2;
/// Set resolution.
pub const MOUSE_CMD_SET_RESOLUTION: u8 = 0xE8;
/// Status request.
pub const MOUSE_CMD_STATUS_REQUEST: u8 = 0xE9;

/// Mouse ACK byte.
pub const MOUSE_ACK: u8 = 0xFA;
/// Mouse self-test passed.
pub const MOUSE_SELF_TEST_OK: u8 = 0xAA;

// ---------------------------------------------------------------------------
// Protocol detection
// ---------------------------------------------------------------------------

/// Mouse protocol type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MouseProtocol {
    /// Standard 3-byte PS/2 protocol (no scroll wheel).
    Standard,
    /// IntelliMouse 4-byte protocol (scroll wheel, device ID 0x03).
    IntelliMouse,
    /// IntelliMouse Explorer 4-byte protocol (5-button + scroll, device ID 0x04).
    Explorer,
}

// ---------------------------------------------------------------------------
// IntelliMouse activation sequence
// ---------------------------------------------------------------------------

/// The "magic" sample rate sequence to activate IntelliMouse scroll wheel.
/// Send SET_SAMPLE_RATE with values 200, 100, 80 in sequence.
/// Then GET_ID — if device returns 0x03, IntelliMouse is active.
pub const INTELLIMOUSE_SEQUENCE: [u8; 3] = [200, 100, 80];

/// The "magic" sample rate sequence to activate IntelliMouse Explorer (5 buttons).
/// Send SET_SAMPLE_RATE with values 200, 200, 80 in sequence.
/// Then GET_ID — if device returns 0x04, Explorer mode is active.
pub const EXPLORER_SEQUENCE: [u8; 3] = [200, 200, 80];

// ---------------------------------------------------------------------------
// PS/2 mouse packet parser
// ---------------------------------------------------------------------------

/// PS/2 mouse packet decoder.
///
/// Accumulates bytes from IRQ12 and produces `MouseEvent`s.
pub struct Ps2MouseDecoder {
    /// Current protocol (3-byte or 4-byte).
    pub protocol: MouseProtocol,
    /// Packet buffer (max 4 bytes).
    buf: [u8; 4],
    /// Current byte index in the packet.
    index: u8,
    /// Expected packet size (3 or 4).
    packet_size: u8,
}

impl Ps2MouseDecoder {
    /// Create a new decoder for the standard 3-byte protocol.
    pub const fn new() -> Self {
        Self {
            protocol: MouseProtocol::Standard,
            buf: [0; 4],
            index: 0,
            packet_size: 3,
        }
    }

    /// Set the protocol (after IntelliMouse detection).
    pub fn set_protocol(&mut self, protocol: MouseProtocol) {
        self.protocol = protocol;
        self.packet_size = match protocol {
            MouseProtocol::Standard => 3,
            MouseProtocol::IntelliMouse | MouseProtocol::Explorer => 4,
        };
        self.index = 0;
    }

    /// Feed a byte from IRQ12. Returns `Some(MouseEvent)` when a complete
    /// packet has been decoded.
    pub fn feed(&mut self, byte: u8) -> Option<MouseEvent> {
        // Synchronization: first byte must have bit 3 set (the "always 1" bit).
        if self.index == 0 && byte & 0x08 == 0 {
            // Out of sync — discard and wait for a valid first byte.
            return None;
        }

        self.buf[self.index as usize] = byte;
        self.index += 1;

        if self.index >= self.packet_size {
            self.index = 0;
            Some(self.decode_packet())
        } else {
            None
        }
    }

    /// Reset the decoder (e.g., after losing sync).
    pub fn reset(&mut self) {
        self.index = 0;
        self.buf = [0; 4];
    }

    /// Decode a complete packet into a MouseEvent.
    fn decode_packet(&self) -> MouseEvent {
        let status = self.buf[0];
        let raw_x = self.buf[1] as i16;
        let raw_y = self.buf[2] as i16;

        // Extract buttons from status byte.
        let buttons = status & 0x07; // bits 0-2: left, right, middle

        // Apply sign extension using overflow bits from status byte.
        // Bit 4 = X sign, bit 5 = Y sign.
        let dx = if status & (1 << 4) != 0 {
            // X is negative: sign-extend from 9 bits.
            raw_x | !0xFF // 0xFF..00 | raw_x
        } else {
            raw_x
        };

        let dy_raw = if status & (1 << 5) != 0 {
            raw_y | !0xFF
        } else {
            raw_y
        };

        // PS/2 Y-axis: positive = up. Negate for screen coordinates (positive = down).
        let dy = -dy_raw;

        // Scroll wheel (4-byte protocol only).
        let dz = if self.packet_size == 4 {
            // IntelliMouse: byte 3 is signed 8-bit scroll delta.
            match self.protocol {
                MouseProtocol::IntelliMouse => {
                    self.buf[3] as i8
                }
                MouseProtocol::Explorer => {
                    // Explorer: bits 3:0 are scroll (signed 4-bit), bits 5:4 are buttons 4,5.
                    let z_raw = self.buf[3] & 0x0F;
                    // Sign-extend from 4 bits.
                    if z_raw & 0x08 != 0 {
                        (z_raw | 0xF0) as i8
                    } else {
                        z_raw as i8
                    }
                }
                MouseProtocol::Standard => 0,
            }
        } else {
            0
        };

        // For Explorer protocol, also extract buttons 4 and 5 from byte 3.
        let mut final_buttons = buttons;
        if self.protocol == MouseProtocol::Explorer && self.packet_size == 4 {
            if self.buf[3] & 0x10 != 0 {
                final_buttons |= crate::event::BUTTON_4;
            }
            if self.buf[3] & 0x20 != 0 {
                final_buttons |= crate::event::BUTTON_5;
            }
        }

        // Check for overflow (bits 6,7 of status) — discard movement if overflowed.
        let x_overflow = status & (1 << 6) != 0;
        let y_overflow = status & (1 << 7) != 0;

        MouseEvent {
            buttons: final_buttons,
            dx: if x_overflow { 0 } else { dx },
            dy: if y_overflow { 0 } else { dy },
            dz,
        }
    }
}

// ---------------------------------------------------------------------------
// PS/2 I/O helpers (for use in the mouse service)
// ---------------------------------------------------------------------------

/// Wait until the PS/2 input buffer is empty (ready to receive a command).
/// Returns true if ready, false if timeout.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn wait_input_ready(max_iters: u32) -> bool {
    for _ in 0..max_iters {
        let status: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") status, in("dx") PS2_CMD_PORT as u16, options(nomem, nostack));
        }
        if status & STATUS_INPUT_FULL == 0 {
            return true;
        }
    }
    false
}

/// Wait until the PS/2 output buffer has data to read.
/// Returns true if data available, false if timeout.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn wait_output_ready(max_iters: u32) -> bool {
    for _ in 0..max_iters {
        let status: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") status, in("dx") PS2_CMD_PORT as u16, options(nomem, nostack));
        }
        if status & STATUS_OUTPUT_FULL != 0 {
            return true;
        }
    }
    false
}

/// Write a command byte to the PS/2 controller command port.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn write_cmd(cmd: u8) {
    unsafe {
        wait_input_ready(100_000);
        core::arch::asm!("out dx, al", in("dx") PS2_CMD_PORT as u16, in("al") cmd, options(nomem, nostack));
    }
}

/// Write a data byte to the PS/2 data port.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn write_data(data: u8) {
    unsafe {
        wait_input_ready(100_000);
        core::arch::asm!("out dx, al", in("dx") PS2_DATA_PORT as u16, in("al") data, options(nomem, nostack));
    }
}

/// Read a data byte from the PS/2 data port.
/// Returns None if timeout.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn read_data(max_iters: u32) -> Option<u8> {
    if !unsafe { wait_output_ready(max_iters) } {
        return None;
    }
    let data: u8;
    unsafe {
        core::arch::asm!("in al, dx", out("al") data, in("dx") PS2_DATA_PORT as u16, options(nomem, nostack));
    }
    Some(data)
}

/// Send a command byte to the mouse (via the PS/2 auxiliary port).
/// Waits for ACK (0xFA).
/// Returns true if ACK received.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn mouse_send(cmd: u8) -> bool {
    unsafe {
        write_cmd(CMD_WRITE_AUX);
        write_data(cmd);
    }
    // Wait for ACK.
    if let Some(response) = unsafe { read_data(100_000) } {
        response == MOUSE_ACK
    } else {
        false
    }
}

/// Send a command byte followed by a parameter to the mouse.
/// Waits for ACK after each byte.
///
/// # Safety
/// Caller must have I/O port access permission.
pub unsafe fn mouse_send_arg(cmd: u8, arg: u8) -> bool {
    if !unsafe { mouse_send(cmd) } {
        return false;
    }
    unsafe { mouse_send(arg) }
}
