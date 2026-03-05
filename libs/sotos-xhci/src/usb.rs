//! USB descriptor parsing and setup packet helpers.

// ---------------------------------------------------------------------------
// USB Setup Packet helpers
// ---------------------------------------------------------------------------

/// Pack a USB setup packet into a u64 (little-endian, for IDT in Setup Stage TRB).
/// Fields: bmRequestType(1), bRequest(1), wValue(2), wIndex(2), wLength(2).
pub fn setup_packet(
    bm_request_type: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
) -> u64 {
    (bm_request_type as u64)
        | ((b_request as u64) << 8)
        | ((w_value as u64) << 16)
        | ((w_index as u64) << 32)
        | ((w_length as u64) << 48)
}

// Standard requests.
pub const REQ_GET_DESCRIPTOR: u8 = 6;
pub const REQ_SET_CONFIGURATION: u8 = 9;

// HID class requests (bmRequestType = 0x21 for interface OUT).
pub const REQ_SET_PROTOCOL: u8 = 0x0B;
pub const REQ_SET_IDLE: u8 = 0x0A;

// Descriptor types.
pub const DESC_DEVICE: u8 = 1;
pub const DESC_CONFIGURATION: u8 = 2;
pub const DESC_INTERFACE: u8 = 4;
pub const DESC_ENDPOINT: u8 = 5;

// HID class/protocol.
pub const HID_CLASS: u8 = 3;
pub const HID_SUBCLASS_BOOT: u8 = 1;
pub const HID_PROTOCOL_KEYBOARD: u8 = 1;

/// GET_DESCRIPTOR(Device, 18 bytes) setup packet.
pub fn get_device_descriptor() -> u64 {
    setup_packet(0x80, REQ_GET_DESCRIPTOR, (DESC_DEVICE as u16) << 8, 0, 18)
}

/// GET_DESCRIPTOR(Configuration, `length` bytes) setup packet.
pub fn get_config_descriptor(length: u16) -> u64 {
    setup_packet(0x80, REQ_GET_DESCRIPTOR, (DESC_CONFIGURATION as u16) << 8, 0, length)
}

/// SET_CONFIGURATION(config_value) setup packet.
pub fn set_configuration(config_value: u8) -> u64 {
    setup_packet(0x00, REQ_SET_CONFIGURATION, config_value as u16, 0, 0)
}

/// SET_PROTOCOL(protocol, interface) setup packet. protocol=0 for boot.
pub fn set_protocol(protocol: u8, interface: u16) -> u64 {
    setup_packet(0x21, REQ_SET_PROTOCOL, protocol as u16, interface, 0)
}

/// SET_IDLE(duration=0, interface) setup packet.
pub fn set_idle(interface: u16) -> u64 {
    setup_packet(0x21, REQ_SET_IDLE, 0, interface, 0)
}

// ---------------------------------------------------------------------------
// Configuration descriptor parsing
// ---------------------------------------------------------------------------

/// Result of parsing a configuration descriptor for a HID keyboard.
pub struct HidKbdInfo {
    pub config_value: u8,
    pub interface_num: u8,
    pub ep_addr: u8,      // e.g. 0x81 = EP1 IN
    pub max_packet: u16,
    pub interval: u8,     // bInterval from endpoint descriptor
}

/// Parse a configuration descriptor buffer to find a HID boot keyboard interface
/// and its interrupt IN endpoint.
/// Returns None if no HID keyboard found.
pub fn parse_config_for_hid_kbd(buf: &[u8]) -> Option<HidKbdInfo> {
    if buf.len() < 9 {
        return None;
    }
    let config_value = buf[5];
    let total_len = (buf[2] as usize) | ((buf[3] as usize) << 8);
    let parse_len = if total_len < buf.len() { total_len } else { buf.len() };

    let mut offset = 0;
    let mut found_hid_kbd = false;
    let mut interface_num: u8 = 0;

    while offset + 1 < parse_len {
        let desc_len = buf[offset] as usize;
        let desc_type = buf[offset + 1];
        if desc_len < 2 || offset + desc_len > parse_len {
            break;
        }

        if desc_type == DESC_INTERFACE && desc_len >= 9 {
            let iface_class = buf[offset + 5];
            let iface_subclass = buf[offset + 6];
            let iface_protocol = buf[offset + 7];
            if iface_class == HID_CLASS
                && iface_subclass == HID_SUBCLASS_BOOT
                && iface_protocol == HID_PROTOCOL_KEYBOARD
            {
                found_hid_kbd = true;
                interface_num = buf[offset + 2];
            } else {
                found_hid_kbd = false;
            }
        }

        if desc_type == DESC_ENDPOINT && desc_len >= 7 && found_hid_kbd {
            let ep_addr = buf[offset + 2];
            // Check if Interrupt IN (bit 7 = IN, bits 1:0 of bmAttributes = 3 = Interrupt).
            if (ep_addr & 0x80) != 0 && (buf[offset + 3] & 0x03) == 3 {
                let max_packet = (buf[offset + 4] as u16) | ((buf[offset + 5] as u16) << 8);
                let interval = buf[offset + 6];
                return Some(HidKbdInfo {
                    config_value,
                    interface_num,
                    ep_addr,
                    max_packet,
                    interval,
                });
            }
        }

        offset += desc_len;
    }
    None
}

/// Convert a USB endpoint address to xHCI Device Context Index (DCI).
/// IN endpoints: DCI = ep_num * 2 + 1
/// OUT endpoints: DCI = ep_num * 2
pub fn ep_addr_to_dci(ep_addr: u8) -> u8 {
    let ep_num = ep_addr & 0x0F;
    if ep_addr & 0x80 != 0 {
        ep_num * 2 + 1  // IN
    } else {
        ep_num * 2      // OUT
    }
}

/// Convert a USB bInterval to xHCI interval encoding.
/// For FS/LS interrupt endpoints, xHCI interval = bInterval + 3 (mapped to 125us frames).
/// For HS/SS, xHCI interval = bInterval - 1.
pub fn convert_interval(b_interval: u8, speed: u8) -> u8 {
    match speed {
        1 | 2 => {
            // Full/Low speed: interval in ms (1-255). Convert to 125us frames.
            // xHCI wants exponent: 2^(interval) * 125us. Closest: interval + 3.
            let mut val = b_interval as u32;
            if val == 0 { val = 1; }
            // Find closest power of 2 >= val ms in 125us frames (8 frames = 1ms).
            let frames = val * 8;
            let mut exp: u8 = 0;
            let mut f = 1u32;
            while f < frames && exp < 15 {
                f *= 2;
                exp += 1;
            }
            exp
        }
        _ => {
            // High/SuperSpeed: already in 125us exponent form.
            if b_interval > 0 { b_interval - 1 } else { 0 }
        }
    }
}
