//! xHCI port management and input context construction.

use crate::regs;
use crate::controller::XhciController;

/// Scan all ports and return a bitmask of connected ports (1-based indexing).
pub unsafe fn connected_ports(ctrl: &XhciController) -> u32 {
    let mut mask: u32 = 0;
    for p in 1..=ctrl.max_ports {
        let portsc = ctrl.portsc(p);
        if portsc & regs::PORTSC_CCS != 0 {
            mask |= 1 << p;
        }
    }
    mask
}

/// Reset a port (1-based). Sets PR=1, PP=1, masks out RW1C bits.
pub unsafe fn reset_port(ctrl: &XhciController, port: u8) {
    let portsc = ctrl.portsc(port);
    let val = (portsc & !regs::PORTSC_RW1C_MASK) | regs::PORTSC_PR | regs::PORTSC_PP;
    ctrl.write_portsc(port, val);
}

/// Wait for port reset to complete (PRC bit set).
pub unsafe fn wait_port_reset(ctrl: &XhciController, port: u8, wait: fn()) -> bool {
    for _ in 0..100_000 {
        let portsc = ctrl.portsc(port);
        if portsc & regs::PORTSC_PRC != 0 {
            let val = (portsc & !regs::PORTSC_RW1C_MASK) | regs::PORTSC_PRC;
            ctrl.write_portsc(port, val);
            return true;
        }
        wait();
    }
    false
}

/// Build an Input Context for Address Device command (32-byte context mode, CSZ=0).
///
/// `speed`: port speed (1=FS, 2=LS, 3=HS, 4=SS) from PORTSC.
pub unsafe fn build_input_context(
    buf: *mut u8,
    root_port: u8,
    ep0_ring_phys: u64,
    speed: u8,
) {
    let icc = buf as *mut u32;
    // Add Context Flags: bit 0 (Slot) + bit 1 (EP0).
    core::ptr::write_volatile(icc.add(1), 0x3);

    // Slot Context at offset 32.
    let slot = buf.add(32) as *mut u32;
    // DW0: Context Entries = 1, Speed from port, Route String = 0.
    core::ptr::write_volatile(slot, (1u32 << 27) | ((speed as u32) << 20));
    // DW1: Root Hub Port Number.
    core::ptr::write_volatile(slot.add(1), (root_port as u32) << 16);

    // EP0 Context at offset 64.
    let ep0 = buf.add(64) as *mut u32;
    let max_packet = regs::ep0_max_packet_for_speed(speed);
    // DW1: EP Type = 4 (Control Bidi), MaxPacketSize, CErr = 3.
    core::ptr::write_volatile(ep0.add(1), ((max_packet as u32) << 16) | (4u32 << 3) | (3u32 << 1));
    // DW2-3: TR Dequeue Pointer | DCS=1.
    let ep0_dq = ep0.add(2) as *mut u64;
    core::ptr::write_volatile(ep0_dq, ep0_ring_phys | 1);
    // DW4: Average TRB Length = 8.
    core::ptr::write_volatile(ep0.add(4), 8);
}

/// Build an Input Context for Configure Endpoint command.
/// Adds an Interrupt IN endpoint (DCI `ep_dci`) with the given transfer ring.
///
/// `ep_dci`: Device Context Index for the endpoint (e.g., 3 for EP1 IN).
/// `max_packet`: max packet size for the interrupt endpoint (typically 8 for HID kbd).
/// `interval`: polling interval (xHCI encoding).
pub unsafe fn build_configure_ep_input(
    buf: *mut u8,
    ep_dci: u8,
    int_ring_phys: u64,
    max_packet: u16,
    interval: u8,
    speed: u8,
) {
    let icc = buf as *mut u32;
    // Add Context Flags: bit 0 (Slot) + bit for the endpoint DCI.
    core::ptr::write_volatile(icc.add(1), (1u32 << 0) | (1u32 << ep_dci));

    // Slot Context at offset 32: update Context Entries to include new DCI.
    let slot = buf.add(32) as *mut u32;
    core::ptr::write_volatile(slot, ((ep_dci as u32) << 27) | ((speed as u32) << 20));

    // Endpoint Context at offset 32 * (ep_dci + 1) — skipping ICC (32) + Slot (32) + previous EPs.
    // In 32-byte mode: offset = (ep_dci + 1) * 32 from input context base.
    // ICC=index0, Slot=index1, EP0(DCI1)=index2, EP1OUT(DCI2)=index3, EP1IN(DCI3)=index4...
    // EP context offset = 32 * (1 + ep_dci)
    let ep_offset = 32 * (1 + ep_dci as usize);
    let ep = buf.add(ep_offset) as *mut u32;
    // DW0: Interval (bits 23:16), bits 2:0 = EP State (will be set by HC).
    core::ptr::write_volatile(ep, (interval as u32) << 16);
    // DW1: EP Type = 7 (Interrupt IN), MaxPacketSize, CErr = 3.
    core::ptr::write_volatile(ep.add(1), ((max_packet as u32) << 16) | (7u32 << 3) | (3u32 << 1));
    // DW2-3: TR Dequeue Pointer | DCS=1.
    let ep_dq = ep.add(2) as *mut u64;
    core::ptr::write_volatile(ep_dq, int_ring_phys | 1);
    // DW4: Average TRB Length = 8 (HID report size).
    core::ptr::write_volatile(ep.add(4), 8);
}
