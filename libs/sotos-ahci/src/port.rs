//! AHCI port management — initialization, command engine control, probing.

use crate::regs;

/// Wait callback — called while spinning for hardware state changes.
pub type WaitFn = fn();

/// Device type detected on a port.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// No device detected.
    None,
    /// SATA drive (ATA).
    Sata,
    /// SATAPI device (ATAPI, e.g., optical drive).
    Satapi,
    /// Enclosure management bridge.
    Semb,
    /// Port multiplier.
    PortMultiplier,
    /// Unknown signature.
    Unknown(u32),
}

/// Probe a port and determine what device (if any) is attached.
///
/// - `hba_base`: HBA MMIO base address.
/// - `port`: Port number (0-31).
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn probe_port(hba_base: *const u8, port: u8) -> DeviceType {
    let base = port_base(hba_base, port);

    let ssts = unsafe { regs::read32(base, regs::PORT_SSTS) };
    let det = ssts & regs::SSTS_DET_MASK;
    let ipm = ssts & regs::SSTS_IPM_MASK;

    // Device must be present and in active state.
    if det != regs::SSTS_DET_PRESENT || ipm != regs::SSTS_IPM_ACTIVE {
        return DeviceType::None;
    }

    let sig = unsafe { regs::read32(base, regs::PORT_SIG) };
    match sig {
        regs::SIG_ATA => DeviceType::Sata,
        regs::SIG_ATAPI => DeviceType::Satapi,
        regs::SIG_SEMB => DeviceType::Semb,
        regs::SIG_PM => DeviceType::PortMultiplier,
        _ => DeviceType::Unknown(sig),
    }
}

/// Calculate the base address for a port's register block.
fn port_base(hba_base: *const u8, port: u8) -> *const u8 {
    unsafe { hba_base.add(regs::port_offset(port)) }
}

/// Calculate the mutable base address for a port's register block.
fn port_base_mut(hba_base: *mut u8, port: u8) -> *mut u8 {
    unsafe { hba_base.add(regs::port_offset(port)) }
}

/// Stop the command engine on a port.
///
/// Clears CMD.ST and CMD.FRE, then waits for CMD.CR and CMD.FR to clear.
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn stop_cmd(hba_base: *mut u8, port: u8, wait: WaitFn) -> Result<(), &'static str> {
    let base = port_base_mut(hba_base, port);

    let mut cmd = unsafe { regs::read32(base as *const u8, regs::PORT_CMD) };

    // If neither ST nor CR is set, engine is already stopped.
    if cmd & (regs::CMD_ST | regs::CMD_CR) == 0 {
        // Also clear FRE.
        cmd &= !regs::CMD_FRE;
        unsafe { regs::write32(base, regs::PORT_CMD, cmd) };
        return Ok(());
    }

    // Clear ST.
    cmd &= !regs::CMD_ST;
    unsafe { regs::write32(base, regs::PORT_CMD, cmd) };

    // Wait for CR to clear (up to 500ms equivalent in iterations).
    for _ in 0..500_000 {
        let c = unsafe { regs::read32(base as *const u8, regs::PORT_CMD) };
        if c & regs::CMD_CR == 0 {
            break;
        }
        wait();
    }

    // Clear FRE.
    cmd = unsafe { regs::read32(base as *const u8, regs::PORT_CMD) };
    cmd &= !regs::CMD_FRE;
    unsafe { regs::write32(base, regs::PORT_CMD, cmd) };

    // Wait for FR to clear.
    for _ in 0..500_000 {
        let c = unsafe { regs::read32(base as *const u8, regs::PORT_CMD) };
        if c & regs::CMD_FR == 0 {
            return Ok(());
        }
        wait();
    }

    Err("AHCI: port command engine failed to stop")
}

/// Start the command engine on a port.
///
/// Sets CMD.FRE first, then CMD.ST.
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory. CLB and FB must
/// already be configured.
pub unsafe fn start_cmd(hba_base: *mut u8, port: u8) {
    let base = port_base_mut(hba_base, port);

    // Wait until CR is clear before starting.
    loop {
        let cmd = unsafe { regs::read32(base as *const u8, regs::PORT_CMD) };
        if cmd & regs::CMD_CR == 0 {
            break;
        }
        core::hint::spin_loop();
    }

    let mut cmd = unsafe { regs::read32(base as *const u8, regs::PORT_CMD) };
    // Enable FIS Receive.
    cmd |= regs::CMD_FRE;
    unsafe { regs::write32(base, regs::PORT_CMD, cmd) };
    // Enable command processing.
    cmd |= regs::CMD_ST;
    unsafe { regs::write32(base, regs::PORT_CMD, cmd) };
}

/// Set the Command List Base Address for a port.
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
/// Command engine must be stopped.
pub unsafe fn set_clb(hba_base: *mut u8, port: u8, clb_phys: u64) {
    let base = port_base_mut(hba_base, port);
    unsafe {
        regs::write32(base, regs::PORT_CLB, clb_phys as u32);
        regs::write32(base, regs::PORT_CLBU, (clb_phys >> 32) as u32);
    }
}

/// Set the FIS Base Address for a port.
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
/// Command engine must be stopped.
pub unsafe fn set_fb(hba_base: *mut u8, port: u8, fb_phys: u64) {
    let base = port_base_mut(hba_base, port);
    unsafe {
        regs::write32(base, regs::PORT_FB, fb_phys as u32);
        regs::write32(base, regs::PORT_FBU, (fb_phys >> 32) as u32);
    }
}

/// Clear all pending interrupts on a port (write all-ones to PORT_IS).
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn clear_interrupts(hba_base: *mut u8, port: u8) {
    let base = port_base_mut(hba_base, port);
    unsafe { regs::write32(base, regs::PORT_IS, 0xFFFFFFFF) };
}

/// Clear SERR register (write all-ones).
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn clear_serr(hba_base: *mut u8, port: u8) {
    let base = port_base_mut(hba_base, port);
    unsafe { regs::write32(base, regs::PORT_SERR, 0xFFFFFFFF) };
}

/// Issue a command by setting the corresponding bit in PORT_CI.
///
/// - `slot`: Command slot (0-31).
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn issue_command(hba_base: *mut u8, port: u8, slot: u8) {
    let base = port_base_mut(hba_base, port);
    unsafe { regs::write32(base, regs::PORT_CI, 1u32 << slot) };
}

/// Wait for a command slot to complete.
///
/// Polls PORT_CI until the bit for `slot` clears, or PORT_IS indicates an error.
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn wait_command(
    hba_base: *mut u8,
    port: u8,
    slot: u8,
    wait: WaitFn,
) -> Result<(), &'static str> {
    let base = port_base_mut(hba_base, port);
    let mask = 1u32 << slot;

    for _ in 0..10_000_000 {
        let ci = unsafe { regs::read32(base as *const u8, regs::PORT_CI) };
        if ci & mask == 0 {
            // Check TFD for errors.
            let tfd = unsafe { regs::read32(base as *const u8, regs::PORT_TFD) };
            if tfd & (regs::TFD_ERR | regs::TFD_BSY) != 0 {
                return Err("AHCI: task file error");
            }
            return Ok(());
        }

        // Check for fatal errors in PORT_IS.
        let is = unsafe { regs::read32(base as *const u8, regs::PORT_IS) };
        if is & (regs::IS_TFES | regs::IS_HBFS | regs::IS_HBDS | regs::IS_IFS) != 0 {
            return Err("AHCI: fatal port error");
        }

        wait();
    }

    Err("AHCI: command timeout")
}

/// Read the Task File Data register (status + error).
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn read_tfd(hba_base: *const u8, port: u8) -> u32 {
    let base = port_base(hba_base, port);
    unsafe { regs::read32(base, regs::PORT_TFD) }
}

/// Wait for the device on a port to be not-busy (BSY and DRQ clear in TFD).
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn wait_busy(hba_base: *const u8, port: u8, wait: WaitFn) -> Result<(), &'static str> {
    for _ in 0..1_000_000 {
        let tfd = unsafe { read_tfd(hba_base, port) };
        if tfd & (regs::TFD_BSY | regs::TFD_DRQ) == 0 {
            return Ok(());
        }
        wait();
    }
    Err("AHCI: device busy timeout")
}

/// Enumerate implemented ports and return a bitmask of active SATA ports.
///
/// # Safety
/// `hba_base` must point to valid UC-mapped MMIO memory.
pub unsafe fn find_sata_ports(hba_base: *const u8) -> u32 {
    let pi = unsafe { regs::read32(hba_base, regs::REG_PI) };
    let mut active = 0u32;

    for i in 0..32u8 {
        if pi & (1 << i) == 0 {
            continue;
        }
        let dev = unsafe { probe_port(hba_base, i) };
        if dev == DeviceType::Sata {
            active |= 1 << i;
        }
    }

    active
}
