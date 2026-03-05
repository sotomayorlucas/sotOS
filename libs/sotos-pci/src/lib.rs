//! Userspace PCI bus enumeration library for sotOS.
//!
//! Scans PCI bus 0 via I/O port config space (0xCF8/0xCFC).
//! Requires an IoPort capability covering ports 0xCF8–0xCFF.

#![no_std]

use sotos_common::sys;

/// PCI config space address port.
const PCI_CONFIG_ADDR: u64 = 0xCF8;
/// PCI config space data port.
const PCI_CONFIG_DATA: u64 = 0xCFC;

/// Wraps a PCI I/O port capability for config space access.
pub struct PciBus {
    cap: u64,
}

/// PCI bus/device/function address.
#[derive(Debug, Clone, Copy)]
pub struct PciAddr {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

/// A discovered PCI device.
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub addr: PciAddr,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub irq_line: u8,
}

impl PciBus {
    /// Create a new PCI bus accessor from an IoPort capability
    /// covering ports 0xCF8–0xCFF.
    pub fn new(pci_port_cap: u64) -> Self {
        Self { cap: pci_port_cap }
    }

    /// Read a 32-bit value from PCI config space.
    pub fn read32(&self, addr: PciAddr, offset: u8) -> u32 {
        let address: u32 = (1 << 31) // enable bit
            | ((addr.bus as u32) << 16)
            | ((addr.dev as u32) << 11)
            | ((addr.func as u32) << 8)
            | ((offset as u32) & 0xFC);
        let _ = sys::port_out32(self.cap, PCI_CONFIG_ADDR, address);
        sys::port_in32(self.cap, PCI_CONFIG_DATA).unwrap_or(0xFFFFFFFF)
    }

    /// Write a 32-bit value to PCI config space.
    pub fn write32(&self, addr: PciAddr, offset: u8, val: u32) {
        let address: u32 = (1 << 31)
            | ((addr.bus as u32) << 16)
            | ((addr.dev as u32) << 11)
            | ((addr.func as u32) << 8)
            | ((offset as u32) & 0xFC);
        let _ = sys::port_out32(self.cap, PCI_CONFIG_ADDR, address);
        let _ = sys::port_out32(self.cap, PCI_CONFIG_DATA, val);
    }

    /// Read vendor and device ID from a PCI address.
    pub fn vendor_device(&self, addr: PciAddr) -> (u16, u16) {
        let val = self.read32(addr, 0x00);
        let vendor = val as u16;
        let device = (val >> 16) as u16;
        (vendor, device)
    }

    /// Read BAR0 value (32-bit I/O or memory BAR).
    pub fn bar0(&self, addr: PciAddr) -> u32 {
        self.read32(addr, 0x10)
    }

    /// Read BAR0 as a 64-bit MMIO base address.
    /// Returns None if BAR0 is an I/O port BAR.
    /// Handles 64-bit BARs (type 2) by reading BAR0 + BAR1.
    pub fn bar0_mmio(&self, addr: PciAddr) -> Option<u64> {
        let bar0 = self.read32(addr, 0x10);
        // Bit 0 = 0 means memory BAR
        if bar0 & 1 != 0 {
            return None; // I/O port BAR
        }
        let bar_type = (bar0 >> 1) & 3;
        let base_lo = (bar0 & !0xF) as u64;
        match bar_type {
            0 => Some(base_lo),        // 32-bit
            2 => {                      // 64-bit
                let bar1 = self.read32(addr, 0x14);
                Some(base_lo | ((bar1 as u64) << 32))
            }
            _ => None,
        }
    }

    /// Enable memory space access (bit 1 of PCI Command register).
    /// Required before accessing MMIO BARs.
    pub fn enable_memory_space(&self, addr: PciAddr) {
        let cmd = self.read32(addr, 0x04);
        self.write32(addr, 0x04, cmd | (1 << 1));
    }

    /// Read the IRQ line from config space (offset 0x3C, byte 0).
    pub fn irq_line(&self, addr: PciAddr) -> u8 {
        self.read32(addr, 0x3C) as u8
    }

    /// Enable bus mastering (set bit 2 of Command register).
    pub fn enable_bus_master(&self, addr: PciAddr) {
        let cmd = self.read32(addr, 0x04);
        self.write32(addr, 0x04, cmd | (1 << 2));
    }

    /// Enumerate PCI bus 0, returning up to N devices.
    pub fn enumerate<const N: usize>(&self) -> ([PciDevice; N], usize) {
        let mut devices = [PciDevice {
            addr: PciAddr { bus: 0, dev: 0, func: 0 },
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
            prog_if: 0,
            header_type: 0,
            irq_line: 0,
        }; N];
        let mut count = 0;

        for dev in 0..32u8 {
            let addr = PciAddr { bus: 0, dev, func: 0 };
            let (vendor, device) = self.vendor_device(addr);
            if vendor == 0xFFFF {
                continue;
            }

            let class_rev = self.read32(addr, 0x08);
            let header_val = self.read32(addr, 0x0C);
            let header_type = ((header_val >> 16) & 0xFF) as u8;

            if count < N {
                devices[count] = PciDevice {
                    addr,
                    vendor_id: vendor,
                    device_id: device,
                    class: (class_rev >> 24) as u8,
                    subclass: ((class_rev >> 16) & 0xFF) as u8,
                    prog_if: ((class_rev >> 8) & 0xFF) as u8,
                    header_type: header_type & 0x7F,
                    irq_line: self.irq_line(addr),
                };
                count += 1;
            }

            // Check multi-function device
            if header_type & 0x80 != 0 {
                for func in 1..8u8 {
                    let faddr = PciAddr { bus: 0, dev, func };
                    let (fv, fd) = self.vendor_device(faddr);
                    if fv == 0xFFFF {
                        continue;
                    }
                    let fc = self.read32(faddr, 0x08);
                    if count < N {
                        devices[count] = PciDevice {
                            addr: faddr,
                            vendor_id: fv,
                            device_id: fd,
                            class: (fc >> 24) as u8,
                            subclass: ((fc >> 16) & 0xFF) as u8,
                            prog_if: ((fc >> 8) & 0xFF) as u8,
                            header_type: 0,
                            irq_line: self.irq_line(faddr),
                        };
                        count += 1;
                    }
                }
            }
        }

        (devices, count)
    }

    /// Find a device by vendor and device ID.
    pub fn find_device(&self, vendor: u16, device: u16) -> Option<PciDevice> {
        let (devs, count) = self.enumerate::<32>();
        for i in 0..count {
            if devs[i].vendor_id == vendor && devs[i].device_id == device {
                return Some(devs[i]);
            }
        }
        None
    }
}
