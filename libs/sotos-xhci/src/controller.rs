//! xHCI controller initialization and command submission.

use crate::regs;
use crate::trb::{self, Trb, TrbRing, EventRing, ErstEntry};

/// DMA memory layout provided by the service process.
pub struct XhciDma {
    pub dcbaa_virt: *mut u8,
    pub dcbaa_phys: u64,
    pub cmd_ring_virt: *mut u8,
    pub cmd_ring_phys: u64,
    pub evt_ring_virt: *mut u8,
    pub evt_ring_phys: u64,
    pub erst_virt: *mut u8,
    pub erst_phys: u64,
    pub scratch_arr_virt: *mut u8,
    pub scratch_arr_phys: u64,
    pub scratch_buf_phys: [u64; 16],
    pub input_ctx_virt: *mut u8,
    pub input_ctx_phys: u64,
    pub device_ctx_virt: *mut u8,
    pub device_ctx_phys: u64,
    pub ep0_ring_virt: *mut u8,
    pub ep0_ring_phys: u64,
    pub data_buf_virt: *mut u8,
    pub data_buf_phys: u64,
}

pub type WaitFn = fn();

/// Result of controller initialization.
pub struct XhciInitResult {
    pub version_major: u8,
    pub version_minor: u8,
    pub max_slots: u8,
    pub max_ports: u8,
}

pub struct XhciController {
    mmio_base: *mut u8,
    op_base: *mut u8,
    db_base: *mut u8,
    rt_base: *mut u8,
    cmd_ring: TrbRing,
    evt_ring: EventRing,
    pub max_ports: u8,
    pub max_slots: u8,
}

impl XhciController {
    /// Initialize the xHCI controller. Follows the 10-step sequence from the spec.
    ///
    /// # Safety
    /// `mmio_base` must point to a valid UC-mapped xHCI BAR0 region.
    pub unsafe fn init(
        mmio_base: *mut u8,
        dma: &XhciDma,
        wait: WaitFn,
    ) -> Result<(Self, XhciInitResult), &'static str> {
        // 1. Read CAPLENGTH, HCIVERSION, DBOFF, RTSOFF.
        let caplength = regs::read8(mmio_base as *const u8, regs::CAP_CAPLENGTH) as usize;
        // HCIVERSION is at offset 2 within a 32-bit register at offset 0.
        let cap0 = regs::read32(mmio_base as *const u8, 0x00);
        let hciversion = (cap0 >> 16) as u16;
        let dboff = regs::read32(mmio_base as *const u8, regs::CAP_DBOFF) as usize;
        let rtsoff = regs::read32(mmio_base as *const u8, regs::CAP_RTSOFF) as usize;

        let op_base = mmio_base.add(caplength);
        let db_base = mmio_base.add(dboff);
        let rt_base = mmio_base.add(rtsoff);

        let version_major = (hciversion >> 8) as u8;
        let version_minor = (hciversion & 0xFF) as u8;

        // 2. Read HCSPARAMS1 → max_slots, max_ports; HCSPARAMS2 → max_scratchpad.
        let hcs1 = regs::read32(mmio_base as *const u8, regs::CAP_HCSPARAMS1);
        let hcs2 = regs::read32(mmio_base as *const u8, regs::CAP_HCSPARAMS2);
        let max_slots = regs::hcs1_max_slots(hcs1);
        let max_ports = regs::hcs1_max_ports(hcs1);
        let max_scratch = regs::hcs2_max_scratchpad(hcs2);

        // 3. Halt: clear USBCMD.RS, wait for USBSTS.HCH=1.
        let cmd = regs::read32(op_base as *const u8, regs::OP_USBCMD);
        regs::write32(op_base, regs::OP_USBCMD, cmd & !regs::CMD_RS);
        for _ in 0..100_000 {
            let sts = regs::read32(op_base as *const u8, regs::OP_USBSTS);
            if sts & regs::STS_HCH != 0 {
                break;
            }
            wait();
        }

        // 4. Reset: set HCRST, wait for HCRST=0 AND CNR=0.
        regs::write32(op_base, regs::OP_USBCMD, regs::CMD_HCRST);
        for _ in 0..1_000_000 {
            let cmd_val = regs::read32(op_base as *const u8, regs::OP_USBCMD);
            let sts = regs::read32(op_base as *const u8, regs::OP_USBSTS);
            if (cmd_val & regs::CMD_HCRST == 0) && (sts & regs::STS_CNR == 0) {
                break;
            }
            wait();
        }
        // Verify reset completed.
        let sts = regs::read32(op_base as *const u8, regs::OP_USBSTS);
        if sts & regs::STS_CNR != 0 {
            return Err("xhci: controller not ready after reset");
        }

        // 5. Set CONFIG.MaxSlotsEn = max_slots.
        regs::write32(op_base, regs::OP_CONFIG, max_slots as u32);

        // 6. Set DCBAAP. Wire scratchpad buffers if needed.
        let dcbaa = dma.dcbaa_virt as *mut u64;
        // Zero the DCBAA (256 entries * 8 bytes = 2048, fits in 1 page).
        core::ptr::write_bytes(dcbaa, 0, 512); // 512 u64s = 4096 bytes

        if max_scratch > 0 {
            // DCBAA[0] points to the scratchpad buffer array.
            let scratch_arr = dma.scratch_arr_virt as *mut u64;
            let count = core::cmp::min(max_scratch as usize, 16);
            for i in 0..count {
                core::ptr::write_volatile(scratch_arr.add(i), dma.scratch_buf_phys[i]);
            }
            core::ptr::write_volatile(dcbaa, dma.scratch_arr_phys);
        }

        regs::write64(op_base, regs::OP_DCBAAP, dma.dcbaa_phys);

        // 7. Init Command Ring, set CRCR = phys | RCS.
        let cmd_ring = TrbRing::init(dma.cmd_ring_virt, dma.cmd_ring_phys);
        regs::write64(op_base, regs::OP_CRCR, dma.cmd_ring_phys | regs::CRCR_RCS);

        // 8. Init Event Ring + ERST, configure Interrupter 0.
        let evt_ring = EventRing::init(dma.evt_ring_virt, dma.evt_ring_phys);

        // Write ERST entry (1 segment).
        let erst = dma.erst_virt as *mut ErstEntry;
        core::ptr::write_volatile(erst, ErstEntry::new(dma.evt_ring_phys, trb::RING_SIZE as u32));

        let ir0_base = rt_base.add(regs::RT_IR0_BASE);
        // ERSTSZ = 1.
        regs::write32(ir0_base, regs::IR_ERSTSZ, 1);
        // ERDP = event ring physical base.
        regs::write64(ir0_base, regs::IR_ERDP, dma.evt_ring_phys);
        // ERSTBA = ERST physical address (must be written AFTER ERSTSZ).
        regs::write64(ir0_base, regs::IR_ERSTBA, dma.erst_phys);

        // 9. Enable interrupts: IMAN.IE=1, USBCMD.INTE=1.
        let iman = regs::read32(ir0_base as *const u8, regs::IR_IMAN);
        regs::write32(ir0_base, regs::IR_IMAN, iman | regs::IMAN_IE);

        let usbcmd = regs::read32(op_base as *const u8, regs::OP_USBCMD);
        regs::write32(op_base, regs::OP_USBCMD, usbcmd | regs::CMD_INTE);

        // 10. Run: set USBCMD.RS=1, wait for USBSTS.HCH=0.
        let usbcmd = regs::read32(op_base as *const u8, regs::OP_USBCMD);
        regs::write32(op_base, regs::OP_USBCMD, usbcmd | regs::CMD_RS);
        for _ in 0..100_000 {
            let sts_val = regs::read32(op_base as *const u8, regs::OP_USBSTS);
            if sts_val & regs::STS_HCH == 0 {
                break;
            }
            wait();
        }
        let sts_final = regs::read32(op_base as *const u8, regs::OP_USBSTS);
        if sts_final & regs::STS_HCH != 0 {
            return Err("xhci: controller failed to start (HCH still set)");
        }

        let ctrl = XhciController {
            mmio_base,
            op_base,
            db_base,
            rt_base,
            cmd_ring,
            evt_ring,
            max_ports,
            max_slots,
        };

        Ok((ctrl, XhciInitResult {
            version_major,
            version_minor,
            max_slots,
            max_ports,
        }))
    }

    /// Ring the command doorbell (doorbell register 0).
    pub unsafe fn ring_cmd_doorbell(&self) {
        regs::write32(self.db_base, 0, 0);
    }

    /// Ring an endpoint doorbell for the given slot and endpoint ID.
    pub unsafe fn ring_ep_doorbell(&self, slot: u8, ep_id: u8) {
        let offset = (slot as usize) * 4;
        regs::write32(self.db_base, offset, ep_id as u32);
    }

    /// Submit a command TRB and wait for a Command Completion Event.
    /// Skips non-command events (e.g. Port Status Change) that may be pending.
    pub unsafe fn submit_command(&mut self, trb: Trb, wait: WaitFn) -> Result<Trb, &'static str> {
        self.cmd_ring.enqueue(trb);
        self.ring_cmd_doorbell();

        // Poll event ring for completion, skipping non-command events.
        for _ in 0..10_000_000 {
            if let Some(evt) = self.evt_ring.poll() {
                self.evt_ring.advance();
                self.update_erdp();

                if evt.trb_type() == trb::TRB_CMD_COMPLETE {
                    return Ok(evt);
                }
                // Non-command event (e.g. Port Status Change) — skip and keep polling.
                continue;
            }
            wait();
        }
        Err("xhci: command timeout")
    }

    /// Drain all pending events from the event ring.
    /// Returns the number of events processed.
    pub unsafe fn drain_events(&mut self) -> usize {
        let mut count = 0;
        loop {
            match self.evt_ring.poll() {
                Some(_evt) => {
                    self.evt_ring.advance();
                    count += 1;
                }
                None => break,
            }
        }
        if count > 0 {
            self.update_erdp();
        }
        count
    }

    /// Update the ERDP register with the current dequeue pointer.
    unsafe fn update_erdp(&self) {
        let ir0_base = self.rt_base.add(regs::RT_IR0_BASE);
        // Write dequeue pointer, clear EHB bit (bit 3).
        let erdp_val = self.evt_ring.dequeue_phys() & !regs::ERDP_EHB;
        regs::write64(ir0_base, regs::IR_ERDP, erdp_val);
    }

    /// Read PORTSC for a 1-based port number.
    pub unsafe fn portsc(&self, port: u8) -> u32 {
        regs::read32(self.op_base as *const u8, regs::portsc_offset(port))
    }

    /// Write PORTSC for a 1-based port number.
    pub unsafe fn write_portsc(&self, port: u8, val: u32) {
        regs::write32(self.op_base, regs::portsc_offset(port), val);
    }

    /// Get the MMIO base pointer.
    pub fn mmio_base(&self) -> *mut u8 {
        self.mmio_base
    }

    /// Get the operational registers base pointer.
    pub fn op_base(&self) -> *mut u8 {
        self.op_base
    }

    /// Set DCBAA entry for a slot (1-based slot_id).
    pub unsafe fn set_dcbaa_entry(&self, dma: &XhciDma, slot_id: u8, ctx_phys: u64) {
        let dcbaa = dma.dcbaa_virt as *mut u64;
        core::ptr::write_volatile(dcbaa.add(slot_id as usize), ctx_phys);
    }

    /// Perform a control transfer with IN data stage on EP0.
    /// Enqueues Setup + Data + Status TRBs, rings doorbell, waits for Transfer Event.
    pub unsafe fn control_transfer_in(
        &mut self,
        slot_id: u8,
        ep0_ring: &mut TrbRing,
        setup_packet: u64,
        buf_phys: u64,
        length: u16,
        wait: WaitFn,
    ) -> Result<Trb, &'static str> {
        ep0_ring.enqueue(trb::trb_setup_stage(setup_packet, 3)); // TRT=3 (IN)
        ep0_ring.enqueue(trb::trb_data_stage(buf_phys, length, true));
        ep0_ring.enqueue(trb::trb_status_stage(false)); // Status OUT for IN data
        self.ring_ep_doorbell(slot_id, 1); // DCI 1 = EP0
        self.wait_transfer_event(wait)
    }

    /// Perform a control transfer with no data stage on EP0.
    pub unsafe fn control_transfer_no_data(
        &mut self,
        slot_id: u8,
        ep0_ring: &mut TrbRing,
        setup_packet: u64,
        wait: WaitFn,
    ) -> Result<Trb, &'static str> {
        ep0_ring.enqueue(trb::trb_setup_stage(setup_packet, 0)); // TRT=0 (No Data)
        ep0_ring.enqueue(trb::trb_status_stage(true)); // Status IN for no-data
        self.ring_ep_doorbell(slot_id, 1); // DCI 1 = EP0
        self.wait_transfer_event(wait)
    }

    /// Wait for a Transfer Event on the event ring.
    /// Skips Command Completion and Port Status events.
    pub unsafe fn wait_transfer_event(&mut self, wait: WaitFn) -> Result<Trb, &'static str> {
        for _ in 0..10_000_000 {
            if let Some(evt) = self.evt_ring.poll() {
                self.evt_ring.advance();
                self.update_erdp();

                if evt.trb_type() == trb::TRB_XFER_EVENT {
                    return Ok(evt);
                }
                // Skip non-transfer events.
                continue;
            }
            wait();
        }
        Err("xhci: transfer event timeout")
    }

    /// Poll for a single event (non-blocking). Returns None if no event pending.
    pub unsafe fn poll_event(&mut self) -> Option<Trb> {
        if let Some(evt) = self.evt_ring.poll() {
            self.evt_ring.advance();
            self.update_erdp();
            Some(evt)
        } else {
            None
        }
    }
}
