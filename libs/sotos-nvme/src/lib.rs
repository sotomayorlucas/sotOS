//! NVMe SSD driver library for sotOS.
//!
//! Implements the NVMe 1.4 specification for single-namespace block I/O.
//! Uses MMIO registers (BAR0) and admin/I/O submission+completion queues.

#![no_std]

pub mod regs;
pub mod queue;
pub mod cmd;
pub mod controller;
pub mod io;
