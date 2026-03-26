//! Structured tracing infrastructure for the init service.
//!
//! Provides feature-gated macros that emit prefixed, filtered trace lines
//! via `crate::framebuffer::print()`.  When the `trace` feature is disabled
//! all macros compile to nothing.

use core::sync::atomic::{AtomicU8, AtomicU16, Ordering};
use sotos_common::trace::TraceLevel;

/// Current maximum trace level (inclusive).  Default: Debug (3).
pub(crate) static TRACE_LEVEL: AtomicU8 = AtomicU8::new(3);

/// Enabled category bitmask.  Default: all (0xFFFF).
pub(crate) static TRACE_CATS: AtomicU16 = AtomicU16::new(0xFFFF);

/// Change the runtime trace level (clamped to 0..=4).
pub(crate) fn set_level(level: u8) {
    TRACE_LEVEL.store(level.min(4), Ordering::Relaxed);
}

/// Change the enabled category mask at runtime.
pub(crate) fn set_categories(mask: u16) {
    TRACE_CATS.store(mask, Ordering::Relaxed);
}

/// Returns `true` when a message at the given level and category should be emitted.
pub(crate) fn trace_enabled(level: TraceLevel, cat_bits: u16) -> bool {
    level as u8 <= TRACE_LEVEL.load(Ordering::Relaxed)
        && (cat_bits & TRACE_CATS.load(Ordering::Relaxed)) != 0
}

// ---------------------------------------------------------------------------
// Macros — feature-gated on `trace` (default enabled)
// ---------------------------------------------------------------------------

/// Core trace macro.  Checks level + category, prints `[L CAT] `, evaluates
/// `$body` (which uses `print()` / `print_u64()` / `print_hex64()`), then
/// appends a newline.
#[cfg(feature = "trace")]
macro_rules! trace {
    ($level:ident, $cat:ident, $body:block) => {
        {
            if $crate::trace::trace_enabled(
                sotos_common::trace::TraceLevel::$level,
                sotos_common::trace::cat::$cat,
            ) {
                $crate::framebuffer::print(&[b'[',
                    sotos_common::trace::TraceLevel::$level.as_byte(),
                    b' ']);
                $crate::framebuffer::print(
                    sotos_common::trace::cat_name_bytes(sotos_common::trace::cat::$cat));
                $crate::framebuffer::print(b"] ");
                $body
                $crate::framebuffer::print(b"\n");
            }
        }
    };
}

#[cfg(not(feature = "trace"))]
macro_rules! trace {
    ($($tt:tt)*) => {{}};
}

/// Standardised syscall trace line at Debug level, SYSCALL category.
/// Format: `[D SYSCALL] P<pid> <name>(<nr>) a0=0x<arg0> -> <ret>`
#[cfg(feature = "trace")]
macro_rules! trace_syscall {
    ($pid:expr, $nr:expr, $arg0:expr, $ret:expr) => {
        {
            if $crate::trace::trace_enabled(
                sotos_common::trace::TraceLevel::Debug,
                sotos_common::trace::cat::SYSCALL,
            ) {
                $crate::framebuffer::print(b"[D SYSCALL] P");
                $crate::framebuffer::print_u64($pid as u64);
                $crate::framebuffer::print(b" ");
                $crate::framebuffer::print(sotos_common::trace::syscall_name($nr as u64));
                $crate::framebuffer::print(b"(");
                $crate::framebuffer::print_u64($nr as u64);
                $crate::framebuffer::print(b") a0=0x");
                $crate::framebuffer::print_hex64($arg0 as u64);
                $crate::framebuffer::print(b" -> ");
                $crate::framebuffer::print_u64($ret as u64);
                $crate::framebuffer::print(b"\n");
            }
        }
    };
}

#[cfg(not(feature = "trace"))]
macro_rules! trace_syscall {
    ($($tt:tt)*) => {{}};
}

/// Register dump at Debug level, REGISTER category.
/// Prints each register from `$regs` (an array of u64) with labels.
#[cfg(feature = "trace")]
macro_rules! trace_regs {
    ($pid:expr, $regs:expr) => {
        {
            if $crate::trace::trace_enabled(
                sotos_common::trace::TraceLevel::Debug,
                sotos_common::trace::cat::REGISTER,
            ) {
                const NAMES: [&[u8]; 8] = [
                    b"r0", b"r1", b"r2", b"r3", b"r4", b"r5", b"r6", b"r7",
                ];
                $crate::framebuffer::print(b"[D REG] P");
                $crate::framebuffer::print_u64($pid as u64);
                $crate::framebuffer::print(b" regs:");
                let mut buf = [0u8; 40];
                let regs_ref = &$regs;
                let len = if regs_ref.len() < 8 { regs_ref.len() } else { 8 };
                for i in 0..len {
                    let n = sotos_common::trace::fmt_reg(NAMES[i], regs_ref[i], &mut buf);
                    $crate::framebuffer::print(&buf[..n]);
                }
            }
        }
    };
}

#[cfg(not(feature = "trace"))]
macro_rules! trace_regs {
    ($($tt:tt)*) => {{}};
}
