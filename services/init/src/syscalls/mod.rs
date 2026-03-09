// ---------------------------------------------------------------------------
// syscalls/ — Extracted syscall handlers, organized by subsystem.
// ---------------------------------------------------------------------------

pub(crate) mod context;
pub(crate) mod mm;
pub(crate) mod fs;
pub(crate) mod net;
pub(crate) mod task;
pub(crate) mod signal;
pub(crate) mod info;
