// ---------------------------------------------------------------------------
// seatd stub — inline seat management protocol for weston
//
// When a child connects to /run/seatd.sock, we assign FD kind=33 (seatd).
// Reads from this fd return seatd protocol responses.
// Writes are parsed as seatd protocol requests.
//
// Protocol: 4-byte header (opcode:u16, size:u16) + payload
// ---------------------------------------------------------------------------

use sotos_common::SyncUnsafeCell;
use crate::framebuffer::print;
use crate::syscalls::context::SyscallContext;
use crate::exec::reply_val;

// Client opcodes
const CLIENT_OPEN_SEAT: u16      = 1;
const CLIENT_CLOSE_SEAT: u16     = 2;
const CLIENT_OPEN_DEVICE: u16    = 3;
const CLIENT_CLOSE_DEVICE: u16   = 4;
const CLIENT_DISABLE_SEAT: u16   = 5;
const CLIENT_PING: u16           = 7;

// Server opcodes
const SERVER_SEAT_OPENED: u16    = 0x8001;
const SERVER_DEVICE_OPENED: u16  = 0x8003;
const SERVER_DEVICE_CLOSED: u16  = 0x8004;
const SERVER_ENABLE_SEAT: u16    = 0x8006;
const SERVER_PONG: u16           = 0x8007;
const SERVER_SEAT_DISABLED: u16  = 0x8009;
const SERVER_ERROR: u16          = 0xFFFF;

// Per-process seatd state
const MAX_SEATD: usize = 4;
struct SeatdState {
    active: bool,
    // Pending response buffer (server → client)
    resp_buf: [u8; 256],
    resp_len: usize,
    resp_pos: usize,
    // Whether we've sent the initial ENABLE_SEAT
    sent_enable: bool,
    // FD to deliver via SCM_RIGHTS on next recvmsg (0 = none pending)
    drm_fd: u8,
    // One-shot flag: clear drm_fd after delivery
    scm_pending: bool,
}

static STATE: SyncUnsafeCell<[SeatdState; MAX_SEATD]> = SyncUnsafeCell::new({
    const EMPTY: SeatdState = SeatdState {
        active: false, resp_buf: [0; 256], resp_len: 0, resp_pos: 0,
        sent_enable: false, drm_fd: 0, scm_pending: false,
    };
    [EMPTY; MAX_SEATD]
});

/// Allocate a seatd session slot. Returns slot index.
pub(crate) fn seatd_alloc() -> Option<usize> {
    let st = unsafe { &mut *STATE.get() };
    for i in 0..MAX_SEATD {
        if !st[i].active {
            st[i] = SeatdState {
                active: true, resp_buf: [0; 256], resp_len: 0, resp_pos: 0, scm_pending: false,
                sent_enable: false, drm_fd: 0,
            };
            return Some(i);
        }
    }
    None
}

/// Free a seatd session slot.
pub(crate) fn seatd_free(slot: usize) {
    let st = unsafe { &mut *STATE.get() };
    if slot < MAX_SEATD { st[slot].active = false; }
}

/// Handle a read from a seatd socket FD.
/// Returns bytes "read" (protocol responses).
pub(crate) fn seatd_read(ctx: &mut SyscallContext, fd: usize, buf: u64, count: u64) -> i64 {
    let slot = ctx.sock_conn_id[fd] as usize;
    if slot >= MAX_SEATD { return -9; } // -EBADF

    let st = unsafe { &mut *STATE.get() };
    let s = &mut st[slot];

    // If we have pending response data, serve it
    if s.resp_pos < s.resp_len {
        let avail = s.resp_len - s.resp_pos;
        let copy = avail.min(count as usize);
        ctx.guest_write(buf, &s.resp_buf[s.resp_pos..s.resp_pos + copy]);
        s.resp_pos += copy;
        return copy as i64;
    }

    // No data available — would block
    -11 // -EAGAIN
}

/// Handle a write to a seatd socket FD.
/// Parses seatd protocol requests and queues responses.
pub(crate) fn seatd_write(ctx: &mut SyscallContext, fd: usize, buf: u64, count: u64) -> i64 {
    let slot = ctx.sock_conn_id[fd] as usize;
    if slot >= MAX_SEATD { return -9; }

    let st = unsafe { &mut *STATE.get() };
    let s = &mut st[slot];

    if count < 4 { return count as i64; } // too small for header

    // Read request from child memory
    let mut req = [0u8; 256];
    let read_len = (count as usize).min(256);
    ctx.guest_read(buf, &mut req[..read_len]);

    let opcode = u16::from_ne_bytes([req[0], req[1]]);
    let size = u16::from_ne_bytes([req[2], req[3]]) as usize;

    match opcode {
        CLIENT_OPEN_SEAT => {
            print(b"seatd: OPEN_SEAT\n");
            // Response: SERVER_SEAT_OPENED + seat_name, then ENABLE_SEAT
            let seat_name = b"seat0\0";
            let payload_size = 2 + seat_name.len();
            let msg1_len = 4 + payload_size;
            s.resp_buf[0..2].copy_from_slice(&SERVER_SEAT_OPENED.to_ne_bytes());
            s.resp_buf[2..4].copy_from_slice(&(payload_size as u16).to_ne_bytes());
            s.resp_buf[4..6].copy_from_slice(&(seat_name.len() as u16).to_ne_bytes());
            s.resp_buf[6..6 + seat_name.len()].copy_from_slice(seat_name);
            // Append ENABLE_SEAT (opcode 0x8006, zero payload)
            let off = msg1_len;
            s.resp_buf[off..off+2].copy_from_slice(&SERVER_ENABLE_SEAT.to_ne_bytes());
            s.resp_buf[off+2..off+4].copy_from_slice(&0u16.to_ne_bytes());
            s.resp_len = off + 4;
            s.resp_pos = 0;
        }

        CLIENT_OPEN_DEVICE => {
            // Parse device path from payload: u16 path_len, then path bytes
            let path_len = if size >= 2 { u16::from_ne_bytes([req[4], req[5]]) as usize } else { 0 };
            let path_start = 6;
            let path_end = (path_start + path_len).min(read_len);
            let dev_path = &req[path_start..path_end];
            print(b"seatd: OPEN_DEVICE [");
            for &b in dev_path { if b != 0 { sotos_common::sys::debug_print(b); } }
            print(b"]\n");

            // Determine fd kind from path
            let kind: u8 = if dev_path.starts_with(b"/dev/input/event1") { 32 } // mouse
                else if dev_path.starts_with(b"/dev/input/event0") { 31 } // keyboard
                else { 30 }; // DRM (default)

            let mut dev_fd = None;
            for i in 3..crate::fd::GRP_MAX_FDS {
                if ctx.child_fds[i] == 0 { dev_fd = Some(i); break; }
            }
            if let Some(f) = dev_fd {
                ctx.child_fds[f] = kind;
                s.drm_fd = f as u8;
                s.scm_pending = true;

                // Response: SERVER_DEVICE_OPENED + device_id
                // The fd is passed via SCM_RIGHTS — we'll store it so the
                // recvmsg handler can attach it
                let device_id: i32 = f as i32;
                s.resp_buf[0..2].copy_from_slice(&SERVER_DEVICE_OPENED.to_ne_bytes());
                s.resp_buf[2..4].copy_from_slice(&4u16.to_ne_bytes());
                s.resp_buf[4..8].copy_from_slice(&device_id.to_ne_bytes());
                s.resp_len = 8;
                s.resp_pos = 0;

                // Mark that SCM_RIGHTS fd should be delivered on next recvmsg
                // Store in slot for recvmsg to pick up
                print(b"seatd: DRM fd=");
                crate::framebuffer::print_u64(f as u64);
                print(b"\n");
            } else {
                s.resp_buf[0..2].copy_from_slice(&SERVER_ERROR.to_ne_bytes());
                s.resp_buf[2..4].copy_from_slice(&4u16.to_ne_bytes());
                s.resp_buf[4..8].copy_from_slice(&24i32.to_ne_bytes()); // EMFILE
                s.resp_len = 8;
                s.resp_pos = 0;
            }
        }

        CLIENT_CLOSE_DEVICE => {
            print(b"seatd: CLOSE_DEVICE\n");
            s.resp_buf[0..2].copy_from_slice(&SERVER_DEVICE_CLOSED.to_ne_bytes());
            s.resp_buf[2..4].copy_from_slice(&0u16.to_ne_bytes());
            s.resp_len = 4;
            s.resp_pos = 0;
        }

        CLIENT_DISABLE_SEAT => {
            s.resp_buf[0..2].copy_from_slice(&SERVER_SEAT_DISABLED.to_ne_bytes());
            s.resp_buf[2..4].copy_from_slice(&0u16.to_ne_bytes());
            s.resp_len = 4;
            s.resp_pos = 0;
        }

        CLIENT_CLOSE_SEAT => {
            print(b"seatd: CLOSE_SEAT\n");
            seatd_free(slot);
        }

        CLIENT_PING => {
            s.resp_buf[0..2].copy_from_slice(&SERVER_PONG.to_ne_bytes());
            s.resp_buf[2..4].copy_from_slice(&0u16.to_ne_bytes());
            s.resp_len = 4;
            s.resp_pos = 0;
        }

        _ => {
            print(b"seatd: unknown opcode ");
            crate::framebuffer::print_u64(opcode as u64);
            print(b"\n");
        }
    }

    count as i64
}

/// Check if a seatd session has pending response data (for poll/epoll).
pub(crate) fn seatd_poll_readable(slot: usize) -> bool {
    let st = unsafe { &*STATE.get() };
    if slot < MAX_SEATD && st[slot].active {
        st[slot].resp_pos < st[slot].resp_len
    } else {
        false
    }
}

/// Get the device fd to pass via SCM_RIGHTS on next recvmsg (one-shot).
pub(crate) fn seatd_get_scm_fd(slot: usize) -> Option<u8> {
    let st = unsafe { &mut *STATE.get() };
    if slot < MAX_SEATD && st[slot].active && st[slot].scm_pending && st[slot].drm_fd != 0 {
        st[slot].scm_pending = false; // one-shot: clear after delivery
        Some(st[slot].drm_fd)
    } else {
        None
    }
}
