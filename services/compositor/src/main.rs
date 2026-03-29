//! sotOS Wayland Compositor Service
//!
//! A minimal Wayland compositor that:
//! - Registers as "compositor" via service registry
//! - Accepts Wayland client connections over IPC
//! - Parses Wayland binary wire protocol messages from IPC data
//! - Dispatches to object handlers (wl_display, wl_registry,
//!   wl_compositor, wl_shm, xdg_wm_base, wl_surface, xdg_surface,
//!   xdg_toplevel, wl_seat)
//! - Renders client buffers to the framebuffer
//! - Forwards keyboard/mouse input as Wayland events

#![no_std]
#![no_main]

mod wayland;
mod render;
mod input;

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR, SyncUnsafeCell};

use render::Framebuffer;
use wayland::{
    ClientObjects, WlMessage, DispatchResult,
    WL_MSG_TAG, WL_CONNECT_TAG, IPC_DATA_MAX,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of connected Wayland clients.
const MAX_CLIENTS: usize = 8;

/// Maximum surfaces tracked.
const MAX_SURFACES: usize = 32;

/// Maximum toplevel windows.
const MAX_TOPLEVELS: usize = 16;

/// Maximum SHM pools.
const MAX_POOLS: usize = 16;

/// Maximum SHM buffers.
const MAX_BUFFERS: usize = 32;

/// Desktop background color (dark blue-gray).
const BG_COLOR: u32 = 0xFF2D2D3D;

/// Title bar height in pixels.
const TITLE_BAR_HEIGHT: u32 = 24;

/// IPC recv_timeout in scheduler ticks (~10ms at 100Hz = 1 tick).
const IPC_POLL_TICKS: u32 = 1;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A connected Wayland client.
struct WlClient {
    active: bool,
    /// IPC endpoint for this client.
    endpoint_cap: u64,
    /// Per-client object ID tracking for wire protocol dispatch.
    objects: ClientObjects,
}

impl WlClient {
    const fn empty() -> Self {
        Self {
            active: false,
            endpoint_cap: 0,
            objects: ClientObjects::empty(),
        }
    }
}

/// A wl_surface.
struct Surface {
    active: bool,
    surface_id: u32,
    client_idx: usize,
    /// Currently attached buffer index (into BUFFERS).
    buffer_idx: Option<usize>,
    /// Committed (ready to display).
    committed: bool,
}

impl Surface {
    const fn empty() -> Self {
        Self {
            active: false,
            surface_id: 0,
            client_idx: 0,
            buffer_idx: None,
            committed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Global compositor state (no heap -- all fixed-size)
// ---------------------------------------------------------------------------

static FB: SyncUnsafeCell<Framebuffer> = SyncUnsafeCell::new(Framebuffer::empty());
static CLIENTS: SyncUnsafeCell<[WlClient; MAX_CLIENTS]> = SyncUnsafeCell::new([const { WlClient::empty() }; MAX_CLIENTS]);
static SURFACES: SyncUnsafeCell<[Surface; MAX_SURFACES]> = SyncUnsafeCell::new([const { Surface::empty() }; MAX_SURFACES]);
static TOPLEVELS: SyncUnsafeCell<[wayland::shell::Toplevel; MAX_TOPLEVELS]> =
    SyncUnsafeCell::new([const { wayland::shell::Toplevel::empty() }; MAX_TOPLEVELS]);
static POOLS: SyncUnsafeCell<[wayland::shm::ShmPool; MAX_POOLS]> =
    SyncUnsafeCell::new([const { wayland::shm::ShmPool::empty() }; MAX_POOLS]);
static BUFFERS: SyncUnsafeCell<[wayland::shm::ShmBuffer; MAX_BUFFERS]> =
    SyncUnsafeCell::new([const { wayland::shm::ShmBuffer::empty() }; MAX_BUFFERS]);

/// Mouse cursor position.
static CURSOR_X: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);
static CURSOR_Y: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);

/// Configure serial counter.
static CONFIGURE_SERIAL: SyncUnsafeCell<u32> = SyncUnsafeCell::new(1);

/// TSC of last composed frame (SDF: fixed token production rate).
static LAST_FRAME_TSC: SyncUnsafeCell<u64> = SyncUnsafeCell::new(0);
/// Damage flag: set when any visual state changes.
static DAMAGE: SyncUnsafeCell<bool> = SyncUnsafeCell::new(true);

/// Frame interval in TSC ticks: ~16.67ms at 2 GHz = 60 Hz.
const FRAME_INTERVAL: u64 = 33_340_000;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    print(b"0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        sys::debug_print(hex[nibble]);
    }
}

fn print_u32_dec(mut val: u32) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < 10 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn mark_damage() {
    unsafe { *DAMAGE.get() = true; }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"compositor: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"compositor: invalid BootInfo!\n");
        loop { sys::yield_now(); }
    }

    // Initialize framebuffer from BootInfo.
    unsafe {
        let fb = &mut *FB.get();
        fb.addr = boot_info.fb_addr;
        fb.width = boot_info.fb_width;
        fb.height = boot_info.fb_height;
        fb.pitch = boot_info.fb_pitch;
        fb.bpp = boot_info.fb_bpp;
    }

    print(b"compositor: fb ");
    print_hex(boot_info.fb_addr);
    print(b" ");
    print_hex(boot_info.fb_width as u64);
    print(b"x");
    print_hex(boot_info.fb_height as u64);
    print(b"\n");

    // Register as "compositor" service.
    let ep_cap = boot_info.caps[0]; // endpoint for IPC
    let svc_name = b"compositor";
    match sys::svc_register(
        svc_name.as_ptr() as u64,
        svc_name.len() as u64,
        ep_cap,
    ) {
        Ok(()) => print(b"compositor: registered service\n"),
        Err(_) => print(b"compositor: svc_register failed\n"),
    }

    print(b"compositor: waiting for clients on IPC\n");

    // Passive: block on IPC endpoint waiting for Wayland client connections.
    // Do NOT touch framebuffer or KB/MOUSE rings until a client connects --
    // the serial console and LUCAS shell own those resources until then.
    loop {
        match sys::recv(ep_cap) {
            Ok(msg) => {
                print(b"compositor: client connected, activating\n");
                handle_new_connection(ep_cap, &msg);
                break;
            }
            Err(_) => {
                sys::yield_now();
            }
        }
    }

    // First client connected -- take over the framebuffer.
    unsafe {
        let fb = &mut *FB.get();
        fb.clear(BG_COLOR);
        *CURSOR_X.get() = (fb.width / 2) as i32;
        *CURSOR_Y.get() = (fb.height / 2) as i32;
    }

    // Active compositing loop with IPC polling.
    loop {
        // Poll for IPC messages (non-blocking with short timeout).
        poll_ipc(ep_cap);

        // Process input (may set damage flag).
        while let Some(scancode) = input::read_kb_scancode() {
            handle_keyboard(scancode);
        }
        while let Some(packet) = input::read_mouse_packet() {
            handle_mouse(packet);
        }

        // Frame pacing: only compose if damaged or interval elapsed.
        let now = rdtsc();
        let elapsed = unsafe { now.wrapping_sub(*LAST_FRAME_TSC.get()) };
        let damaged = unsafe { *DAMAGE.get() };

        if damaged || elapsed >= FRAME_INTERVAL {
            compose();
            unsafe {
                *LAST_FRAME_TSC.get() = now;
                *DAMAGE.get() = false;
            }
        } else {
            sys::yield_now();
        }
    }
}

// ---------------------------------------------------------------------------
// IPC message handling
// ---------------------------------------------------------------------------

/// Poll the IPC endpoint for incoming messages without blocking for long.
fn poll_ipc(ep_cap: u64) {
    // Use recv_timeout to avoid blocking the compositing loop.
    match sys::recv_timeout(ep_cap, IPC_POLL_TICKS) {
        Ok(msg) => {
            process_ipc_message(ep_cap, &msg);
        }
        Err(_) => {
            // Timeout or error -- no message pending, continue.
        }
    }
}

/// Process a single IPC message: either a new connection or a wire protocol message.
/// Note: WL_CONNECT_TAG check must come before WL_MSG_TAG because
/// WL_CONNECT_TAG's low 16 bits happen to equal WL_MSG_TAG.
fn process_ipc_message(ep_cap: u64, msg: &IpcMsg) {
    if msg.tag == WL_CONNECT_TAG {
        handle_new_connection(ep_cap, msg);
        return;
    }

    if (msg.tag & 0xFFFF) == WL_MSG_TAG {
        handle_wire_message(ep_cap, msg);
        return;
    }

    // Unknown tag -- treat as connection attempt.
    handle_new_connection(ep_cap, msg);
}

/// Register a new client connection.
fn handle_new_connection(ep_cap: u64, _msg: &IpcMsg) {
    let clients = unsafe { &mut *CLIENTS.get() };
    for i in 0..MAX_CLIENTS {
        if !clients[i].active {
            clients[i].active = true;
            clients[i].endpoint_cap = ep_cap;
            clients[i].objects = ClientObjects::empty();
            print(b"compositor: client ");
            print_u32_dec(i as u32);
            print(b" connected\n");

            // Send an acknowledgment reply so the client unblocks.
            let mut reply = IpcMsg::empty();
            reply.tag = WL_CONNECT_TAG;
            reply.regs[0] = 1; // success
            let _ = sys::send(ep_cap, &reply);
            return;
        }
    }
    // No free slots -- reject.
    print(b"compositor: no free client slots\n");
    let mut reply = IpcMsg::empty();
    reply.tag = WL_CONNECT_TAG;
    reply.regs[0] = 0; // failure
    let _ = sys::send(ep_cap, &reply);
}

/// Handle an incoming Wayland wire protocol message.
fn handle_wire_message(ep_cap: u64, msg: &IpcMsg) {
    // Extract raw bytes from IPC registers.
    let mut wire_buf = [0u8; IPC_DATA_MAX];
    let wire_len = wayland::ipc_to_wire(msg, &mut wire_buf);
    if wire_len < 8 {
        // Too short for a Wayland header -- send empty reply.
        let _ = sys::send(ep_cap, &IpcMsg::empty());
        return;
    }

    // Parse the Wayland message header.
    let mut wl_msg = WlMessage::empty();
    let consumed = match wl_msg.parse_header(&wire_buf[..wire_len]) {
        Some(n) => n,
        None => {
            print(b"compositor: malformed wayland msg\n");
            let _ = sys::send(ep_cap, &IpcMsg::empty());
            return;
        }
    };

    print(b"compositor: wl obj=");
    print_u32_dec(wl_msg.object_id);
    print(b" op=");
    print_u32_dec(wl_msg.opcode as u32);
    print(b" sz=");
    print_u32_dec(wl_msg.size as u32);
    print(b"\n");

    // Find which client this came from (first active client on this endpoint).
    let client_idx = find_client(ep_cap);
    if client_idx >= MAX_CLIENTS {
        print(b"compositor: msg from unknown client\n");
        let _ = sys::send(ep_cap, &IpcMsg::empty());
        return;
    }

    // Dispatch the message.
    let result = unsafe {
        let clients = &mut *CLIENTS.get();
        let serial = &mut *CONFIGURE_SERIAL.get();
        wayland::dispatch_message(&wl_msg, &mut clients[client_idx].objects, serial)
    };

    // Apply state changes from the dispatch result.
    apply_dispatch_result(client_idx, &result);

    // If there are remaining bytes in the buffer (multiple messages packed
    // into one IPC transfer), parse them too.
    let mut offset = consumed;
    while offset + 8 <= wire_len {
        let mut next_msg = WlMessage::empty();
        match next_msg.parse_header(&wire_buf[offset..wire_len]) {
            Some(n) => {
                let next_result = unsafe {
                    let clients = &mut *CLIENTS.get();
                    let serial = &mut *CONFIGURE_SERIAL.get();
                    wayland::dispatch_message(&next_msg, &mut clients[client_idx].objects, serial)
                };
                apply_dispatch_result(client_idx, &next_result);
                // Send events for this sub-message inline.
                send_events(ep_cap, &next_result);
                offset += n;
            }
            None => break,
        }
    }

    // Send response events for the first (or only) message.
    send_events(ep_cap, &result);
}

/// Send response events back to the client via IPC.
fn send_events(ep_cap: u64, result: &DispatchResult) {
    if result.event_count == 0 {
        // Always send a reply so the client unblocks (even if no events).
        let _ = sys::send(ep_cap, &IpcMsg::empty());
        return;
    }

    // Pack events into IPC reply.
    let reply = wayland::events_to_ipc(&result.events, result.event_count);
    let _ = sys::send(ep_cap, &reply);
}

/// Find the client index for the given endpoint capability.
fn find_client(ep_cap: u64) -> usize {
    let clients = unsafe { &*CLIENTS.get() };
    for i in 0..MAX_CLIENTS {
        if clients[i].active && clients[i].endpoint_cap == ep_cap {
            return i;
        }
    }
    // If no client found, use the first active client as fallback.
    // This handles the case where all clients share the same service endpoint.
    for i in 0..MAX_CLIENTS {
        if clients[i].active {
            return i;
        }
    }
    MAX_CLIENTS // sentinel: no client found
}

/// Apply state changes from a dispatch result to the global compositor state.
fn apply_dispatch_result(client_idx: usize, result: &DispatchResult) {
    // New surface created?
    if result.new_surface_id != 0 {
        let surfaces = unsafe { &mut *SURFACES.get() };
        for i in 0..MAX_SURFACES {
            if !surfaces[i].active {
                surfaces[i].active = true;
                surfaces[i].surface_id = result.new_surface_id;
                surfaces[i].client_idx = client_idx;
                surfaces[i].buffer_idx = None;
                surfaces[i].committed = false;
                print(b"compositor: new surface ");
                print_u32_dec(result.new_surface_id);
                print(b"\n");
                break;
            }
        }
    }

    // Surface attach?
    if result.attach.0 != 0 {
        let (surface_id, buffer_id) = result.attach;
        let surfaces = unsafe { &mut *SURFACES.get() };
        let buffers = unsafe { &*BUFFERS.get() };
        for i in 0..MAX_SURFACES {
            if surfaces[i].active && surfaces[i].surface_id == surface_id {
                // Find the buffer index.
                for bi in 0..MAX_BUFFERS {
                    if buffers[bi].active && buffers[bi].buffer_id == buffer_id {
                        surfaces[i].buffer_idx = Some(bi);
                        break;
                    }
                }
                break;
            }
        }
    }

    // Surface committed?
    if result.committed_surface_id != 0 {
        let surfaces = unsafe { &mut *SURFACES.get() };
        for i in 0..MAX_SURFACES {
            if surfaces[i].active && surfaces[i].surface_id == result.committed_surface_id {
                surfaces[i].committed = true;
                mark_damage();
                break;
            }
        }
    }

    // New toplevel?
    let (tl_id, xdg_id, wl_surf_id) = result.new_toplevel;
    if tl_id != 0 {
        let toplevels = unsafe { &mut *TOPLEVELS.get() };
        for i in 0..MAX_TOPLEVELS {
            if !toplevels[i].active {
                toplevels[i].active = true;
                toplevels[i].toplevel_id = tl_id;
                toplevels[i].xdg_surface_id = xdg_id;
                toplevels[i].wl_surface_id = wl_surf_id;
                toplevels[i].x = 50 + (i as i32 * 30); // cascade
                toplevels[i].y = 50 + (i as i32 * 30) + TITLE_BAR_HEIGHT as i32;
                toplevels[i].width = 640;
                toplevels[i].height = 480;
                print(b"compositor: new toplevel ");
                print_u32_dec(tl_id);
                print(b"\n");
                mark_damage();
                break;
            }
        }
    }

    // Title update?
    let (title_tl_id, ref title_buf, title_len) = result.title_update;
    if title_tl_id != 0 && title_len > 0 {
        let toplevels = unsafe { &mut *TOPLEVELS.get() };
        for i in 0..MAX_TOPLEVELS {
            if toplevels[i].active && toplevels[i].toplevel_id == title_tl_id {
                let copy_len = title_len.min(64);
                toplevels[i].title[..copy_len].copy_from_slice(&title_buf[..copy_len]);
                toplevels[i].title_len = copy_len;
                mark_damage();
                break;
            }
        }
    }

    // Damage reported?
    if result.damage {
        mark_damage();
    }
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

fn handle_keyboard(scancode: u8) {
    let is_release = scancode & 0x80 != 0;
    let code = scancode & 0x7F;
    let keycode = wayland::seat::scancode_to_linux_keycode(code);
    if keycode == 0 { return; }

    let state = if is_release { 0u32 } else { 1u32 };

    // Send wl_keyboard::key to focused client's keyboard.
    // (Simplified: send to first client with a keyboard binding.)
    let _ = (keycode, state); // TODO: send via IPC once clients connect

    mark_damage();
}

fn handle_mouse(packet: input::MousePacket) {
    unsafe {
        let fb = &*FB.get();
        let cx = &mut *CURSOR_X.get();
        let cy = &mut *CURSOR_Y.get();
        *cx = (*cx + packet.dx).max(0).min(fb.width as i32 - 1);
        *cy = (*cy + packet.dy).max(0).min(fb.height as i32 - 1);
    }

    mark_damage();

    // TODO: hit-test toplevels, send wl_pointer::motion/button/frame events
}

// ---------------------------------------------------------------------------
// Compositing
// ---------------------------------------------------------------------------

fn compose() {
    unsafe {
        let fb = &mut *FB.get();
        let toplevels = &*TOPLEVELS.get();
        let surfaces = &*SURFACES.get();
        let buffers = &*BUFFERS.get();
        let pools = &*POOLS.get();

        // Clear background (needed since we only redraw on damage).
        fb.clear(BG_COLOR);

        // Draw all active toplevels.
        for i in 0..MAX_TOPLEVELS {
            let tl = &toplevels[i];
            if !tl.active { continue; }

            // Draw title bar.
            fb.draw_title_bar(
                tl.x, tl.y - TITLE_BAR_HEIGHT as i32,
                tl.width,
                &tl.title[..tl.title_len],
            );

            // Find the surface and its buffer.
            for si in 0..MAX_SURFACES {
                let surf = &surfaces[si];
                if !surf.active || surf.surface_id != tl.wl_surface_id { continue; }
                if !surf.committed { continue; }

                if let Some(buf_idx) = surf.buffer_idx {
                    let buf = &buffers[buf_idx];
                    if !buf.active { continue; }

                    // Find the pool and blit the buffer.
                    let pool_idx = buf.pool_idx;
                    if pool_idx < MAX_POOLS && pools[pool_idx].active {
                        let pool = &pools[pool_idx];
                        let src = (pool.mapped_vaddr + buf.offset as u64) as *const u32;
                        fb.blit(tl.x, tl.y, buf.width, buf.height, src, buf.stride);
                    }
                }
                break;
            }
        }

        // Draw cursor on top.
        fb.draw_cursor(*CURSOR_X.get(), *CURSOR_Y.get());
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"compositor: PANIC: ");
    if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        for &b in file { sys::debug_print(b); }
        print(b":");
        print_u32_dec(loc.line());
    }
    print(b"\n");
    loop { sys::yield_now(); }
}
