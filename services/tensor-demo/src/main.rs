//! Typed IPC tensor pipeline demo for sotOS.
//!
//! Demonstrates the typed IPC payload system by creating tensors and images,
//! sending them via IPC endpoints, and verifying correctness on the receiver.
//!
//! IPC register packing for typed payloads:
//!   tag       = payload discriminant (1=Tensor, 3=Image)
//!   regs[0]   = data_phys (physical address of backing frame)
//!   regs[1..] = descriptor fields packed per type
//!
//! Output:
//!   === Typed IPC Demo ===
//!   Tensor 4x4 F32 (identity matrix): PASS
//!   Image 8x8 RGBA (gradient): PASS

#![no_std]
#![no_main]

use sotos_common::sys;

// ---------------------------------------------------------------------------
// Payload discriminants (matching kernel typed_payload.rs PayloadType)
// ---------------------------------------------------------------------------
const TAG_TENSOR: u64 = 1;
const TAG_IMAGE: u64 = 3;

// DataType::F32 = 0, ImageFormat::Rgba8 = 0
const DTYPE_F32: u64 = 0;
const FMT_RGBA8: u64 = 0;

// Map flags: bit 1 = WRITABLE, bit 63 = NO_EXECUTE
const MAP_RW_NX: u64 = (1 << 1) | (1 << 63);

// Virtual addresses for our data pages (well above .text/.data)
const TENSOR_VADDR: u64 = 0xF00000;
const IMAGE_VADDR: u64 = 0xF01000;
const ECHO_STACK_VADDR: u64 = 0xF10000;

// ---------------------------------------------------------------------------
// Serial output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a u32 from a physical address via the kernel debug HHDM read.
fn read_phys_u32(phys: u64) -> u32 {
    let val64 = sys::debug_phys_read(phys & !7);
    if (phys & 4) == 0 { val64 as u32 } else { (val64 >> 32) as u32 }
}

/// Build a pass/fail IPC reply with the given tag.
fn reply_msg(tag: u64, pass: bool) -> sotos_common::IpcMsg {
    sotos_common::IpcMsg {
        tag,
        regs: [if pass { 1 } else { 0 }, 0, 0, 0, 0, 0, 0, 0],
    }
}

// ---------------------------------------------------------------------------
// Echo thread -- receives typed IPC messages, verifies, replies PASS/FAIL
// ---------------------------------------------------------------------------

/// Endpoint cap ID, written by main thread before spawning echo thread.
static mut ECHO_EP: u64 = 0;

/// Echo thread entry point. Receives two messages (tensor, image), verifies
/// each, and replies with result (regs[0] = 1 for pass, 0 for fail).
unsafe extern "C" fn echo_thread() -> ! {
    let ep = unsafe { ECHO_EP };

    if let Ok(msg) = sys::recv(ep) {
        let _ = sys::send(ep, &reply_msg(TAG_TENSOR, verify_tensor(&msg)));
    }

    if let Ok(msg) = sys::recv(ep) {
        let _ = sys::send(ep, &reply_msg(TAG_IMAGE, verify_image(&msg)));
    }

    sys::thread_exit();
}

/// Verify a tensor descriptor carried in IPC registers.
///
/// Register packing:
///   tag     = TAG_TENSOR (1)
///   regs[0] = data_phys
///   regs[1] = dims[0] | (dims[1] << 32)
///   regs[2] = ndim | (dtype << 8) | (data_size << 16)
fn verify_tensor(msg: &sotos_common::IpcMsg) -> bool {
    if msg.tag != TAG_TENSOR {
        return false;
    }

    let data_phys = msg.regs[0];
    let dim0 = (msg.regs[1] & 0xFFFFFFFF) as u32;
    let dim1 = (msg.regs[1] >> 32) as u32;
    let ndim = (msg.regs[2] & 0xFF) as u8;
    let dtype = ((msg.regs[2] >> 8) & 0xFF) as u8;
    let data_size = (msg.regs[2] >> 16) as u32;

    if dim0 != 4 || dim1 != 4 || ndim != 2 || dtype != DTYPE_F32 as u8 || data_size != 64 {
        return false;
    }

    // Verify identity matrix: diag=1.0f32, rest=0.0f32
    for row in 0u64..4 {
        for col in 0u64..4 {
            let phys = data_phys + (row * 4 + col) * 4;
            let expected = if row == col { 0x3F80_0000u32 } else { 0u32 };
            if read_phys_u32(phys) != expected {
                return false;
            }
        }
    }

    true
}

/// Verify an image descriptor carried in IPC registers.
///
/// Register packing:
///   tag     = TAG_IMAGE (3)
///   regs[0] = data_phys
///   regs[1] = width | (height << 32)
///   regs[2] = format | (stride << 8)
fn verify_image(msg: &sotos_common::IpcMsg) -> bool {
    if msg.tag != TAG_IMAGE {
        return false;
    }

    let data_phys = msg.regs[0];
    let width = (msg.regs[1] & 0xFFFFFFFF) as u32;
    let height = (msg.regs[1] >> 32) as u32;
    let format = (msg.regs[2] & 0xFF) as u8;
    let stride = (msg.regs[2] >> 8) as u32;

    if width != 8 || height != 8 || format != FMT_RGBA8 as u8 || stride != 32 {
        return false;
    }

    // Verify gradient: RGBA little-endian, r=x*32, g=y*32, b=128, a=255
    for y in 0u64..8 {
        for x in 0u64..8 {
            let phys = data_phys + y * stride as u64 + x * 4;
            let pixel = read_phys_u32(phys);
            let r = (pixel & 0xFF) as u8;
            let g = ((pixel >> 8) & 0xFF) as u8;
            let b = ((pixel >> 16) & 0xFF) as u8;
            let a = ((pixel >> 24) & 0xFF) as u8;

            if r != (x as u8).wrapping_mul(32)
                || g != (y as u8).wrapping_mul(32)
                || b != 128
                || a != 255
            {
                return false;
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"=== Typed IPC Demo ===\n");

    // 1. Allocate and map a frame for tensor data (4x4 f32 = 64 bytes)
    let tensor_frame = sys::frame_alloc().expect("tensor frame_alloc");
    sys::map(TENSOR_VADDR, tensor_frame, MAP_RW_NX).expect("tensor map");
    let tensor_phys = sys::frame_phys(tensor_frame).expect("tensor frame_phys");

    // Fill with identity matrix: mat[i][j] = if i==j { 1.0 } else { 0.0 }
    let tensor_ptr = TENSOR_VADDR as *mut f32;
    for row in 0..4u32 {
        for col in 0..4u32 {
            let val: f32 = if row == col { 1.0 } else { 0.0 };
            unsafe { tensor_ptr.add((row * 4 + col) as usize).write_volatile(val); }
        }
    }

    // 2. Allocate and map a frame for image data (8x8 RGBA = 256 bytes)
    let image_frame = sys::frame_alloc().expect("image frame_alloc");
    sys::map(IMAGE_VADDR, image_frame, MAP_RW_NX).expect("image map");
    let image_phys = sys::frame_phys(image_frame).expect("image frame_phys");

    // Fill with gradient: r=x*32, g=y*32, b=128, a=255
    let image_ptr = IMAGE_VADDR as *mut u8;
    for y in 0u8..8 {
        for x in 0u8..8 {
            let off = (y as usize) * 32 + (x as usize) * 4;
            unsafe {
                image_ptr.add(off).write_volatile(x.wrapping_mul(32));     // R
                image_ptr.add(off + 1).write_volatile(y.wrapping_mul(32)); // G
                image_ptr.add(off + 2).write_volatile(128);                // B
                image_ptr.add(off + 3).write_volatile(255);                // A
            }
        }
    }

    // 3. Create endpoint for typed IPC exchange
    let ep = sys::endpoint_create().expect("endpoint_create");

    // 4. Allocate stack + spawn echo thread
    let stack_frame = sys::frame_alloc().expect("stack frame_alloc");
    sys::map(ECHO_STACK_VADDR, stack_frame, MAP_RW_NX).expect("stack map");
    let stack_top = ECHO_STACK_VADDR + 4096; // stack grows down

    unsafe { ECHO_EP = ep; }

    let _echo_tid = sys::thread_create(
        echo_thread as *const () as u64,
        stack_top,
    ).expect("thread_create echo");

    // Give the echo thread a moment to reach recv()
    for _ in 0..10 {
        sys::yield_now();
    }

    // 5. Send tensor descriptor via typed IPC
    //    Pack TensorDesc into IPC registers:
    //      tag     = TAG_TENSOR
    //      regs[0] = data_phys
    //      regs[1] = dims[0] | (dims[1] << 32)
    //      regs[2] = ndim | (dtype << 8) | (data_size << 16)
    let tensor_msg = sotos_common::IpcMsg {
        tag: TAG_TENSOR,
        regs: [
            tensor_phys,
            4 | (4 << 32),                    // dims[0]=4, dims[1]=4
            2 | (DTYPE_F32 << 8) | (64 << 16), // ndim=2, dtype=F32, data_size=64
            0, 0, 0, 0, 0,
        ],
    };
    let tensor_result = sys::call(ep, &tensor_msg);
    let tensor_pass = match tensor_result {
        Ok(reply) => reply.regs[0] == 1,
        Err(_) => false,
    };

    print(b"Tensor 4x4 F32 (identity matrix): ");
    if tensor_pass { print(b"PASS\n"); } else { print(b"FAIL\n"); }

    // 6. Send image descriptor via typed IPC
    //    Pack ImageDesc into IPC registers:
    //      tag     = TAG_IMAGE
    //      regs[0] = data_phys
    //      regs[1] = width | (height << 32)
    //      regs[2] = format | (stride << 8)
    let image_msg = sotos_common::IpcMsg {
        tag: TAG_IMAGE,
        regs: [
            image_phys,
            8 | (8 << 32),              // width=8, height=8
            FMT_RGBA8 | (32 << 8),      // format=RGBA8, stride=32
            0, 0, 0, 0, 0,
        ],
    };
    let image_result = sys::call(ep, &image_msg);
    let image_pass = match image_result {
        Ok(reply) => reply.regs[0] == 1,
        Err(_) => false,
    };

    print(b"Image 8x8 RGBA (gradient): ");
    if image_pass { print(b"PASS\n"); } else { print(b"FAIL\n"); }

    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"TENSOR-DEMO: PANIC!\n");
    loop { sys::yield_now(); }
}
