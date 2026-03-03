#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::spsc;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};

/// Shared memory page for the SPSC ring buffer.
const RING_ADDR: u64 = 0xA00000;
/// Producer thread stack base (1 page).
const PRODUCER_STACK_BASE: u64 = 0xA10000;
/// Producer thread stack top.
const PRODUCER_STACK_TOP: u64 = PRODUCER_STACK_BASE + 0x1000;
/// Number of messages to send through the ring.
const MSG_COUNT: u64 = 1000;
/// WRITABLE flag for map syscall (bit 1).
const MAP_WRITABLE: u64 = 2;

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // --- Phase 1: Read BootInfo ---
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let cap_count = if boot_info.is_valid() {
        boot_info.cap_count
    } else {
        0
    };

    print(b"INIT: boot complete, ");
    print_u64(cap_count);
    print(b" caps received\n");

    // --- Phase 2: SPSC channel test ---
    // 1. Allocate and map shared page for ring buffer
    let ring_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
    sys::map(RING_ADDR, ring_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());

    // 2. Create notification objects (empty = consumer waits, full = producer waits)
    let empty_cap = sys::notify_create().unwrap_or_else(|_| panic_halt());
    let full_cap = sys::notify_create().unwrap_or_else(|_| panic_halt());

    // 3. Initialize SPSC ring at shared address
    let ring = unsafe {
        spsc::SpscRing::init(RING_ADDR as *mut u8, 128, empty_cap as u32, full_cap as u32)
    };

    // 4. Allocate and map producer stack
    let stack_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
    sys::map(PRODUCER_STACK_BASE, stack_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());

    // 5. Spawn producer thread
    let _thread_cap = sys::thread_create(producer as *const () as u64, PRODUCER_STACK_TOP)
        .unwrap_or_else(|_| panic_halt());

    // 6. Consumer loop: receive MSG_COUNT values and sum them
    let mut sum: u64 = 0;
    for _ in 0..MSG_COUNT {
        sum += spsc::recv(ring);
    }

    // 7. Print result: expected sum = 0+1+2+...+999 = 499500
    print(b"SPSC: sum=");
    print_u64(sum);
    print(b"\n");

    // --- Phase 3: Benchmarks ---
    run_benchmarks(ring);

    sys::thread_exit();
}

/// Producer entry point — runs in a separate thread, same address space.
#[unsafe(no_mangle)]
pub extern "C" fn producer() -> ! {
    let ring = unsafe { spsc::SpscRing::from_ptr(RING_ADDR as *mut u8) };
    for i in 0..MSG_COUNT {
        spsc::send(ring, i);
    }
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Read the CPU timestamp counter.
#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Run SPSC benchmarks after the main test completes.
fn run_benchmarks(ring: &spsc::SpscRing) {
    // Latency: measure try_send + try_recv round-trip (single-threaded, no contention)
    const LAT_ITERS: u64 = 10000;

    // Warm up
    for i in 0..128 {
        spsc::try_send(ring, i);
    }
    for _ in 0..128 {
        spsc::try_recv(ring);
    }

    let start = rdtsc();
    for i in 0..LAT_ITERS {
        spsc::try_send(ring, i);
        spsc::try_recv(ring);
    }
    let end = rdtsc();
    let cycles_per_msg = (end - start) / LAT_ITERS;

    print(b"BENCH: spsc_rt=");
    print_u64(cycles_per_msg);
    print(b"cy/msg\n");

    // Throughput: stream 10K messages (single-threaded, no blocking)
    const TPUT_MSGS: u64 = 10000;
    let start = rdtsc();
    for i in 0..TPUT_MSGS {
        while !spsc::try_send(ring, i) {}
        while spsc::try_recv(ring).is_none() {}
    }
    let end = rdtsc();
    let tput_cy = (end - start) / TPUT_MSGS;

    print(b"BENCH: spsc_tput=");
    print_u64(tput_cy);
    print(b"cy/msg (10000 msgs)\n");
}

fn panic_halt() -> ! {
    print(b"PANIC\n");
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"PANIC\n");
    loop {}
}
