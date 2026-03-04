#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::spsc;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_virtio::blk::VirtioBlk;
use sotos_objstore::{ObjectStore, Vfs, DirEntry, DIR_ENTRY_COUNT};

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

    // --- Phase 4: Virtio-BLK demo + Object Store ---
    run_virtio_blk_demo(boot_info);

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

fn print_hex(val: u32) {
    let hex = b"0123456789ABCDEF";
    for i in (0..8).rev() {
        sys::debug_print(hex[((val >> (i * 4)) & 0xF) as usize]);
    }
}

fn init_virtio_blk(boot_info: &BootInfo) -> Option<VirtioBlk> {
    if boot_info.cap_count < 11 {
        print(b"BLK: no PCI cap, skipping\n");
        return None;
    }
    let pci_cap = boot_info.caps[10];
    let pci = PciBus::new(pci_cap);

    let (devices, count) = pci.enumerate::<32>();
    print(b"PCI: ");
    print_u64(count as u64);
    print(b" devices\n");

    for i in 0..count {
        let d = &devices[i];
        print(b"  ");
        print_u64(i as u64);
        print(b": vendor=");
        print_hex(d.vendor_id as u32);
        print(b" device=");
        print_hex(d.device_id as u32);
        print(b" class=");
        print_hex(d.class as u32);
        print(b":");
        print_hex(d.subclass as u32);
        print(b" irq=");
        print_u64(d.irq_line as u64);
        print(b"\n");
    }

    let blk_dev = match pci.find_device(0x1AF4, 0x1001) {
        Some(d) => d,
        None => {
            print(b"BLK: virtio-blk not found\n");
            return None;
        }
    };

    print(b"BLK: found at dev ");
    print_u64(blk_dev.addr.dev as u64);
    print(b" IRQ ");
    print_u64(blk_dev.irq_line as u64);
    print(b"\n");

    match VirtioBlk::init(&blk_dev, &pci) {
        Ok(blk) => {
            print(b"BLK: ");
            print_u64(blk.capacity);
            print(b" sectors\n");
            Some(blk)
        }
        Err(e) => {
            print(b"BLK: init failed: ");
            print(e.as_bytes());
            print(b"\n");
            None
        }
    }
}

fn run_virtio_blk_demo(boot_info: &BootInfo) {
    let mut blk = match init_virtio_blk(boot_info) {
        Some(b) => b,
        None => return,
    };

    // Read sector 0 and print first 16 bytes.
    match blk.read_sector(0) {
        Ok(()) => {
            print(b"BLK READ: ");
            let data = unsafe { core::slice::from_raw_parts(blk.data_ptr(), 16) };
            for &b in data {
                if b >= 0x20 && b < 0x7F {
                    sys::debug_print(b);
                } else {
                    sys::debug_print(b'.');
                }
            }
            print(b"\n");
        }
        Err(e) => {
            print(b"BLK READ ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    }

    // Write "WROTE\0" to sector 1.
    {
        let data = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), 512) };
        for b in data.iter_mut() {
            *b = 0;
        }
        let msg = b"WROTE";
        data[..msg.len()].copy_from_slice(msg);
    }
    match blk.write_sector(1) {
        Ok(()) => print(b"BLK WRITE OK\n"),
        Err(e) => {
            print(b"BLK WRITE ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    }

    // Read back sector 1 to verify.
    match blk.read_sector(1) {
        Ok(()) => {
            print(b"BLK VERIFY: ");
            let data = unsafe { core::slice::from_raw_parts(blk.data_ptr(), 16) };
            for &b in data {
                if b >= 0x20 && b < 0x7F {
                    sys::debug_print(b);
                } else if b == 0 {
                    break;
                } else {
                    sys::debug_print(b'.');
                }
            }
            print(b"\n");
        }
        Err(e) => {
            print(b"BLK VERIFY ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    }

    // --- Object Store + VFS demo ---
    run_objstore_demo(blk);
}

fn run_objstore_demo(blk: VirtioBlk) {
    // 1. Format a new filesystem.
    let store = match ObjectStore::format(blk) {
        Ok(s) => s,
        Err(e) => {
            print(b"OBJSTORE: format failed: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    };

    // 2. Create VFS.
    let mut vfs = Vfs::new(store);

    // 3. Create and write hello.txt.
    let fd = match vfs.create(b"hello.txt") {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS CREATE ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    };
    if let Err(e) = vfs.write(fd, b"Hello from sotOS!") {
        print(b"VFS WRITE ERR: ");
        print(e.as_bytes());
        print(b"\n");
        return;
    }
    let _ = vfs.close(fd);

    // 4. Read back hello.txt.
    let fd = match vfs.open(b"hello.txt", 1) {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS OPEN ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    };
    let mut buf = [0u8; 64];
    match vfs.read(fd, &mut buf) {
        Ok(n) => {
            print(b"VFS READ: ");
            print(&buf[..n]);
            print(b"\n");
        }
        Err(e) => {
            print(b"VFS READ ERR: ");
            print(e.as_bytes());
            print(b"\n");
        }
    }
    let _ = vfs.close(fd);

    // 5. Create data.bin with binary data.
    let fd = match vfs.create(b"data.bin") {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS CREATE ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    };
    let _ = vfs.write(fd, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    let _ = vfs.close(fd);

    // 6. List files.
    let mut entries = [DirEntry::zeroed(); DIR_ENTRY_COUNT];
    let count = vfs.store().list(&mut entries);
    print(b"VFS LIST: ");
    print_u64(count as u64);
    print(b" files\n");
    for i in 0..count {
        print(b"  ");
        print(entries[i].name_as_str());
        print(b" oid=");
        print_u64(entries[i].oid);
        print(b" size=");
        print_u64(entries[i].size);
        print(b"\n");
    }

    // 7. Delete data.bin.
    if let Err(e) = vfs.delete(b"data.bin") {
        print(b"VFS DELETE ERR: ");
        print(e.as_bytes());
        print(b"\n");
    }
    let remain = vfs.store().list(&mut entries);
    print(b"VFS: ");
    print_u64(remain as u64);
    print(b" files remain\n");

    // 8. Re-mount from disk and verify persistence.
    let blk = vfs.store_mut().into_blk();
    let store = match ObjectStore::mount(blk) {
        Ok(s) => s,
        Err(e) => {
            print(b"OBJSTORE: mount failed: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    };
    let mut vfs = Vfs::new(store);
    let fd = match vfs.open(b"hello.txt", 1) {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS REMOUNT OPEN ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return;
        }
    };
    let mut buf2 = [0u8; 64];
    match vfs.read(fd, &mut buf2) {
        Ok(n) => {
            print(b"VFS REMOUNT READ: ");
            print(&buf2[..n]);
            print(b"\n");
        }
        Err(e) => {
            print(b"VFS REMOUNT READ ERR: ");
            print(e.as_bytes());
            print(b"\n");
        }
    }
    let _ = vfs.close(fd);
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
