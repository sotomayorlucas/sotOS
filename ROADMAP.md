# sotOS Development Roadmap

> Current state: All kernel primitives implemented and tested. 12 userspace threads
> demonstrate sync/async IPC, capabilities, notifications, shared-memory, IRQ
> virtualization, demand paging (VMM), and ELF loading from initramfs. First Rust
> userspace program runs from disk.

---

## Phase 0 — Foundation (DONE)

- [x] Project scaffold (Cargo workspace, toolchain, linker script)
- [x] Limine boot protocol integration (v0.5 crate, v8 bootloader)
- [x] Serial output driver (COM1 16550 UART)
- [x] GDT + TSS (double fault IST stack)
- [x] IDT with CPU exception handlers (breakpoint, double fault, GPF, page fault)
- [x] Bitmap physical frame allocator (from bootloader memory map)
- [x] Capability table with CDT revocation
- [x] IPC endpoint skeleton (create only)
- [x] Thread Control Block definition
- [x] Syscall ABI definition (`sotos-common`)
- [x] QEMU boot pipeline (`just run` → build → mkimage → QEMU serial)

---

## Phase 1 — Preemption & Context Switching (DONE)

**Goal**: The CPU can run multiple kernel threads and switch between them on a timer tick.

- [x] 8254 PIT at 100 Hz, 8259 PIC remapped to vectors 32+
- [x] Assembly `context_switch` trampoline (callee-saved regs + RSP swap)
- [x] Thread creation with initial stack frame, `#[unsafe(naked)]` trampoline
- [x] Round-robin scheduler with 10-tick timeslice, circular run queue

### Milestone: Multiple kernel threads printing interleaved output to serial.

---

## Phase 2 — Syscall Interface & Ring 3 (DONE)

**Goal**: Userspace code can execute, trap into the kernel via `syscall`, and return.

- [x] SYSCALL/SYSRET via EFER/STAR/LSTAR/FMASK MSRs
- [x] Syscall entry/exit assembly (kernel stack swap, TrapFrame, dispatcher)
- [x] GDT restructured for SYSRET segment ordering
- [x] Bootstrap paging (`AddressSpace::new_user()`, 4-level page table walk)
- [x] First userspace process (assembly blob, prints "INIT\n" via `SYS_DEBUG_PRINT`)

### Milestone: A userspace process runs, syscalls into the kernel, and returns.

---

## Phase 3 — IPC: Send, Receive, Call (DONE)

**Goal**: Two userspace threads can exchange messages through kernel endpoints.

- [x] Synchronous endpoint IPC: `sys_send`, `sys_recv`, `sys_call` (rendezvous)
- [x] Register-based transfer: 8 regs × 8 bytes = 64 bytes per message
- [x] Ping-pong integration test (sender/receiver IPC demo)
- [ ] Capability transfer via IPC message register
- [ ] IPC round-trip latency benchmark (rdtsc)

### Milestone: Two processes communicate via IPC.

---

## Phase 4 — IRQ Virtualization (DONE)

**Goal**: Hardware interrupts are delivered to userspace driver threads via notifications.

- [x] Notification-based IRQ binding (`irq.rs` rewritten, ~55 LOC)
- [x] `sys_irq_register(irq_cap, notify_cap)`: bind IRQ line to notification
- [x] `sys_irq_ack(irq_cap)`: unmask IRQ line after handling
- [x] `sys_port_in(cap, port)` / `sys_port_out(cap, port, val)`: I/O port access
- [x] Userspace keyboard driver (IRQ 1 → notification → port 0x60 read)
- [x] Userspace serial driver (COM1 IRQ 4, receive interrupt, hex echo)
- [ ] Detect APIC via CPUID / ACPI MADT (currently 8259 PIC only)
- [ ] Move serial output fully to userspace (keep `kprintln!` as kernel fallback)

### Milestone: Userspace drivers handle keyboard and serial via IRQ notifications.

---

## Phase 5 — Userspace VMM Server (DONE)

**Goal**: Virtual memory is managed by a userspace server, not the kernel.

- [x] `sys_frame_alloc()` / `sys_frame_free()`: physical frame management with caps
- [x] `sys_map(vaddr, frame_cap, flags)` / `sys_unmap(vaddr)`: page table manipulation
- [x] Page fault handler delivers fault info to VMM server via notification
- [x] VMM server: receives faults, allocates frames, maps pages, resumes threads
- [x] Demand paging proven: fault test touches unmapped 0x600000, VMM handles it
- [x] Exokernel bypass: `sys_map()` callable directly with frame cap (no VMM needed)
- [x] `ThreadState::Faulted` distinct from Blocked (prevents accidental wake)
- [x] `sys_thread_resume(tid)` for VMM to resume faulted threads

### Milestone: Page faults handled by userspace. Demand paging works.

---

## Phase 6 — ELF Loader & Initramfs (DONE)

**Goal**: Load Rust-compiled ELF binaries from disk and run them in userspace.

- [x] ELF64 ET_EXEC loader in kernel (`elf.rs`): maps PT_LOAD segments
- [x] CPIO newc parser in kernel (`initrd.rs`): finds files in archive
- [x] CPIO initrd builder (`scripts/mkinitrd.py`)
- [x] Limine ModuleRequest delivers initrd as boot module
- [x] `sotos-common::sys` module: raw syscall wrappers for userspace
- [x] First Rust userspace program (`services/init/`): prints "ELF!\n"
- [x] Build pipeline: `build-user` → `initrd` → `image` → `run`
- [ ] Init service that spawns further processes (currently just a test)
- [ ] Root capability delegation from kernel to init
- [ ] argc/argv/envp or simplified init ABI

### Milestone: Rust userspace binary loaded from initrd, runs, and exits.

---

## Phase 7 — Shared-Memory Channels (Fast IPC)

**Goal**: High-throughput zero-copy data transfer between services.

Basic async channels (kernel ring buffers) already exist from Phase 3 extras.
This phase adds the lock-free userspace-only fast path.

### 7.1 Lock-Free SPSC Ring Buffer
- [ ] Kernel allocates shared memory region between two processes
- [ ] Lock-free single-producer single-consumer ring buffer in userspace
  - Producer writes data + updates write pointer (atomic store)
  - Consumer reads data + updates read pointer (atomic store)
  - Zero syscalls on the hot path
- [ ] Syscall only needed for block/wake when ring is full/empty

### 7.2 Typed Channels (IDL)
- [ ] Design an Interface Definition Language for message schemas
- [ ] Code generator: IDL → Rust stubs for serialize/deserialize
- [ ] Type checking at compile time, zero parsing at runtime

### 7.3 Benchmarks
- [ ] Throughput test: stream N MiB between two processes
- [ ] Compare: endpoint IPC vs shared-memory channel vs raw memcpy baseline
- [ ] Target: channel throughput within 10% of raw memcpy

### Milestone: Zero-copy data streaming between services at near-memcpy speed.

---

## Phase 8 — SMP (Multi-Core)

**Goal**: The kernel runs on all available CPU cores.

### 8.1 AP Startup
- [ ] Parse ACPI MADT to find all local APICs
- [ ] Limine SMP request: get list of CPUs from bootloader
- [ ] Boot Application Processors (APs) into the kernel
- [ ] Per-CPU data structures (current thread, local APIC, per-CPU run queue)

### 8.2 SMP Scheduler
- [ ] Per-core run queues with work stealing
- [ ] Affinity hints: a thread can prefer a specific core (cache locality)
- [ ] Global load balancer: periodically rebalance across cores

### 8.3 Synchronization
- [ ] Audit all spinlocks for SMP safety (interrupt disable + spin)
- [ ] Add ticket locks or MCS locks where contention is expected
- [ ] IPI (Inter-Processor Interrupt) for cross-core notifications

### Milestone: Kernel utilizes all cores. Threads migrate between cores.

---

## Phase 9 — Scheduling Domains

**Goal**: Userspace can implement custom schedulers for their own threads.

### 9.1 Domain API
- [ ] `sys_sched_domain_create(quantum_us)`: create a scheduling domain with a budget
- [ ] The kernel schedules domains (not individual user threads within a domain)
- [ ] Domain manager thread receives its quantum and distributes it internally

### 9.2 Use Cases
- [ ] Go-style M:N green thread runtime as a scheduling domain
- [ ] Dedicated-core domain for latency-sensitive workloads
- [ ] Work-stealing pool domain for parallel compute

### 9.3 Enforcement
- [ ] If a domain exceeds its quantum → kernel preempts unconditionally
- [ ] Domains can request more/less quantum dynamically (kernel mediates)
- [ ] Priority inheritance across domain boundaries for IPC chains

### Milestone: A user-level scheduler manages green threads without kernel involvement.

---

## Phase 10 — LUCAS (Legacy UNIX Compatibility Abstraction System)

**Goal**: Run unmodified Linux/POSIX ELF binaries on sotOS.

LUCAS is a set of coordinated userspace servers that present a complete Linux illusion
to legacy binaries. It translates monolithic UNIX semantics into sotOS's decentralized,
capability-based primitives — entirely in Ring 3.

### 10.1 Syscall Interceptor (Trap Handler)
- [ ] Capture `syscall` instructions from the guest ELF binary in Ring 3
- [ ] Redirect to LUCAS translation engine instead of letting them reach Ring 0
- [ ] Map Linux syscall numbers (read=0, write=1, open=2, ...) to LUCAS handlers
- [ ] Handle the full lifecycle: `execve` → setup → syscall translation → `exit`

### 10.2 Capability Mapper (Ambient Authority Emulator)
- [ ] Maintain internal table: Linux file descriptors (FDs) → sotOS capabilities
- [ ] Emulate UID/GID/permission model on top of capabilities
- [ ] Map Linux PIDs to sotOS ThreadIds
- [ ] Hide CDT complexity from guest processes — present flat POSIX view
- [ ] Translate `open("/dev/...")` to capability lookups for device endpoints

### 10.3 VFS Bridge (Virtual File System Translator)
- [ ] Intercept POSIX file operations: `open`, `read`, `write`, `close`, `stat`, `lseek`
- [ ] Translate path-based access to Object Store transactions
- [ ] Expose typed objects as flat byte streams (what POSIX expects)
- [ ] Implement `/proc` and `/sys` as synthetic views of sotOS state
- [ ] Support `opendir`/`readdir` for directory enumeration

### 10.4 Process & Memory Coordinator
- [ ] Emulate `fork()`: create new address space + CoW via VMM server
- [ ] Emulate `execve()`: parse ELF, map segments, transfer FD table
- [ ] Emulate `mmap()`/`munmap()`: delegate to VMM server via `sys_map`/`sys_unmap`
- [ ] Emulate `brk()` for heap growth
- [ ] Emulate `clone()` for thread creation via `sys_thread_create`
- [ ] Emulate `wait()`/`waitpid()` via IPC notifications

### 10.5 IPC & Network Translator
- [ ] Translate UNIX pipes → sotOS shared-memory channels (ring buffers)
- [ ] Translate UNIX signals → sotOS endpoint messages
- [ ] Translate UNIX sockets:
  - Small control messages → sotOS sync endpoints
  - High-throughput streams → sotOS async channels (zero-copy)
- [ ] Emulate `select()`/`poll()`/`epoll()` over sotOS IPC primitives

### 10.6 Security: Confinement by Design
- [ ] LUCAS processes run in a strict capability sandbox
- [ ] No ambient authority: a compromised Linux binary cannot escape the LUCAS illusion
- [ ] RCE inside LUCAS = attacker trapped in emulated UNIX, no access to sotOS primitives
- [ ] Optional: per-binary capability policy (restrict which "Linux files" map to which capabilities)

### Milestone: `ls`, `cat`, `grep` and a basic shell run unmodified on sotOS via LUCAS.

---

## Phase 11 — Filesystem & Storage

**Goal**: Persistent storage accessible through the object store interface.

### 11.1 Block Device Driver
- [ ] Virtio-blk driver (userspace, talks to QEMU)
- [ ] Block layer abstraction: read/write sectors through capabilities

### 11.2 Object Store
- [ ] Transactional object store (userspace service)
- [ ] Write-Ahead Log (WAL) for crash consistency
- [ ] Copy-on-Write snapshots for object versioning
- [ ] Schema-based typed objects with 128-bit OIDs

### 11.3 POSIX Compatibility
- [ ] VFS shim: translates open/read/write/close to object store operations
- [ ] Enough for basic utilities (shell, coreutils)

### Milestone: Data persists across reboots. Object store with transactional guarantees.

---

## Phase 12 — Networking & Distribution

**Goal**: Nodes communicate; IPC is transparent across the network.

### 12.1 Network Stack
- [ ] Virtio-net driver (userspace)
- [ ] Minimal IP/UDP/TCP stack (userspace service)
- [ ] Socket-like API through IPC endpoints

### 12.2 Remote IPC
- [ ] Transparent IPC proxy: local endpoint → network → remote endpoint
- [ ] Explicit failure semantics: `Result<T, RemoteError>` with timeouts
- [ ] OID resolution: distributed hash table for object location

### 12.3 Cluster Management
- [ ] Failure domains: process → node → cluster → swarm
- [ ] Raft consensus for critical shared state
- [ ] Service migration on node failure

### Milestone: Two sotOS nodes exchange IPC messages over the network.

---

## Phase 13 — Formal Verification & Hardening

**Goal**: Mathematical proof that the kernel is correct.

### 13.1 Verification
- [ ] Annotate kernel code with Verus/Prusti pre/post-conditions
- [ ] Prove: capability enforcement never bypassed
- [ ] Prove: frame allocator never double-allocates
- [ ] Prove: IPC transfer preserves message integrity
- [ ] Model check scheduler with TLA+ (no deadlocks, no starvation)

### 13.2 Hardware Security
- [ ] CHERI capability support (when hardware is available)
  - 128-bit fat pointers with hardware bounds checking
  - Spatial memory safety at instruction level
- [ ] IOMMU integration: device isolation for DMA
- [ ] Measured boot: TPM-backed chain of trust

### 13.3 Audit
- [ ] Security audit of syscall interface
- [ ] Fuzz all syscall paths (syzkaller-style)
- [ ] Penetration testing: escape from a confined process

### Milestone: Core kernel invariants formally verified. Hardware security integrated.

---

## Phase Summary

```
Phase  Scope                          Dependencies    Status
─────  ─────────────────────────────  ──────────────  ──────
  0    Foundation                     —               DONE
  1    Preemption + Context Switch    Phase 0         DONE
  2    Syscall + Ring 3               Phase 1         DONE
  3    IPC Send/Recv/Call + extras    Phase 2         DONE (no cap transfer, no benchmarks)
  4    IRQ Virtualization             Phase 3         DONE (PIC only, no APIC)
  5    VMM Server                     Phase 2         DONE
  6    ELF Loader + Initramfs         Phase 3,5       DONE (no full init service yet)
  7    Shared-Memory Channels         Phase 3         TODO (basic kernel channels done)
  8    SMP (Multi-Core)               Phase 1         TODO
  9    Scheduling Domains             Phase 8         TODO
 10    LUCAS (UNIX Compat Layer)      Phase 6,7,11    TODO
 11    Filesystem + Object Store      Phase 6         TODO
 12    Networking + Distribution      Phase 6,11      TODO
 13    Verification + Hardening       Phase 3+        TODO
```

```
                         Phase 0 (DONE)
                              │
                         Phase 1 (DONE)
                        ╱          ╲
                Phase 2              Phase 8
                (DONE)               (SMP)
              ╱     ╲                   │
        Phase 3    Phase 5         Phase 9
        (DONE)     (DONE)     (Sched Domains)
        ╱    ╲        │
  Phase 4   Phase 7   │
  (DONE)   (Channels)  │
        ╲    ╱        ╱
         Phase 6
         (DONE)
           │
     ┌─────┼─────┐
  Phase 11 │  Phase 12
  (Storage) │  (Network)
        ╲  │  ╱
       Phase 10
       (LUCAS)
           │
       Phase 13
    (Verification)
```

---

## Immediate Next Steps

Phases 0–6 are complete. The next unlocked phases are:

- **Phase 7 (Shared-Memory Channels)**: lock-free SPSC ring buffer in userspace for zero-syscall hot path. Basic kernel channels already work.
- **Phase 8 (SMP)**: independent of Phases 7+, can be started in parallel. Requires APIC, per-CPU state, Limine SMP request, and lock audit.
- **Phase 6 completion**: expand `services/init/` into a real init service that receives root capabilities and spawns VMM + drivers from config.

### Also open (smaller items from completed phases):
- IPC capability transfer (Phase 3 leftover)
- IPC latency benchmarks (Phase 3 leftover)
- APIC detection (Phase 4 leftover — needed for Phase 8 anyway)
