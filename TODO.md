# sotBSD / Project STYX — TODO

**Status**: Framework complete (Phases 0-5 implemented). Remaining work is toolchain + wiring.
**Branch**: `sotBSD`
**Updated**: 2026-03-29

---

## Tier 1 — Boot verification (1-2 days)

- [ ] QEMU boot test: verify STYX banner appears in serial output
  - TCG on Windows is slow with 310MB initrd
  - Try smaller initrd or WHPX with longer timeout
- [ ] Verify SOT syscalls 300-310 are reachable from userspace
- [ ] Write `services/styx-test/` minimal binary that calls so_create/tx_begin

---

## Tier 2 — BSD personality real (~1-2 weeks)

- [ ] Cross-compile `vendor/netbsd-rump/rumpuser_sot.c`
  - `clang --target=x86_64-unknown-none -ffreestanding -nostdlib`
  - Link as sotOS service (like lkl-server)
- [ ] Build librump.a from vendored NetBSD rump sources
  - NetBSD `build.sh` or manual Makefile for rump components
  - `sys/rump/librump/rumpkern/` + `rumpvfs/` minimum
- [ ] Link librump + rumpuser_sot into a rump VFS service
- [ ] Create FFS disk image, mount via rump VFS
- [ ] Test: `cat /etc/passwd` through rump VFS domain
- [ ] Connect rump network stack (rumpnet) for TCP/IP

---

## Tier 3 — Deception live demo (~3-5 days)

- [ ] Wire `GraphHunter::ingest()` to provenance ring drain in child_handler
- [ ] Create test "attacker" binary: reads /etc/shadow + writes /usr/bin/sshd
  - Should trigger CredentialTheftAfterBackdoor pattern
- [ ] Verify cap_interpose runtime: so_invoke on interposed cap routes through proxy
- [ ] End-to-end demo: attacker triggers anomaly -> automatic migration to deception
  - Domain continues operating, sees fake /proc/version "Linux 5.15.0-91-generic"
  - All post-migration activity logged in provenance
- [ ] Test with Ubuntu 22.04 webserver deception profile

---

## Tier 4 — Advanced features (~weeks)

### ZFS
- [ ] Compile OpenZFS libzpool for x86_64-unknown-none
- [ ] Connect to SOT block device capabilities
- [ ] Wire SnapshotManager.on_tx_commit() to ZFS snapshots
- [ ] Test: tx_abort -> rollback to previous ZFS snapshot

### FreeBSD pkg
- [ ] Requires rump VFS + rump network stack (Tier 2)
- [ ] Port pkg-static (musl-static build)
- [ ] Test: `pkg install nginx` via rump

### PF Firewall
- [ ] Extract FreeBSD PF as standalone library
- [ ] Wire as capability interposer between client and network domain
- [ ] Provenance-aware rules (query graph for decisions)

### bhyve Hypervisor
- [ ] VT-x/WHPX support in QEMU (-enable-kvm or WHPX)
- [ ] VMCS setup from sot-bhyve types
- [ ] CPUID/MSR spoofing (bare_metal_intel profile)
- [ ] Guest VM runs in domain with interposable caps
- [ ] Test: VM introspection detects guest kernel module load

### HAMMER2
- [ ] Compile DragonFlyBSD HAMMER2 as userspace library
- [ ] CoW snapshots tied to SOT transactions
- [ ] Clustering for distributed deception (Phase 3 of ISOS)

---

## Tier 5 — Production hardening

### Transactions
- [ ] Implement Tier 2 (2PC) coordinator for multi-object transactions
- [ ] Stress test concurrent transactions on same SO

### Performance
- [ ] Benchmark IPC cycles (target: <1000 for 64B message)
- [ ] Compare against seL4 (~500 cycles) and L4 (~700 cycles)
- [ ] Profile cap_interpose overhead per policy (Passthrough vs Inspect)
- [ ] Measure provenance ring buffer throughput

### Compatibility
- [ ] Run Linux Test Project (LTP) subset over Linuxulator
- [ ] Target >80% LTP pass rate
- [ ] Test Docker hello-world (stretch goal)

### Security
- [ ] Fuzz cap_interpose with malformed caps
- [ ] Fuzz epoch revocation race conditions
- [ ] Verify W^X enforcement cannot be bypassed
- [ ] Test domain escape attempts (from test crate)
- [ ] Signify boot chain: sign all binaries with Ed25519
- [ ] KARL-style re-randomization on each boot

### CI/CD
- [ ] GitHub Actions: kernel build + QEMU boot test
- [ ] TLC model checker run on all 6 TLA+ specs
- [ ] Clippy + fmt on all Rust code
- [ ] Cross-compile smoke test for rumpuser_sot.c

---

## Completed

- [x] Phase 0: SOT kernel core (13 modules, 11 syscalls, 3 TLA+ specs)
- [x] Phase 1: BSD vendor sources (NetBSD rump 499 files, FreeBSD 11 files, OpenBSD 9 files) + rumpuser_sot.c (2K LOC)
- [x] Phase 2: Process server (LUCAS bridge, Linuxulator errno/signal maps, policy engine + TOML parser)
- [x] Phase 3: Deception engine (kernel cap_interpose wiring, 4 profiles, anomaly detection, live migration)
- [x] Phase 4: OpenBSD security (ChaCha20 CSPRNG, W^X, ASLR, secure_string) + fast IPC (PCID, cap cache, shared memory rings)
- [x] Phase 5: Graph Hunter + BlastRadius, bhyve hypervisor domain, ZFS tx snapshots, HAMMER2 clustering
- [x] Boot wiring: STYX banner, SOT syscall wrappers in sotos-common, init compiles with sot_bridge
- [x] 20+ personality/driver/tool crates, 5 docs, 4 test crates (157+ tests), 5 CLI tools
