#!/usr/bin/env python3
"""Test glibc dynamic binaries on sotOS — Operacion Ubuntu.

Runs Ubuntu's dynamically-linked binaries (glibc) inside sotOS.
Tests: VFS ELF loading -> glibc ld-linux -> dynamic linking -> binary execution.

Requires disk built with Ubuntu glibc:
  python scripts/fetch_rootfs.py --ubuntu --disk
"""

import sys, time, subprocess, threading

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
IMAGE = "target/sotos.img"
DISK = "target/disk.img"

class Session:
    def __init__(self):
        self.output = bytearray()
        self.lock = threading.Lock()
    def start(self):
        self.proc = subprocess.Popen(
            [QEMU, "-drive", f"format=raw,file={IMAGE}",
             "-drive", f"if=none,format=raw,file={DISK},id=disk0",
             "-device", "virtio-blk-pci,drive=disk0,disable-modern=on",
             "-serial", "stdio", "-display", "none", "-no-reboot", "-m", "512M",
             "-netdev", "user,id=net0",
             "-device", "virtio-net-pci,netdev=net0,disable-modern=on"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
    def _read_loop(self):
        while True:
            b = self.proc.stdout.read(1)
            if not b: break
            with self.lock:
                self.output.extend(b)
    def wait_for(self, text, timeout=60):
        t0 = time.time()
        while time.time() - t0 < timeout:
            with self.lock:
                if text.encode() in self.output: return True
            time.sleep(0.1)
        return False
    def get_output(self):
        with self.lock: return self.output.decode('utf-8', errors='replace')
    def send(self, cmd):
        for ch in cmd:
            self.proc.stdin.write(ch.encode())
            self.proc.stdin.flush()
            time.sleep(0.05)
        self.proc.stdin.write(b'\n')
        self.proc.stdin.flush()
    def clear(self):
        with self.lock: self.output.clear()
    def stop(self):
        try: self.proc.kill()
        except: pass

def main():
    s = Session()
    s.start()
    print("Waiting for LUCAS shell...")
    if not s.wait_for("$", 80):
        print("FAIL: shell not ready")
        print(s.get_output()[-500:])
        s.stop()
        return 1

    time.sleep(3)

    # Test 1: echo_ubuntu (simplest glibc binary)
    s.clear()
    print("\n=== Test 1: echo_ubuntu ===")
    cmd = "/usr/bin/echo_ubuntu glibc-works"
    print(f"  cmd: {cmd}")
    s.send(cmd)

    got_echo = s.wait_for("glibc-works", 60)
    s.wait_for("$", 30)
    out = s.get_output()

    lines = out.strip().split('\n')
    for line in lines[:20]:
        print(f"  | {line[:200]}")
    if len(lines) > 20:
        print(f"  ... {len(lines)-20} more lines ...")
        for line in lines[-5:]:
            print(f"  | {line[:200]}")
    print(f"  {'[PASS]' if got_echo else '[FAIL]'}")

    if not got_echo:
        # Analyze failure
        has_fault = any(x in out.lower() for x in ["page fault", "gpf", "panic"])
        has_unimpl = any(x in out.lower() for x in ["unimplemented", "unknown syscall"])
        has_exec = "exec: failed" in out

        if has_fault:
            print("  Diagnosis: Crashed (page fault / GPF)")
        elif has_unimpl:
            print("  Diagnosis: Hit unimplemented syscall")
        elif has_exec:
            print("  Diagnosis: Binary not found or ELF loading failed")
        else:
            print("  Diagnosis: No output (glibc init may be blocking)")

        print("\n  Last 15 lines:")
        for line in lines[-15:]:
            print(f"  | {line[:200]}")

    time.sleep(3)

    # Test 2: ls_ubuntu /
    s.clear()
    print("\n=== Test 2: ls_ubuntu / ===")
    cmd = "/usr/bin/ls_ubuntu /"
    print(f"  cmd: {cmd}")
    s.send(cmd)

    got_ls = s.wait_for("bin", 60) or s.wait_for("lib", 60)
    s.wait_for("$", 30)
    out = s.get_output()

    lines = out.strip().split('\n')
    for line in lines[:20]:
        print(f"  | {line[:200]}")
    if len(lines) > 20:
        print(f"  ... {len(lines)-20} more lines ...")
    print(f"  {'[PASS]' if got_ls else '[FAIL]'}")

    if not got_ls:
        print("\n  Last 15 lines:")
        for line in lines[-15:]:
            print(f"  | {line[:200]}")

    print("\n" + "=" * 50)
    results = [got_echo, got_ls]
    passed = sum(1 for r in results if r)
    print(f"glibc on sotOS: {passed}/{len(results)} tests passed")

    s.stop()
    return 0 if all(results) else 1

if __name__ == '__main__':
    sys.exit(main())
