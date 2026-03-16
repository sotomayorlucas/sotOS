#!/usr/bin/env python3
"""Test fastfetch on sotOS — boots QEMU, runs fastfetch, captures output."""
import sys, time, subprocess, threading

QEMU = r"C:\Program Files\qemu\qemu-system-x86_64.exe"
IMAGE = "target/sotos.img"
OUTPUT = "target/fastfetch_output.txt"

class Session:
    def __init__(self):
        self.output = bytearray()
        self.lock = threading.Lock()

    def start(self):
        self.proc = subprocess.Popen(
            [QEMU, "-drive", f"format=raw,file={IMAGE}",
             "-serial", "stdio", "-display", "none", "-no-reboot", "-m", "512M"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0)
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
        with self.lock:
            return self.output.decode('utf-8', errors='replace')

    def output_size(self):
        with self.lock:
            return len(self.output)

    def send(self, cmd):
        for ch in cmd:
            self.proc.stdin.write(ch.encode())
            self.proc.stdin.flush()
            time.sleep(0.05)
        self.proc.stdin.write(b'\n')
        self.proc.stdin.flush()

    def clear(self):
        with self.lock:
            self.output.clear()

    def stop(self):
        try: self.proc.kill()
        except: pass

def main():
    s = Session()
    s.start()

    # Stage 1: Boot
    print("=== Stage 1: Boot ===", flush=True)
    if not s.wait_for("$", 60):
        print("  FAIL: no shell prompt within 60s", flush=True)
        out = s.get_output()
        with open(OUTPUT, 'w') as f: f.write(out)
        s.stop()
        return 1
    print("  Shell ready.", flush=True)
    time.sleep(0.5)

    # Stage 2: Run fastfetch
    print("\n=== Stage 2: fastfetch ===", flush=True)
    s.clear()
    s.send("fastfetch")

    # Wait up to 60s, stall detect at 15s
    t0 = time.time()
    last_size = 0
    stall_start = None
    found = False

    while time.time() - t0 < 60:
        with s.lock:
            cur = len(s.output)
            # fastfetch prints OS: or Host: or similar
            if b"OS" in s.output or b"Host" in s.output or b"Kernel" in s.output or b"sotOS" in s.output:
                found = True
        if found:
            # Let it finish printing
            time.sleep(3)
            break
        if cur == last_size:
            if stall_start is None: stall_start = time.time()
            elif time.time() - stall_start > 15:
                print("  Output stalled for 15s", flush=True)
                break
        else:
            stall_start = None
            last_size = cur
        time.sleep(0.5)

    out = s.get_output()
    s.stop()

    with open(OUTPUT, 'w') as f:
        f.write(out)
    print(f"\nOutput saved to {OUTPUT} ({len(out)} bytes, {out.count(chr(10))} lines)", flush=True)

    # Show the output
    print("\n" + "=" * 60, flush=True)
    print("FASTFETCH OUTPUT:", flush=True)
    print("=" * 60, flush=True)
    # Print raw output (may contain ANSI escapes)
    for line in out.split('\n'):
        stripped = line.rstrip()
        if stripped:
            print(stripped, flush=True)
    print("=" * 60, flush=True)

    # Check for unhandled syscalls
    unhandled = []
    for line in out.split('\n'):
        if 'unimpl' in line.lower() or 'unhandled' in line.lower():
            unhandled.append(line.strip())

    if unhandled:
        print(f"\nUnhandled syscalls ({len(unhandled)}):", flush=True)
        seen = set()
        for line in unhandled:
            if line not in seen:
                seen.add(line)
                print(f"  {line[:120]}", flush=True)

    if found:
        print("\nRESULT: PASS - fastfetch produced output!", flush=True)
        return 0
    else:
        print("\nRESULT: FAIL - no fastfetch output detected", flush=True)
        return 1

if __name__ == '__main__':
    sys.exit(main())
