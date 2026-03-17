#!/usr/bin/env python3
"""Test Alpine dynamic wget on sotOS — full-stack networking test.

Tests: VFS ELF loading -> musl dynamic linking -> socket -> TCP -> HTTP
Uses Alpine's dynamically-linked busybox (808KB, musl) invoked as wget.
QEMU SLIRP provides DNS (10.0.2.3) and NAT for outbound TCP.
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
    def wait_for_prompt(self, timeout=30):
        return self.wait_for("$ ", timeout)
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

    time.sleep(2)

    # Test: Alpine dynamic wget HTTP download by IP (example.com via Cloudflare)
    s.clear()
    print("\n=== Alpine dynamic wget (HTTP by IP) ===")
    print("  cmd: /usr/bin/wget http://104.18.27.120/ -O -")
    s.send("/usr/bin/wget http://104.18.27.120/ -O -")

    # Wait for HTML body — the full page is ~9KB
    got_html = s.wait_for("</html>", 90)
    if not got_html:
        got_html = s.wait_for("<!DOCTYPE", 10)
    # Wait for shell prompt (wget finished)
    s.wait_for("$", 30)
    out = s.get_output()

    # Check results
    has_doctype = "<!DOCTYPE" in out
    has_html_close = "</html>" in out
    has_body = "<body" in out

    print(f"\n  Results:")
    print(f"    <!DOCTYPE html>  : {'YES' if has_doctype else 'NO'}")
    print(f"    <body>           : {'YES' if has_body else 'NO'}")
    print(f"    </html>          : {'YES' if has_html_close else 'NO'}")

    # Show first and last few lines of HTML
    lines = out.strip().split('\n')
    html_lines = [l for l in lines if '<' in l or 'wget' in l.lower() or 'Connecting' in l]
    print(f"\n  --- Key output ({len(html_lines)} HTML lines) ---")
    for line in html_lines[:10]:
        print(f"  | {line[:120]}")
    if len(html_lines) > 20:
        print(f"  | ... ({len(html_lines) - 20} more lines) ...")
    for line in html_lines[-10:]:
        print(f"  | {line[:120]}")
    print("  --- End ---")

    if has_doctype and has_html_close:
        print("\n  [PASS] Full HTML page downloaded successfully!")
    elif has_doctype:
        print("\n  [PARTIAL] HTML started but incomplete (connection may have timed out)")
    else:
        print("\n  [FAIL] No HTML content received")

    s.stop()
    return 0 if has_doctype else 1

if __name__ == '__main__':
    sys.exit(main())
