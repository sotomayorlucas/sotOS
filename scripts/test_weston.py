"""Test script: boot sotOS, run weston, capture output."""
import subprocess, time, os, sys

proc = subprocess.Popen(
    [r'C:\Program Files\qemu\qemu-system-x86_64.exe',
     '-drive', 'format=raw,file=target/sotos.img',
     '-serial', 'stdio', '-display', 'none',
     '-no-reboot', '-m', '4096M'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)

os.set_blocking(proc.stdout.fileno(), False)
buf = b''

# Wait for shell
t0 = time.time()
while time.time() - t0 < 120:
    try:
        d = proc.stdout.read(8192)
        if d:
            buf += d
        if b'LUCAS shell' in buf:
            time.sleep(8)
            break
    except:
        pass
    time.sleep(0.1)

print("=== Shell ready ===", file=sys.stderr)

def send_line(text):
    """Send text char by char with delays to avoid serial overrun."""
    for b in text:
        proc.stdin.write(bytes([b]))
        proc.stdin.flush()
        time.sleep(0.03)  # 30ms per char = ~33 chars/sec
    proc.stdin.write(b'\n')
    proc.stdin.flush()
    time.sleep(0.5)

send_line(b'weston --renderer=pixman')
print("=== Sent weston command ===", file=sys.stderr)

# Collect for 120 seconds (LLVM+mesa loading takes a long time)
t0 = time.time()
while time.time() - t0 < 120:
    try:
        d = proc.stdout.read(8192)
        if d:
            buf += d
    except:
        pass
    time.sleep(0.1)

proc.kill()

# Output results
text = buf.decode('utf-8', errors='replace')
lines = text.split('\n')
for line in lines:
    s = line.strip()
    if s:
        print(s)
