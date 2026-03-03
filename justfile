# sotOS Build System
# Requires: rust nightly, python3, QEMU

QEMU := if os() == "windows" { "C:/Program Files/qemu/qemu-system-x86_64.exe" } else { "qemu-system-x86_64" }
KERNEL := "target/x86_64-unknown-none/debug/sotos-kernel"
IMAGE := "target/sotos.img"

# Default: build and run
default: run

# Build the kernel
build:
    cargo build --package sotos-kernel

# Build in release mode
release:
    cargo build --package sotos-kernel --release

# Create the bootable disk image (BIOS + Limine)
image: build
    python scripts/mkimage.py --kernel {{KERNEL}} --output {{IMAGE}}

# Build and run in QEMU (serial output to terminal)
run: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M

# Run with QEMU display window (for framebuffer/Limine menu)
run-gui: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -no-reboot \
        -m 256M

# Run with GDB server for debugging (connect with gdb -ex "target remote :1234")
debug: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M \
        -s -S

# Clean build artifacts
clean:
    cargo clean

# Check without building (fast feedback)
check:
    cargo check --package sotos-kernel

# Run clippy
lint:
    cargo clippy --package sotos-kernel -- -W clippy::all
