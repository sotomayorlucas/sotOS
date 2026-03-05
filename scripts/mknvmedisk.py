#!/usr/bin/env python3
"""Create a 64 MiB NVMe test disk image with a marker string in sector 0."""

import os
import sys

OUTPUT = os.path.join("target", "nvme-disk.img")
DISK_SIZE = 64 * 1024 * 1024  # 64 MiB
SECTOR_SIZE = 512
MARKER = b"NVME DISK TEST"


def main():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

    with open(OUTPUT, "wb") as f:
        # Write marker at start of sector 0.
        sector0 = bytearray(SECTOR_SIZE)
        sector0[: len(MARKER)] = MARKER
        f.write(sector0)

        # Fill rest with zeros.
        remaining = DISK_SIZE - SECTOR_SIZE
        # Write in 1 MiB chunks for efficiency.
        chunk = b"\x00" * (1024 * 1024)
        while remaining > 0:
            n = min(len(chunk), remaining)
            f.write(chunk[:n])
            remaining -= n

    print(f"Created NVMe disk: {OUTPUT} ({DISK_SIZE // (1024*1024)} MiB)")


if __name__ == "__main__":
    main()
