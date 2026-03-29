/*
 * disk_backend.h -- Block device I/O bridge (LKL fusion <-> virtio-blk).
 *
 * Simplified fusion variant: LKL runs inside init, IPC to "blk" service
 * for real sector read/write on virtio-blk.
 */

#ifndef DISK_BACKEND_H
#define DISK_BACKEND_H

#include <stdint.h>
#include <stddef.h>

#define DISK_ENOSYS (-38)

/* Initialise the disk backend (look up virtio-blk "blk" service).
 * Returns 0 on success, negative on error. */
int disk_init(void);

/* Read `count` bytes from disk at byte `offset` into `buf`.
 * Returns bytes read, or negative on error. */
int disk_read(void *buf, uint64_t offset, size_t count);

/* Write `count` bytes from `buf` to disk at byte `offset`.
 * Returns bytes written, or negative on error. */
int disk_write(const void *buf, uint64_t offset, size_t count);

/* Query disk capacity in bytes.  Returns 0 if unknown. */
uint64_t disk_capacity(void);

#endif /* DISK_BACKEND_H */
