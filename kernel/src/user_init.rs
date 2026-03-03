//! Embedded init process — the first userspace code.
//!
//! A minimal assembly blob that prints "INIT\n" via SYS_DEBUG_PRINT (255)
//! then yields in a loop forever. Placed in the `.user_init` section
//! so the kernel can copy it into a user page at boot.

extern "C" {
    static user_init_start: u8;
    static user_init_end: u8;
}

/// Return the init code as a byte slice.
pub fn init_code() -> &'static [u8] {
    unsafe {
        let start = &user_init_start as *const u8;
        let end = &user_init_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

core::arch::global_asm!(
    ".section .user_init, \"ax\"",
    ".global user_init_start",
    ".global user_init_end",
    "user_init_start:",

    // Print 'I'
    "    mov rax, 255",
    "    mov rdi, 0x49",       // 'I'
    "    syscall",

    // Print 'N'
    "    mov rax, 255",
    "    mov rdi, 0x4E",       // 'N'
    "    syscall",

    // Print 'I'
    "    mov rax, 255",
    "    mov rdi, 0x49",       // 'I'
    "    syscall",

    // Print 'T'
    "    mov rax, 255",
    "    mov rdi, 0x54",       // 'T'
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // Yield forever
    "0:",
    "    mov rax, 0",          // SYS_YIELD
    "    syscall",
    "    jmp 0b",

    "user_init_end:",
    ".previous",               // restore previous section
);
