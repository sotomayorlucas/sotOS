//! Embedded init process — two userspace threads for IPC testing.
//!
//! **Sender** (`.user_init`): prints "INIT\n", sends IPC message with
//! chars ['I','P','C','!'] as msg regs 0–3, prints "OK\n", yields forever.
//!
//! **Receiver** (`.user_recv`): does SYS_RECV on endpoint 0, prints the
//! 4 received characters + newline, yields forever.
//!
//! Register convention for IPC syscalls:
//!   rax = syscall#, rdi = endpoint ID
//!   rsi = tag, rdx/r8/r9/r10/r12/r13/r14/r15 = msg regs 0–7

extern "C" {
    static user_init_start: u8;
    static user_init_end: u8;
    static user_recv_start: u8;
    static user_recv_end: u8;
    static user_kb_start: u8;
    static user_kb_end: u8;
}

/// Return the sender (init) code as a byte slice.
pub fn init_code() -> &'static [u8] {
    unsafe {
        let start = &user_init_start as *const u8;
        let end = &user_init_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the receiver code as a byte slice.
pub fn recv_code() -> &'static [u8] {
    unsafe {
        let start = &user_recv_start as *const u8;
        let end = &user_recv_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Return the keyboard driver code as a byte slice.
pub fn kb_code() -> &'static [u8] {
    unsafe {
        let start = &user_kb_start as *const u8;
        let end = &user_kb_end as *const u8;
        let len = end as usize - start as usize;
        core::slice::from_raw_parts(start, len)
    }
}

// ---------------------------------------------------------------------------
// Sender: prints "INIT\n", sends IPC('I','P','C','!'), prints "OK\n"
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_init, \"ax\"",
    ".global user_init_start",
    ".global user_init_end",
    "user_init_start:",

    // --- Print "INIT\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x49",       // 'I'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4E",       // 'N'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x49",       // 'I'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x54",       // 'T'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- SYS_SEND(1): ep=0, tag=0, regs[0]='I', regs[1]='P', regs[2]='C', regs[3]='!' ---
    "    mov rax, 1",          // SYS_SEND
    "    xor rdi, rdi",        // endpoint 0
    "    xor rsi, rsi",        // tag = 0
    "    mov rdx, 0x49",       // 'I' → msg reg 0
    "    mov r8,  0x50",       // 'P' → msg reg 1
    "    mov r9,  0x43",       // 'C' → msg reg 2
    "    mov r10, 0x21",       // '!' → msg reg 3
    "    xor r12, r12",        // msg reg 4 = 0
    "    xor r13, r13",        // msg reg 5 = 0
    "    xor r14, r14",        // msg reg 6 = 0
    "    xor r15, r15",        // msg reg 7 = 0
    "    syscall",

    // --- Print "OK\n" ---
    "    mov rax, 255",
    "    mov rdi, 0x4F",       // 'O'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x4B",       // 'K'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_init_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Receiver: SYS_RECV(ep=0), print 4 chars from msg regs + newline
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_recv, \"ax\"",
    ".global user_recv_start",
    ".global user_recv_end",
    "user_recv_start:",

    // --- SYS_RECV(2): ep=0 ---
    "    mov rax, 2",          // SYS_RECV
    "    xor rdi, rdi",        // endpoint 0
    "    syscall",

    // On return: rdx='I', r8='P', r9='C', r10='!'
    // Save received regs (rdx, r8, r9, r10) to callee-saved regs
    "    mov r12, rdx",        // 'I'
    "    mov r13, r8",         // 'P'
    "    mov r14, r9",         // 'C'
    "    mov r15, r10",        // '!'

    // Print r12 ('I')
    "    mov rax, 255",
    "    mov rdi, r12",
    "    syscall",

    // Print r13 ('P')
    "    mov rax, 255",
    "    mov rdi, r13",
    "    syscall",

    // Print r14 ('C')
    "    mov rax, 255",
    "    mov rdi, r14",
    "    syscall",

    // Print r15 ('!')
    "    mov rax, 255",
    "    mov rdi, r15",
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    // --- Yield forever ---
    "0:",
    "    mov rax, 0",
    "    syscall",
    "    jmp 0b",

    "user_recv_end:",
    ".previous",
);

// ---------------------------------------------------------------------------
// Keyboard driver: SYS_IRQ_REGISTER(1), loop { SYS_IRQ_ACK(1), read scancode,
//                  print "K:XX\n" where XX is hex scancode }
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .user_kb, \"ax\"",
    ".global user_kb_start",
    ".global user_kb_end",
    "user_kb_start:",

    // --- SYS_IRQ_REGISTER(50): irq=1 (keyboard) ---
    "    mov rax, 50",         // SYS_IRQ_REGISTER
    "    mov rdi, 1",          // IRQ 1 = keyboard
    "    syscall",

    // --- Print 'K' 'B' '\n' to confirm registration ---
    "    mov rax, 255",
    "    mov rdi, 0x4B",       // 'K'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x42",       // 'B'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x0A",       // '\n'
    "    syscall",

    // --- Main loop: wait for IRQ, read scancode, print ---
    "2:",
    "    mov rax, 51",         // SYS_IRQ_ACK
    "    mov rdi, 1",          // IRQ 1
    "    syscall",

    // Read scancode from port 0x60
    "    mov rax, 60",         // SYS_PORT_IN
    "    mov rdi, 0x60",       // keyboard data port
    "    syscall",
    "    mov r12, rax",        // save scancode in callee-saved r12

    // Print "K:"
    "    mov rax, 255",
    "    mov rdi, 0x4B",       // 'K'
    "    syscall",
    "    mov rax, 255",
    "    mov rdi, 0x3A",       // ':'
    "    syscall",

    // Print high hex nibble
    "    mov rdi, r12",
    "    shr rdi, 4",
    "    and rdi, 0x0F",
    "    lea rax, [rip + .Lhex_table]",
    "    movzx rdi, byte ptr [rax + rdi]",
    "    mov rax, 255",
    "    syscall",

    // Print low hex nibble
    "    mov rdi, r12",
    "    and rdi, 0x0F",
    "    lea rax, [rip + .Lhex_table]",
    "    movzx rdi, byte ptr [rax + rdi]",
    "    mov rax, 255",
    "    syscall",

    // Print newline
    "    mov rax, 255",
    "    mov rdi, 0x0A",
    "    syscall",

    "    jmp 2b",

    // Hex lookup table
    ".Lhex_table: .ascii \"0123456789ABCDEF\"",

    "user_kb_end:",
    ".previous",
);
