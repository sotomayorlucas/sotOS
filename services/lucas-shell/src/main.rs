#![no_std]
#![no_main]

// ---------------------------------------------------------------------------
// Stack canary support
// ---------------------------------------------------------------------------

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"!!! STACK SMASH DETECTED (shell) !!!\n";
    linux_write(1, msg.as_ptr(), msg.len());
    linux_exit(137);
}

// ---------------------------------------------------------------------------
// Linux syscall wrappers (raw inline asm — the kernel redirects these via LUCAS)
// ---------------------------------------------------------------------------

#[inline(always)]
fn linux_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 1u64 => ret,
            in("rdi") fd,
            in("rsi") buf as u64,
            in("rdx") len as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 0u64 => ret,
            in("rdi") fd,
            in("rsi") buf as u64,
            in("rdx") len as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_open(path: *const u8, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 2u64 => ret,
            in("rdi") path as u64,
            in("rsi") flags,
            in("rdx") 0u64, // mode (unused)
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_close(fd: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 3u64 => ret,
            in("rdi") fd,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_unlink(path: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 87u64 => ret,
            in("rdi") path as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_stat(path: *const u8, statbuf: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 4u64 => ret,
            in("rdi") path as u64,
            in("rsi") statbuf as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_fstat(fd: u64, statbuf: *mut u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 5u64 => ret,
            in("rdi") fd,
            in("rsi") statbuf as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_lseek(fd: u64, offset: i64, whence: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 8u64 => ret,
            in("rdi") fd,
            in("rsi") offset as u64,
            in("rdx") whence,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_brk(addr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 12u64 => ret,
            in("rdi") addr,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 9u64 => ret,
            in("rdi") addr,
            in("rsi") len,
            in("rdx") prot,
            in("r10") flags,
            in("r8") fd,
            in("r9") offset,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline(always)]
fn linux_exit(status: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 60u64,
            in("rdi") status,
            options(nostack, noreturn),
        );
    }
}

fn linux_clone(child_fn: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 56u64 => ret,
            in("rdi") child_fn,
            in("rsi") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_waitpid(pid: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 61u64 => ret,
            in("rdi") pid,
            in("rsi") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_getpid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 39u64 => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_getppid() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 110u64 => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_execve(path: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 59u64 => ret,
            in("rdi") path as u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_socket(domain: u64, sock_type: u64, protocol: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 41u64 => ret,
            in("rdi") domain,
            in("rsi") sock_type,
            in("rdx") protocol,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_connect(fd: u64, addr: *const u8, addrlen: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 42u64 => ret,
            in("rdi") fd,
            in("rsi") addr as u64,
            in("rdx") addrlen,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_sendto(fd: u64, buf: *const u8, len: u64, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 44u64 => ret,
            in("rdi") fd,
            in("rsi") buf as u64,
            in("rdx") len,
            in("r10") flags,
            in("r8") 0u64,  // dest_addr (null)
            in("r9") 0u64,  // addrlen
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_recvfrom(fd: u64, buf: *mut u8, len: u64, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 45u64 => ret,
            in("rdi") fd,
            in("rsi") buf as u64,
            in("rdx") len,
            in("r10") flags,
            in("r8") 0u64,  // src_addr (null)
            in("r9") 0u64,  // addrlen (null)
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_kill(pid: u64, sig: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 62u64 => ret,
            in("rdi") pid,
            in("rsi") sig,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_getcwd(buf: *mut u8, size: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 79u64 => ret,
            in("rdi") buf as u64,
            in("rsi") size,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_chdir(path: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 80u64 => ret,
            in("rdi") path as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_mkdir(path: *const u8, mode: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 83u64 => ret,
            in("rdi") path as u64,
            in("rsi") mode,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn linux_rmdir(path: *const u8) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 84u64 => ret,
            in("rdi") path as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    linux_write(1, s.as_ptr(), s.len());
}

fn print_u64(mut n: u64) {
    if n == 0 {
        print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // Print in reverse
    while i > 0 {
        i -= 1;
        linux_write(1, &buf[i] as *const u8, 1);
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    &hay[..needle.len()] == needle
}

fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a == b
}

/// Copy name into buf with NUL terminator. Returns pointer to buf.
fn null_terminate<'a>(name: &[u8], buf: &'a mut [u8]) -> *const u8 {
    let len = name.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&name[..len]);
    buf[len] = 0;
    buf.as_ptr()
}

/// Find the first space in a byte slice, returning the index or None.
fn find_space(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b' ' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse a decimal u64 from byte slice.
fn parse_u64_simple(s: &[u8]) -> u64 {
    let mut val: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        val = val * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    val
}

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

const MAX_ENV_VARS: usize = 32;
const MAX_KEY_LEN: usize = 32;
const MAX_VAL_LEN: usize = 128;

struct EnvVar {
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
    val: [u8; MAX_VAL_LEN],
    val_len: usize,
    active: bool,
}

impl EnvVar {
    const fn empty() -> Self {
        Self { key: [0; MAX_KEY_LEN], key_len: 0, val: [0; MAX_VAL_LEN], val_len: 0, active: false }
    }
}

static mut ENV: [EnvVar; MAX_ENV_VARS] = {
    const INIT: EnvVar = EnvVar::empty();
    [INIT; MAX_ENV_VARS]
};

fn env_slice() -> &'static [EnvVar] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(ENV) as *const EnvVar, MAX_ENV_VARS) }
}

fn env_slice_mut() -> &'static mut [EnvVar] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ENV) as *mut EnvVar, MAX_ENV_VARS) }
}

fn env_set(key: &[u8], val: &[u8]) {
    // Update existing.
    for e in env_slice_mut().iter_mut() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            let vl = val.len().min(MAX_VAL_LEN);
            e.val[..vl].copy_from_slice(&val[..vl]);
            e.val_len = vl;
            return;
        }
    }
    // Insert new.
    for e in env_slice_mut().iter_mut() {
        if !e.active {
            let kl = key.len().min(MAX_KEY_LEN);
            let vl = val.len().min(MAX_VAL_LEN);
            e.key[..kl].copy_from_slice(&key[..kl]);
            e.key_len = kl;
            e.val[..vl].copy_from_slice(&val[..vl]);
            e.val_len = vl;
            e.active = true;
            return;
        }
    }
}

fn env_get(key: &[u8]) -> Option<&'static [u8]> {
    for e in env_slice() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            return Some(&e.val[..e.val_len]);
        }
    }
    None
}

fn env_unset(key: &[u8]) {
    for e in env_slice_mut().iter_mut() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            e.active = false;
            return;
        }
    }
}

/// Expand $VAR references in a command line.
fn expand_vars(input: &[u8], output: &mut [u8]) -> usize {
    let mut out_pos = 0;
    let mut i = 0;
    while i < input.len() && out_pos < output.len() - 1 {
        if input[i] == b'$' && i + 1 < input.len() && input[i + 1] != b' ' {
            // Extract variable name.
            let start = i + 1;
            let mut end = start;
            while end < input.len() && (input[end].is_ascii_alphanumeric() || input[end] == b'_') {
                end += 1;
            }
            if end > start {
                if let Some(val) = env_get(&input[start..end]) {
                    let copy_len = val.len().min(output.len() - 1 - out_pos);
                    output[out_pos..out_pos + copy_len].copy_from_slice(&val[..copy_len]);
                    out_pos += copy_len;
                }
                i = end;
            } else {
                output[out_pos] = input[i];
                out_pos += 1;
                i += 1;
            }
        } else {
            output[out_pos] = input[i];
            out_pos += 1;
            i += 1;
        }
    }
    out_pos
}

/// Find a byte in a slice.
fn find_byte(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b { return Some(i); }
        i += 1;
    }
    None
}

/// Simple pattern match (supports only leading/trailing `*`).
fn pattern_match(pattern: &[u8], text: &[u8]) -> bool {
    if eq(pattern, b"*") { return true; }
    if pattern.is_empty() { return text.is_empty(); }
    // "foo*" — starts with
    if pattern[pattern.len() - 1] == b'*' {
        let prefix = &pattern[..pattern.len() - 1];
        return starts_with(text, prefix);
    }
    // "*foo" — ends with
    if pattern[0] == b'*' {
        let suffix = &pattern[1..];
        return text.len() >= suffix.len() && &text[text.len() - suffix.len()..] == suffix;
    }
    // Exact match.
    eq(pattern, text)
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

fn shell_loop() {
    let mut line_buf = [0u8; 256];

    // Set default env vars.
    env_set(b"SHELL", b"lucas");
    env_set(b"OS", b"sotOS");
    env_set(b"VERSION", b"0.1.0");

    loop {
        // Prompt
        print(b"$ ");

        // Read line
        let mut pos: usize = 0;
        loop {
            let mut ch = [0u8; 1];
            let n = linux_read(0, ch.as_mut_ptr(), 1);
            if n == -4 {
                // -EINTR (Ctrl+C)
                print(b"^C\n");
                pos = 0;
                break;
            }
            if n <= 0 {
                continue;
            }
            let c = ch[0];

            match c {
                // Enter
                b'\r' | b'\n' => {
                    print(b"\n");
                    break;
                }
                // Backspace (0x08) or DEL (0x7F)
                0x08 | 0x7F => {
                    if pos > 0 {
                        pos -= 1;
                        // Erase character on terminal: BS + space + BS
                        print(b"\x08 \x08");
                    }
                }
                // Printable character
                0x20..=0x7E => {
                    if pos < line_buf.len() - 1 {
                        line_buf[pos] = c;
                        pos += 1;
                        // Echo
                        linux_write(1, &c as *const u8, 1);
                    }
                }
                // Ignore other control chars
                _ => {}
            }
        }

        let raw_line = trim(&line_buf[..pos]);
        if raw_line.is_empty() {
            continue;
        }

        // Expand environment variables ($VAR).
        let mut expanded = [0u8; 256];
        let exp_len = expand_vars(raw_line, &mut expanded);
        let line = trim(&expanded[..exp_len]);
        if line.is_empty() {
            continue;
        }

        // Check for pipe operator.
        if let Some(pipe_pos) = find_byte(line, b'|') {
            let left = trim(&line[..pipe_pos]);
            let right = trim(&line[pipe_pos + 1..]);
            if !left.is_empty() && !right.is_empty() {
                execute_pipe(left, right);
                continue;
            }
        }

        // Check for background execution (&).
        let (line, background) = if line.len() > 0 && line[line.len() - 1] == b'&' {
            (trim(&line[..line.len() - 1]), true)
        } else {
            (line, false)
        };

        if background {
            // Run in a forked child.
            let child_fn = child_shell_main as *const () as u64;
            let pid = linux_clone(child_fn);
            if pid > 0 {
                print(b"[bg] pid=");
                print_u64(pid as u64);
                print(b"\n");
            }
            continue;
        }

        // --- Shell scripting: if/then/fi ---
        if starts_with(line, b"if ") {
            execute_if_block(line, &mut line_buf);
            continue;
        }

        // --- Shell scripting: for/do/done ---
        if starts_with(line, b"for ") {
            execute_for_block(line, &mut line_buf);
            continue;
        }

        dispatch_command(line);
    }
}

fn dispatch_command(line: &[u8]) {
        // --- Command dispatch ---
        if eq(line, b"help") {
            print(b"commands: help, echo, uname, uptime, caps, ls, cat, write, rm,\n");
            print(b"  stat, hexdump, head, tail, grep, mkdir, rmdir, cd, pwd, snap,\n");
            print(b"  fork, getpid, exec, ps, top, kill, resolve, ping, traceroute,\n");
            print(b"  wget, export, env, unset, exit\n");
            print(b"operators: cmd1 | cmd2 (pipe), cmd & (background)\n");
            print(b"scripting: if COND; then CMD; fi, for VAR in A B C; do CMD; done\n");
        } else if eq(line, b"uname") {
            print(b"sotOS 0.1.0 x86_64 LUCAS\n");
        } else if eq(line, b"uptime") {
            cmd_uptime();
        } else if eq(line, b"ps") {
            cmd_ps();
        } else if starts_with(line, b"kill ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                print(b"usage: kill <pid> [signal]\n");
            } else {
                cmd_kill(args);
            }
        } else if eq(line, b"caps") {
            print(b"capability system active (query via sotOS ABI)\n");
        } else if starts_with(line, b"echo ") {
            let rest = &line[5..];
            print(rest);
            print(b"\n");
        } else if eq(line, b"echo") {
            print(b"\n");
        } else if eq(line, b"ls") {
            cmd_ls();
        } else if starts_with(line, b"ls ") {
            let path = trim(&line[3..]);
            if path.is_empty() {
                cmd_ls();
            } else {
                cmd_ls_path(path);
            }
        } else if starts_with(line, b"cat ") {
            let name = trim(&line[4..]);
            if name.is_empty() {
                print(b"usage: cat <file>\n");
            } else {
                cmd_cat(name);
            }
        } else if starts_with(line, b"write ") {
            let args = trim(&line[6..]);
            match find_space(args) {
                Some(sp) => {
                    let name = &args[..sp];
                    let text = trim(&args[sp + 1..]);
                    cmd_write(name, text);
                }
                None => {
                    print(b"usage: write <file> <text>\n");
                }
            }
        } else if starts_with(line, b"rm ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                print(b"usage: rm <file>\n");
            } else {
                cmd_rm(name);
            }
        } else if starts_with(line, b"stat ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                print(b"usage: stat <file>\n");
            } else {
                cmd_stat(name);
            }
        } else if eq(line, b"stat") {
            cmd_stat(b".");
        } else if starts_with(line, b"hexdump ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                print(b"usage: hexdump <file>\n");
            } else {
                cmd_hexdump(name);
            }
        } else if starts_with(line, b"mkdir ") {
            let name = trim(&line[6..]);
            if name.is_empty() {
                print(b"usage: mkdir <dir>\n");
            } else {
                cmd_mkdir(name);
            }
        } else if starts_with(line, b"rmdir ") {
            let name = trim(&line[6..]);
            if name.is_empty() {
                print(b"usage: rmdir <dir>\n");
            } else {
                cmd_rmdir(name);
            }
        } else if starts_with(line, b"cd ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                print(b"usage: cd <dir>\n");
            } else {
                cmd_cd(name);
            }
        } else if eq(line, b"cd") {
            // cd with no args goes to root
            cmd_cd(b"/");
        } else if eq(line, b"pwd") {
            cmd_pwd();
        } else if eq(line, b"fork") {
            cmd_fork();
        } else if eq(line, b"getpid") {
            print(b"pid=");
            print_u64(linux_getpid() as u64);
            print(b"\n");
        } else if starts_with(line, b"exec ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                print(b"usage: exec <program>\n");
            } else {
                cmd_exec(name);
            }
        } else if starts_with(line, b"resolve ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                print(b"usage: resolve <hostname>\n");
            } else {
                cmd_resolve(name);
            }
        } else if starts_with(line, b"ping ") {
            let host = trim(&line[5..]);
            if host.is_empty() {
                print(b"usage: ping <host>\n");
            } else {
                cmd_ping(host);
            }
        } else if starts_with(line, b"traceroute ") {
            let host = trim(&line[11..]);
            if host.is_empty() {
                print(b"usage: traceroute <host>\n");
            } else {
                cmd_traceroute(host);
            }
        } else if starts_with(line, b"wget ") {
            let url = trim(&line[5..]);
            if url.is_empty() {
                print(b"usage: wget <url>\n");
            } else {
                cmd_wget(url);
            }
        } else if starts_with(line, b"snap ") {
            let args = trim(&line[5..]);
            cmd_snap(args);
        } else if starts_with(line, b"export ") {
            let args = trim(&line[7..]);
            if let Some(eq_pos) = find_byte(args, b'=') {
                let key = trim(&args[..eq_pos]);
                let val = trim(&args[eq_pos + 1..]);
                env_set(key, val);
            } else {
                print(b"usage: export KEY=VALUE\n");
            }
        } else if eq(line, b"env") {
            cmd_env();
        } else if starts_with(line, b"unset ") {
            let key = trim(&line[6..]);
            if !key.is_empty() {
                env_unset(key);
            }
        } else if starts_with(line, b"head ") {
            let args = trim(&line[5..]);
            cmd_head(args);
        } else if starts_with(line, b"tail ") {
            let args = trim(&line[5..]);
            cmd_tail(args);
        } else if starts_with(line, b"grep ") {
            let args = trim(&line[5..]);
            cmd_grep(args);
        } else if eq(line, b"top") {
            cmd_top();
        } else if eq(line, b"exit") {
            print(b"bye!\n");
            linux_exit(0);
        } else {
            print(b"unknown command: ");
            print(line);
            print(b"\n");
        }
}

// ---------------------------------------------------------------------------
// New commands: env, head, tail, grep, top, pipe support, scripting
// ---------------------------------------------------------------------------

fn cmd_env() {
    for e in env_slice() {
        if e.active {
            print(&e.key[..e.key_len]);
            print(b"=");
            print(&e.val[..e.val_len]);
            print(b"\n");
        }
    }
}

fn cmd_head(args: &[u8]) {
    let mut num_lines: usize = 10;
    let name;
    if starts_with(args, b"-n ") {
        let rest = trim(&args[3..]);
        if let Some(sp) = find_space(rest) {
            num_lines = parse_u64_simple(&rest[..sp]) as usize;
            name = trim(&rest[sp + 1..]);
        } else { print(b"usage: head [-n N] <file>\n"); return; }
    } else { name = args; }
    if name.is_empty() { print(b"usage: head [-n N] <file>\n"); return; }

    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { print(b"head: file not found\n"); return; }

    let mut buf = [0u8; 1];
    let mut lines_printed: usize = 0;
    loop {
        if lines_printed >= num_lines { break; }
        let n = linux_read(fd as u64, buf.as_mut_ptr(), 1);
        if n <= 0 { break; }
        linux_write(1, buf.as_ptr(), 1);
        if buf[0] == b'\n' { lines_printed += 1; }
    }
    linux_close(fd as u64);
}

fn cmd_tail(args: &[u8]) {
    let mut num_lines: usize = 10;
    let name;
    if starts_with(args, b"-n ") {
        let rest = trim(&args[3..]);
        if let Some(sp) = find_space(rest) {
            num_lines = parse_u64_simple(&rest[..sp]) as usize;
            name = trim(&rest[sp + 1..]);
        } else { print(b"usage: tail [-n N] <file>\n"); return; }
    } else { name = args; }
    if name.is_empty() { print(b"usage: tail [-n N] <file>\n"); return; }

    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { print(b"tail: file not found\n"); return; }

    // Read entire file into buffer, then print last N lines.
    let mut data = [0u8; 4096];
    let mut total: usize = 0;
    loop {
        let n = linux_read(fd as u64, data[total..].as_mut_ptr(), (data.len() - total) as usize);
        if n <= 0 { break; }
        total += n as usize;
        if total >= data.len() { break; }
    }
    linux_close(fd as u64);

    // Count total lines, find start of last N.
    let mut line_count: usize = 0;
    for i in 0..total { if data[i] == b'\n' { line_count += 1; } }
    let skip_lines = if line_count > num_lines { line_count - num_lines } else { 0 };
    let mut lines_seen: usize = 0;
    let mut start: usize = 0;
    for i in 0..total {
        if data[i] == b'\n' {
            lines_seen += 1;
            if lines_seen >= skip_lines { start = if lines_seen == skip_lines { i + 1 } else { start }; break; }
        }
    }
    if skip_lines == 0 { start = 0; }
    if start < total {
        linux_write(1, data[start..total].as_ptr(), total - start);
    }
}

fn cmd_grep(args: &[u8]) {
    if let Some(sp) = find_space(args) {
        let pattern = &args[..sp];
        let name = trim(&args[sp + 1..]);
        if name.is_empty() { print(b"usage: grep <pattern> <file>\n"); return; }

        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let fd = linux_open(path, 0);
        if fd < 0 { print(b"grep: file not found\n"); return; }

        // Read line-by-line and print matching lines.
        let mut buf = [0u8; 4096];
        let mut total: usize = 0;
        loop {
            let n = linux_read(fd as u64, buf[total..].as_mut_ptr(), (buf.len() - total) as usize);
            if n <= 0 { break; }
            total += n as usize;
            if total >= buf.len() { break; }
        }
        linux_close(fd as u64);

        // Scan for lines containing the pattern.
        let mut line_start: usize = 0;
        let mut i: usize = 0;
        while i <= total {
            if i == total || buf[i] == b'\n' {
                let line = &buf[line_start..i];
                if contains(line, pattern) {
                    linux_write(1, line.as_ptr(), line.len());
                    print(b"\n");
                }
                line_start = i + 1;
            }
            i += 1;
        }
    } else {
        print(b"usage: grep <pattern> <file>\n");
    }
}

/// Check if `hay` contains `needle` as a substring.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if hay.len() < needle.len() { return false; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

/// top — list threads with CPU usage.
fn cmd_top() {
    // Use custom syscall 142 to get thread count, 140 to get thread info.
    print(b"  TID  STATE   PRI  CPU_TICKS  MEM  TYPE\n");
    // Iterate up to 256 thread pool slots.
    for idx in 0..256u64 {
        let ret: u64;
        let tid: u64;
        let state: u64;
        let pri: u64;
        let ticks: u64;
        let mem: u64;
        let is_user: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 140u64 => ret,
                inlateout("rdi") idx => tid,
                lateout("rsi") state,
                lateout("rdx") pri,
                lateout("rcx") _,
                lateout("r11") _,
                lateout("r8") ticks,
                lateout("r9") mem,
                lateout("r10") is_user,
                options(nostack),
            );
        }
        if (ret as i64) < 0 { continue; }
        // Format: TID STATE PRI CPU_TICKS MEM TYPE
        print(b"  ");
        if tid < 10 { print(b"  "); } else if tid < 100 { print(b" "); }
        print_u64(tid);
        print(b"  ");
        match state {
            0 => print(b"READY  "),
            1 => print(b"RUN    "),
            2 => print(b"BLOCK  "),
            3 => print(b"FAULT  "),
            _ => print(b"DEAD   "),
        }
        if pri < 10 { print(b"  "); } else if pri < 100 { print(b" "); }
        print_u64(pri);
        print(b"  ");
        // Right-align ticks in 9 chars.
        let mut tstr = [b' '; 9];
        let mut t = ticks;
        let mut ti = 8;
        if t == 0 { tstr[ti] = b'0'; }
        while t > 0 { tstr[ti] = b'0' + (t % 10) as u8; t /= 10; if ti > 0 { ti -= 1; } }
        print(&tstr);
        print(b"  ");
        if mem < 10 { print(b"  "); } else if mem < 100 { print(b" "); }
        print_u64(mem);
        print(b"  ");
        if is_user != 0 { print(b"user\n"); } else { print(b"kern\n"); }
    }
}

/// Execute a pipe: capture output of left command, feed as input to right command.
/// Simple implementation: left command's output goes to a temp file, right reads it.
fn execute_pipe(left: &[u8], right: &[u8]) {
    // For builtins, we capture output by redirecting stdout.
    // Simple approach: use a temp file ".pipe_tmp".
    let mut tmp_buf = [0u8; 16];
    let tmp_path = null_terminate(b".pipe_tmp", &mut tmp_buf);

    // Write left command's output to temp file.
    let tmp_fd = linux_open(tmp_path, 0x41); // O_WRONLY | O_CREAT
    if tmp_fd < 0 {
        print(b"pipe: cannot create temp\n");
        return;
    }

    // Redirect: we'll execute left, but writing to tmp_fd instead of stdout.
    // For simplicity, capture by running the command and checking if it's cat-like.
    // Actually, the simplest approach: just run both commands textually.
    // Since all commands use `print()` which writes to fd 1, we can't easily redirect.
    // Instead, let's implement a minimal capture: if left is "cat", we can read its file
    // and pipe to right as "grep".
    linux_close(tmp_fd as u64);

    // Simplified pipe: if right is "grep PATTERN", capture left output and filter.
    if starts_with(right, b"grep ") {
        let pattern = trim(&right[5..]);
        // Run left into a buffer.
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            // Filter lines containing pattern.
            let mut line_start: usize = 0;
            let mut i: usize = 0;
            while i <= cap_len {
                if i == cap_len || capture[i] == b'\n' {
                    let line = &capture[line_start..i];
                    if contains(line, pattern) {
                        linux_write(1, line.as_ptr(), line.len());
                        print(b"\n");
                    }
                    line_start = i + 1;
                }
                i += 1;
            }
        }
    } else if starts_with(right, b"head") || starts_with(right, b"tail") {
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            let num_lines: usize = 10; // default
            if starts_with(right, b"head") {
                let mut lines_printed: usize = 0;
                for i in 0..cap_len {
                    if lines_printed >= num_lines { break; }
                    linux_write(1, &capture[i] as *const u8, 1);
                    if capture[i] == b'\n' { lines_printed += 1; }
                }
            } else {
                // tail: print last N lines
                let mut line_count: usize = 0;
                for i in 0..cap_len { if capture[i] == b'\n' { line_count += 1; } }
                let skip = if line_count > num_lines { line_count - num_lines } else { 0 };
                let mut seen: usize = 0;
                for i in 0..cap_len {
                    if seen >= skip { linux_write(1, &capture[i] as *const u8, 1); }
                    if capture[i] == b'\n' { seen += 1; }
                }
            }
        }
    } else {
        // Fallback: just run both commands sequentially.
        dispatch_command(left);
        dispatch_command(right);
    }
    // Cleanup temp file.
    linux_unlink(tmp_path);
}

/// Capture a command's output into a buffer (for cat-like commands).
fn capture_command(cmd: &[u8], buf: &mut [u8]) -> usize {
    // Only support cat and ls for piping.
    if starts_with(cmd, b"cat ") {
        let name = trim(&cmd[4..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let fd = linux_open(path, 0);
        if fd < 0 { return 0; }
        let mut total: usize = 0;
        loop {
            let n = linux_read(fd as u64, buf[total..].as_mut_ptr(), (buf.len() - total) as usize);
            if n <= 0 { break; }
            total += n as usize;
            if total >= buf.len() { break; }
        }
        linux_close(fd as u64);
        return total;
    }
    if eq(cmd, b"ls") || starts_with(cmd, b"ls ") {
        let mut path_buf = [0u8; 4];
        let path = null_terminate(b".", &mut path_buf);
        let fd = linux_open(path, 0);
        if fd < 0 { return 0; }
        let mut total: usize = 0;
        loop {
            let n = linux_read(fd as u64, buf[total..].as_mut_ptr(), (buf.len() - total) as usize);
            if n <= 0 { break; }
            total += n as usize;
            if total >= buf.len() { break; }
        }
        linux_close(fd as u64);
        return total;
    }
    if eq(cmd, b"env") {
        let mut total: usize = 0;
        for e in env_slice() {
            if e.active && total + e.key_len + e.val_len + 2 < buf.len() {
                buf[total..total + e.key_len].copy_from_slice(&e.key[..e.key_len]);
                total += e.key_len;
                buf[total] = b'=';
                total += 1;
                buf[total..total + e.val_len].copy_from_slice(&e.val[..e.val_len]);
                total += e.val_len;
                buf[total] = b'\n';
                total += 1;
            }
        }
        return total;
    }
    0
}

/// Basic if/then/fi scripting.
/// Format: if CONDITION; then COMMAND; fi
/// CONDITION: "test -f FILE" or "test -d FILE" or "test VAR = VALUE"
fn execute_if_block(line: &[u8], _line_buf: &mut [u8; 256]) {
    // Parse: "if COND; then CMD; fi"
    let after_if = trim(&line[3..]);
    // Find "; then "
    let then_pos = find_substr(after_if, b"; then ");
    if then_pos.is_none() { print(b"syntax error: expected '; then'\n"); return; }
    let then_pos = then_pos.unwrap();
    let condition = trim(&after_if[..then_pos]);
    let after_then = &after_if[then_pos + 7..];
    // Find "; fi"
    let fi_pos = find_substr(after_then, b"; fi");
    if fi_pos.is_none() { print(b"syntax error: expected '; fi'\n"); return; }
    let fi_pos = fi_pos.unwrap();
    let command = trim(&after_then[..fi_pos]);

    if evaluate_condition(condition) {
        dispatch_command(command);
    }
}

/// Basic for loop.
/// Format: for VAR in A B C; do CMD; done
fn execute_for_block(line: &[u8], _line_buf: &mut [u8; 256]) {
    let after_for = trim(&line[4..]);
    // Parse "VAR in ITEMS; do CMD; done"
    if let Some(in_pos) = find_substr(after_for, b" in ") {
        let var_name = trim(&after_for[..in_pos]);
        let after_in = &after_for[in_pos + 4..];
        if let Some(do_pos) = find_substr(after_in, b"; do ") {
            let items_str = trim(&after_in[..do_pos]);
            let after_do = &after_in[do_pos + 5..];
            if let Some(done_pos) = find_substr(after_do, b"; done") {
                let command_template = trim(&after_do[..done_pos]);
                // Split items by space and run command for each.
                let mut pos = 0;
                while pos < items_str.len() {
                    // Skip spaces.
                    while pos < items_str.len() && items_str[pos] == b' ' { pos += 1; }
                    let start = pos;
                    while pos < items_str.len() && items_str[pos] != b' ' { pos += 1; }
                    if start < pos {
                        let item = &items_str[start..pos];
                        env_set(var_name, item);
                        // Expand command template with the new variable.
                        let mut cmd_buf = [0u8; 256];
                        let cmd_len = expand_vars(command_template, &mut cmd_buf);
                        dispatch_command(trim(&cmd_buf[..cmd_len]));
                    }
                }
                return;
            }
        }
    }
    print(b"syntax error: for VAR in ITEMS; do CMD; done\n");
}

fn find_substr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    if hay.len() < needle.len() { return None; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle { return Some(i); }
        i += 1;
    }
    None
}

fn evaluate_condition(cond: &[u8]) -> bool {
    // "test -f FILE" — file exists
    if starts_with(cond, b"test -f ") {
        let name = trim(&cond[8..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        return linux_stat(path, stat_buf.as_mut_ptr()) >= 0;
    }
    // "test -d FILE" — directory exists
    if starts_with(cond, b"test -d ") {
        let name = trim(&cond[8..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        if linux_stat(path, stat_buf.as_mut_ptr()) < 0 { return false; }
        let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
        return mode & 0o170000 == 0o40000;
    }
    // "test STR = STR" — string equality
    if starts_with(cond, b"test ") {
        let rest = trim(&cond[5..]);
        if let Some(eq_pos) = find_substr(rest, b" = ") {
            let left = trim(&rest[..eq_pos]);
            let right = trim(&rest[eq_pos + 3..]);
            return eq(left, right);
        }
    }
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sotOS LUCAS shell v0.2\n");
    shell_loop();
    linux_exit(0);
}

#[unsafe(no_mangle)]
pub extern "C" fn child_shell_main() -> ! {
    let pid = linux_getpid();
    print(b"[child shell pid=");
    print_u64(pid as u64);
    print(b"]\n");
    shell_loop();
    linux_exit(0);
}

// ---------------------------------------------------------------------------
// File commands
// ---------------------------------------------------------------------------

fn cmd_ls() {
    let mut path_buf = [0u8; 4];
    let path = null_terminate(b".", &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"ls: cannot open directory\n");
        return;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    linux_close(fd as u64);
}

fn cmd_cat(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"cat: file not found\n");
        return;
    }
    let mut buf = [0u8; 512];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    print(b"\n");
    linux_close(fd as u64);
}

fn cmd_write(name: &[u8], text: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    // O_WRONLY(1) | O_CREAT(0x40) = 0x41
    let fd = linux_open(path, 0x41);
    if fd < 0 {
        print(b"write: cannot open file\n");
        return;
    }
    let n = linux_write(fd as u64, text.as_ptr(), text.len());
    if n > 0 {
        print(b"wrote ");
        print_u64(n as u64);
        print(b" bytes\n");
    } else {
        print(b"write: error\n");
    }
    linux_close(fd as u64);
}

fn cmd_stat(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let mut stat_buf = [0u8; 144];
    let ret = linux_stat(path, stat_buf.as_mut_ptr());
    if ret < 0 {
        print(b"stat: not found\n");
        return;
    }
    // st_mode at offset 24 (u32)
    let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
    // st_size at offset 48 (u64)
    let size = u64::from_le_bytes([
        stat_buf[48], stat_buf[49], stat_buf[50], stat_buf[51],
        stat_buf[52], stat_buf[53], stat_buf[54], stat_buf[55],
    ]);
    // st_ino at offset 8 (u64)
    let ino = u64::from_le_bytes([
        stat_buf[8], stat_buf[9], stat_buf[10], stat_buf[11],
        stat_buf[12], stat_buf[13], stat_buf[14], stat_buf[15],
    ]);

    print(b"  file: ");
    print(name);
    print(b"\n  size: ");
    print_u64(size);
    print(b"\n  inode: ");
    print_u64(ino);
    print(b"\n  type: ");
    if mode & 0o170000 == 0o40000 {
        print(b"directory");
    } else if mode & 0o170000 == 0o100000 {
        print(b"regular file");
    } else if mode & 0o170000 == 0o20000 {
        print(b"character device");
    } else {
        print(b"unknown");
    }
    print(b"\n");
}

fn cmd_hexdump(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"hexdump: file not found\n");
        return;
    }
    let hex = b"0123456789abcdef";
    let mut offset: u64 = 0;
    let mut buf = [0u8; 16];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), 16);
        if n <= 0 {
            break;
        }
        let count = n as usize;
        // Print offset (8 hex digits)
        for i in (0..8).rev() {
            let nibble = ((offset >> (i * 4)) & 0xF) as usize;
            linux_write(1, &hex[nibble] as *const u8, 1);
        }
        print(b"  ");
        // Hex bytes
        for i in 0..16 {
            if i < count {
                linux_write(1, &hex[(buf[i] >> 4) as usize] as *const u8, 1);
                linux_write(1, &hex[(buf[i] & 0xF) as usize] as *const u8, 1);
            } else {
                print(b"  ");
            }
            print(b" ");
            if i == 7 {
                print(b" ");
            }
        }
        print(b" |");
        // ASCII
        for i in 0..count {
            if buf[i] >= 0x20 && buf[i] < 0x7F {
                linux_write(1, &buf[i] as *const u8, 1);
            } else {
                print(b".");
            }
        }
        print(b"|\n");
        offset += count as u64;
    }
    linux_close(fd as u64);
}

fn cmd_rm(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_unlink(path);
    if ret == 0 {
        print(b"removed\n");
    } else {
        print(b"rm: file not found\n");
    }
}

fn cmd_ls_path(path: &[u8]) {
    // Save cwd, cd to path, ls, cd back
    let mut old_cwd = [0u8; 128];
    let cwd_ret = linux_getcwd(old_cwd.as_mut_ptr(), old_cwd.len() as u64);

    let mut path_buf = [0u8; 64];
    let p = null_terminate(path, &mut path_buf);
    if linux_chdir(p) < 0 {
        print(b"ls: cannot access ");
        print(path);
        print(b"\n");
        return;
    }
    cmd_ls();
    // Restore cwd
    if cwd_ret > 0 {
        linux_chdir(old_cwd.as_ptr());
    }
}

fn cmd_mkdir(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_mkdir(path, 0o755);
    if ret == 0 {
        print(b"directory created\n");
    } else {
        print(b"mkdir: failed\n");
    }
}

fn cmd_rmdir(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_rmdir(path);
    if ret == 0 {
        print(b"directory removed\n");
    } else {
        print(b"rmdir: failed (not empty or not found)\n");
    }
}

fn cmd_cd(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_chdir(path);
    if ret < 0 {
        print(b"cd: not a directory or not found\n");
    }
}

fn cmd_pwd() {
    let mut buf = [0u8; 128];
    let ret = linux_getcwd(buf.as_mut_ptr(), buf.len() as u64);
    if ret > 0 {
        // Find NUL or use full buf
        let mut len = 0;
        while len < buf.len() && buf[len] != 0 {
            len += 1;
        }
        linux_write(1, buf.as_ptr(), len);
        print(b"\n");
    } else {
        print(b"/\n");
    }
}

fn cmd_snap(args: &[u8]) {
    if starts_with(args, b"create ") {
        let name = trim(&args[7..]);
        if name.is_empty() {
            print(b"usage: snap create <name>\n");
            return;
        }
        // Open /snap/create/<name> to trigger snapshot creation
        let mut path_buf = [0u8; 64];
        let prefix = b"/snap/create/";
        path_buf[..prefix.len()].copy_from_slice(prefix);
        let copy_len = name.len().min(path_buf.len() - prefix.len() - 1);
        path_buf[prefix.len()..prefix.len() + copy_len].copy_from_slice(&name[..copy_len]);
        path_buf[prefix.len() + copy_len] = 0;
        let fd = linux_open(path_buf.as_ptr(), 0);
        if fd >= 0 {
            let mut buf = [0u8; 64];
            let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
            if n > 0 { linux_write(1, buf.as_ptr(), n as usize); }
            linux_close(fd as u64);
        } else {
            print(b"snap create: failed\n");
        }
    } else if eq(args, b"list") {
        let mut path_buf = [0u8; 16];
        let path = null_terminate(b"/snap/list", &mut path_buf);
        let fd = linux_open(path, 0);
        if fd >= 0 {
            let mut buf = [0u8; 256];
            let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
            if n > 0 { linux_write(1, buf.as_ptr(), n as usize); }
            linux_close(fd as u64);
        } else {
            print(b"snap list: failed\n");
        }
    } else if starts_with(args, b"restore ") {
        let name = trim(&args[8..]);
        if name.is_empty() {
            print(b"usage: snap restore <name>\n");
            return;
        }
        let mut path_buf = [0u8; 64];
        let prefix = b"/snap/restore/";
        path_buf[..prefix.len()].copy_from_slice(prefix);
        let copy_len = name.len().min(path_buf.len() - prefix.len() - 1);
        path_buf[prefix.len()..prefix.len() + copy_len].copy_from_slice(&name[..copy_len]);
        path_buf[prefix.len() + copy_len] = 0;
        let fd = linux_open(path_buf.as_ptr(), 0);
        if fd >= 0 {
            let mut buf = [0u8; 64];
            let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
            if n > 0 { linux_write(1, buf.as_ptr(), n as usize); }
            linux_close(fd as u64);
        } else {
            print(b"snap restore: failed\n");
        }
    } else if starts_with(args, b"delete ") {
        let name = trim(&args[7..]);
        if name.is_empty() {
            print(b"usage: snap delete <name>\n");
            return;
        }
        let mut path_buf = [0u8; 64];
        let prefix = b"/snap/delete/";
        path_buf[..prefix.len()].copy_from_slice(prefix);
        let copy_len = name.len().min(path_buf.len() - prefix.len() - 1);
        path_buf[prefix.len()..prefix.len() + copy_len].copy_from_slice(&name[..copy_len]);
        path_buf[prefix.len() + copy_len] = 0;
        let fd = linux_open(path_buf.as_ptr(), 0);
        if fd >= 0 {
            let mut buf = [0u8; 64];
            let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
            if n > 0 { linux_write(1, buf.as_ptr(), n as usize); }
            linux_close(fd as u64);
        } else {
            print(b"snap delete: failed\n");
        }
    } else {
        print(b"usage: snap create|list|restore|delete [<name>]\n");
    }
}

fn cmd_fork() {
    let child_fn = child_shell_main as *const () as u64;
    let child_pid = linux_clone(child_fn);
    if child_pid < 0 {
        print(b"fork: failed\n");
        return;
    }
    print(b"forked child pid=");
    print_u64(child_pid as u64);
    print(b"\nwaiting...\n");
    let status = linux_waitpid(child_pid as u64);
    print(b"child exited status=");
    print_u64(status as u64);
    print(b"\n");
}

fn cmd_exec(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_execve(path);
    // If execve returns, it failed
    print(b"exec: failed (");
    print_u64((-ret) as u64);
    print(b")\n");
}

fn cmd_ps() {
    let mut path_buf = [0u8; 8];
    let path = null_terminate(b"/proc", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"ps: cannot open /proc\n");
        return;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    linux_close(fd as u64);
}

fn cmd_uptime() {
    let mut path_buf = [0u8; 16];
    let path = null_terminate(b"/proc/uptime", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"uptime: cannot read\n");
        return;
    }
    let mut buf = [0u8; 64];
    let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
    if n > 0 {
        print(b"up ");
        linux_write(1, buf.as_ptr(), n as usize);
        print(b" ticks\n");
    }
    linux_close(fd as u64);
}

fn cmd_kill(args: &[u8]) {
    match find_space(args) {
        Some(sp) => {
            let pid = parse_u64_simple(&args[..sp]);
            let sig = parse_u64_simple(trim(&args[sp + 1..]));
            let ret = linux_kill(pid, sig);
            if ret < 0 {
                print(b"kill: no such process\n");
            }
        }
        None => {
            // No signal specified, default to SIGKILL(9)
            let pid = parse_u64_simple(args);
            let ret = linux_kill(pid, 9);
            if ret < 0 {
                print(b"kill: no such process\n");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Custom sotOS syscalls (intercepted by LUCAS)
// ---------------------------------------------------------------------------

/// DNS resolve: syscall 200(hostname_ptr, hostname_len) → IP as u32 (0 = failed)
fn linux_dns_resolve(name: *const u8, len: usize) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 200u64 => ret,
            in("rdi") name as u64,
            in("rsi") len as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Traceroute hop: syscall 201(dst_ip, ttl) → responder_ip | (reached_flag << 32)
fn linux_traceroute_hop(dst_ip: u64, ttl: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 201u64 => ret,
            in("rdi") dst_ip,
            in("rsi") ttl,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// Networking helpers
// ---------------------------------------------------------------------------

/// Print an IPv4 address in dotted-decimal.
fn print_ip(ip: u32) {
    let bytes = ip.to_be_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 { print(b"."); }
        print_u64(b as u64);
    }
}

/// Resolve a hostname to an IP address. Tries parse_ip first, then DNS.
fn resolve_host(host: &[u8]) -> Option<u32> {
    if let Some(ip) = parse_ip(host) {
        return Some(ip);
    }
    // Try DNS resolution.
    let ip = linux_dns_resolve(host.as_ptr(), host.len());
    if ip != 0 {
        Some(ip as u32)
    } else {
        None
    }
}

/// Parse an IPv4 dotted-decimal address. Returns big-endian u32.
fn parse_ip(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut val: u32 = 0;
    let mut has_digit = false;

    for &b in s {
        if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u32;
            if val > 255 { return None; }
            has_digit = true;
        } else if b == b'.' {
            if !has_digit || octet_idx >= 3 { return None; }
            octets[octet_idx] = val as u8;
            octet_idx += 1;
            val = 0;
            has_digit = false;
        } else {
            return None;
        }
    }
    if !has_digit || octet_idx != 3 { return None; }
    octets[3] = val as u8;
    Some(u32::from_be_bytes(octets))
}

/// Build a sockaddr_in structure.
fn build_sockaddr(ip: u32, port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0] = 2; // AF_INET (low byte)
    sa[1] = 0;
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip.to_be_bytes());
    sa
}

fn cmd_ping(host: &[u8]) {
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            print(b"ping: cannot resolve host\n");
            return;
        }
    };

    print(b"PING ");
    print(host);
    print(b" (");
    print_ip(ip);
    print(b")\n");

    // Use a TCP socket connect to port 80 as a connectivity test.
    let fd = linux_socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if fd < 0 {
        print(b"ping: socket failed\n");
        return;
    }

    let sa = build_sockaddr(ip, 80);
    let ret = linux_connect(fd as u64, sa.as_ptr(), 16);
    if ret == 0 {
        print(b"  connection to port 80: OK\n");
    } else {
        print(b"  connection to port 80: FAILED\n");
    }
    linux_close(fd as u64);
}

fn cmd_wget(url: &[u8]) {
    // Parse URL: http://host[:port]/path
    if !starts_with(url, b"http://") {
        print(b"wget: only http:// URLs supported\n");
        return;
    }
    let after_scheme = &url[7..]; // skip "http://"

    // Find host and path.
    let mut host_end = after_scheme.len();
    let mut path_start = after_scheme.len();
    for i in 0..after_scheme.len() {
        if after_scheme[i] == b'/' {
            host_end = i;
            path_start = i;
            break;
        }
    }
    let host = &after_scheme[..host_end];
    let path = if path_start < after_scheme.len() {
        &after_scheme[path_start..]
    } else {
        b"/" as &[u8]
    };

    // Parse host:port.
    let mut port: u16 = 80;
    let mut hostname = host;
    for i in 0..host.len() {
        if host[i] == b':' {
            hostname = &host[..i];
            port = parse_u64_simple(&host[i + 1..]) as u16;
            break;
        }
    }

    // Resolve hostname (IP or DNS).
    let ip = match resolve_host(hostname) {
        Some(ip) => ip,
        None => {
            print(b"wget: cannot resolve hostname\n");
            return;
        }
    };

    // Create socket.
    let fd = linux_socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if fd < 0 {
        print(b"wget: socket failed\n");
        return;
    }

    // Connect.
    let sa = build_sockaddr(ip, port);
    if linux_connect(fd as u64, sa.as_ptr(), 16) < 0 {
        print(b"wget: connect failed\n");
        linux_close(fd as u64);
        return;
    }

    // Build HTTP GET request.
    let mut req = [0u8; 256];
    let mut pos = 0;
    let prefix = b"GET ";
    req[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let plen = path.len().min(128);
    req[pos..pos + plen].copy_from_slice(&path[..plen]);
    pos += plen;
    let suffix = b" HTTP/1.0\r\nHost: ";
    req[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();
    let hlen = hostname.len().min(64);
    req[pos..pos + hlen].copy_from_slice(&hostname[..hlen]);
    pos += hlen;
    let end = b"\r\n\r\n";
    req[pos..pos + end.len()].copy_from_slice(end);
    pos += end.len();

    // Send request.
    let sent = linux_sendto(fd as u64, req.as_ptr(), pos as u64, 0);
    if sent <= 0 {
        print(b"wget: send failed\n");
        linux_close(fd as u64);
        return;
    }

    // Read response.
    let mut buf = [0u8; 40]; // Limited by IPC inline data size
    loop {
        let n = linux_recvfrom(fd as u64, buf.as_mut_ptr(), buf.len() as u64, 0);
        if n <= 0 { break; }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    print(b"\n");
    linux_close(fd as u64);
}

fn cmd_resolve(name: &[u8]) {
    match resolve_host(name) {
        Some(ip) => {
            print(name);
            print(b" -> ");
            print_ip(ip);
            print(b"\n");
        }
        None => {
            print(b"resolve: cannot resolve ");
            print(name);
            print(b"\n");
        }
    }
}

fn cmd_traceroute(host: &[u8]) {
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            print(b"traceroute: cannot resolve host\n");
            return;
        }
    };

    print(b"traceroute to ");
    print(host);
    print(b" (");
    print_ip(ip);
    print(b"), 30 hops max\n");

    for ttl in 1..=30u64 {
        // Print TTL number with padding.
        if ttl < 10 { print(b" "); }
        print_u64(ttl);
        print(b"  ");

        let result = linux_traceroute_hop(ip as u64, ttl);
        if result == 0 {
            print(b"* * *\n");
        } else {
            let hop_ip = (result & 0xFFFFFFFF) as u32;
            let reached = (result >> 32) != 0;
            print_ip(hop_ip);
            print(b"\n");
            if reached {
                break;
            }
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"PANIC in lucas-shell\n");
    linux_exit(1);
}
