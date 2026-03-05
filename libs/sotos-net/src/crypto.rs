//! Cryptographic primitives for TLS: SHA-256, HMAC-SHA256, ChaCha20, X25519.
//!
//! All implementations are pure Rust, no_std, no heap. Suitable for
//! a microkernel environment with fixed-size buffers only.

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

/// SHA-256 round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values.
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 hasher. Processes data incrementally.
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher.
    pub fn new() -> Self {
        Self {
            h: H_INIT,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        // If we have buffered data, try to complete a block.
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let copy = data.len().min(space);
            self.buf[self.buf_len..self.buf_len + copy].copy_from_slice(&data[..copy]);
            self.buf_len += copy;
            offset += copy;
            if self.buf_len == 64 {
                let block = self.buf;
                Self::compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from input.
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::compress(&mut self.h, &block);
            offset += 64;
        }

        // Buffer remaining bytes.
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        // Padding: append 1 bit, then zeros, then 64-bit length.
        let bit_len = self.total_len * 8;

        // Append 0x80 byte.
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If not enough room for length (need 8 bytes), pad and compress.
        if self.buf_len > 56 {
            // Fill rest with zeros.
            let mut i = self.buf_len;
            while i < 64 {
                self.buf[i] = 0;
                i += 1;
            }
            let block = self.buf;
            Self::compress(&mut self.h, &block);
            self.buf_len = 0;
        }

        // Pad with zeros up to byte 56.
        let mut i = self.buf_len;
        while i < 56 {
            self.buf[i] = 0;
            i += 1;
        }

        // Append bit length as big-endian u64.
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        Self::compress(&mut self.h, &block);

        // Produce output.
        let mut out = [0u8; 32];
        let mut j = 0;
        while j < 8 {
            let bytes = self.h[j].to_be_bytes();
            out[j * 4] = bytes[0];
            out[j * 4 + 1] = bytes[1];
            out[j * 4 + 2] = bytes[2];
            out[j * 4 + 3] = bytes[3];
            j += 1;
        }
        out
    }

    /// Compress a single 64-byte block.
    fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
        // Prepare message schedule W.
        let mut w = [0u32; 64];
        let mut i = 0;
        while i < 16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            i += 1;
        }
        while i < 64 {
            let s0 = w[i - 15].rotate_right(7)
                ^ w[i - 15].rotate_right(18)
                ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17)
                ^ w[i - 2].rotate_right(19)
                ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        // Working variables.
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // 64 rounds.
        i = 0;
        while i < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            i += 1;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
}

/// Convenience: hash a single slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256. Key can be any length; data can be any length.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // If key is longer than block size (64), hash it first.
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Inner padding.
    let mut ipad = [0x36u8; 64];
    let mut i = 0;
    while i < 64 {
        ipad[i] ^= key_block[i];
        i += 1;
    }

    // Outer padding.
    let mut opad = [0x5Cu8; 64];
    i = 0;
    while i < 64 {
        opad[i] ^= key_block[i];
        i += 1;
    }

    // inner = SHA256(ipad || data)
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // outer = SHA256(opad || inner)
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 7539)
// ---------------------------------------------------------------------------

/// ChaCha20 stream cipher state.
pub struct ChaCha20 {
    state: [u32; 16],
    block_counter: u32,
}

impl ChaCha20 {
    /// Create a ChaCha20 instance from a 256-bit key and 96-bit nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];
        // "expand 32-byte k" constant.
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        // Key (8 words, little-endian).
        let mut i = 0;
        while i < 8 {
            state[4 + i] = u32::from_le_bytes([
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ]);
            i += 1;
        }
        // Counter starts at 0.
        state[12] = 0;
        // Nonce (3 words, little-endian).
        state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
        Self {
            state,
            block_counter: 0,
        }
    }

    /// Encrypt (or decrypt) data in place by XORing with the keystream.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    /// Decrypt is the same operation as encrypt for a stream cipher.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            self.state[12] = self.block_counter;
            let keystream = self.chacha20_block();
            self.block_counter = self.block_counter.wrapping_add(1);

            let remaining = data.len() - offset;
            let to_xor = if remaining < 64 { remaining } else { 64 };
            let mut i = 0;
            while i < to_xor {
                let word_idx = i / 4;
                let byte_idx = i % 4;
                let ks_byte = (keystream[word_idx] >> (byte_idx * 8)) as u8;
                data[offset + i] ^= ks_byte;
                i += 1;
            }
            offset += to_xor;
        }
    }

    /// Generate one 64-byte keystream block (20 rounds = 10 double-rounds).
    fn chacha20_block(&self) -> [u32; 16] {
        let mut working = self.state;

        let mut i = 0;
        while i < 10 {
            // Column rounds.
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds.
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
            i += 1;
        }

        // Add original state.
        i = 0;
        while i < 16 {
            working[i] = working[i].wrapping_add(self.state[i]);
            i += 1;
        }
        working
    }
}

/// ChaCha20 quarter round.
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

// ---------------------------------------------------------------------------
// X25519 (RFC 7748) — Curve25519 Diffie-Hellman
// ---------------------------------------------------------------------------

/// The prime p = 2^255 - 19, represented as 10 limbs of 26/25 bits each.
/// We use a radix-2^25.5 representation: limbs alternate between 26-bit and 25-bit.
/// Limb widths: [26, 25, 26, 25, 26, 25, 26, 25, 26, 25].

/// Field element: 10 limbs, each fitting in i64 for intermediate calculations.
#[derive(Clone, Copy)]
struct Fe([i64; 10]);

impl Fe {
    const ZERO: Fe = Fe([0; 10]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Load a 32-byte little-endian integer into a field element.
    fn from_bytes(s: &[u8; 32]) -> Fe {
        let mut h = [0i64; 10];
        let load4 = |b: &[u8]| -> i64 {
            (b[0] as i64)
                | ((b[1] as i64) << 8)
                | ((b[2] as i64) << 16)
                | ((b[3] as i64) << 24)
        };
        let load3 = |b: &[u8]| -> i64 {
            (b[0] as i64) | ((b[1] as i64) << 8) | ((b[2] as i64) << 16)
        };

        h[0] = load4(&s[0..]) & 0x3ffffff;
        h[1] = (load4(&s[3..]) >> 2) & 0x1ffffff;
        h[2] = (load4(&s[6..]) >> 3) & 0x3ffffff;
        h[3] = (load4(&s[9..]) >> 5) & 0x1ffffff;
        h[4] = (load4(&s[12..]) >> 6) & 0x3ffffff;
        h[5] = (load3(&s[16..]) >> 0) & 0x1ffffff;
        h[6] = (load4(&s[19..]) >> 1) & 0x3ffffff;
        h[7] = (load4(&s[22..]) >> 3) & 0x1ffffff;
        h[8] = (load4(&s[25..]) >> 4) & 0x3ffffff;
        h[9] = (load3(&s[28..]) >> 6) & 0x1ffffff;
        Fe(h)
    }

    /// Serialize a field element to 32 bytes (little-endian), fully reduced mod p.
    fn to_bytes(&self) -> [u8; 32] {
        let mut h = self.0;
        // Carry and reduce to canonical form.
        let mut q = (19 * h[9] + (1 << 24)) >> 25;
        let mut i = 0;
        while i < 5 {
            q = (h[2 * i] + q) >> 26;
            q = (h[2 * i + 1] + q) >> 25;
            i += 1;
        }
        h[0] += 19 * q;
        // Propagate carries.
        let mut carry = 0i64;
        i = 0;
        while i < 10 {
            h[i] += carry;
            if i % 2 == 0 {
                carry = h[i] >> 26;
                h[i] &= 0x3ffffff;
            } else {
                carry = h[i] >> 25;
                h[i] &= 0x1ffffff;
            }
            i += 1;
        }
        // Second pass to ensure full reduction.
        h[0] += 19 * carry;
        carry = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += carry;
        carry = h[1] >> 25;
        h[1] &= 0x1ffffff;
        h[2] += carry;

        let mut s = [0u8; 32];
        s[0] = h[0] as u8;
        s[1] = (h[0] >> 8) as u8;
        s[2] = (h[0] >> 16) as u8;
        s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
        s[4] = (h[1] >> 6) as u8;
        s[5] = (h[1] >> 14) as u8;
        s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
        s[7] = (h[2] >> 5) as u8;
        s[8] = (h[2] >> 13) as u8;
        s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
        s[10] = (h[3] >> 3) as u8;
        s[11] = (h[3] >> 11) as u8;
        s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
        s[13] = (h[4] >> 2) as u8;
        s[14] = (h[4] >> 10) as u8;
        s[15] = (h[4] >> 18) as u8;
        s[16] = h[5] as u8;
        s[17] = (h[5] >> 8) as u8;
        s[18] = (h[5] >> 16) as u8;
        s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
        s[20] = (h[6] >> 7) as u8;
        s[21] = (h[6] >> 15) as u8;
        s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
        s[23] = (h[7] >> 5) as u8;
        s[24] = (h[7] >> 13) as u8;
        s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
        s[26] = (h[8] >> 4) as u8;
        s[27] = (h[8] >> 12) as u8;
        s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
        s[29] = (h[9] >> 2) as u8;
        s[30] = (h[9] >> 10) as u8;
        s[31] = (h[9] >> 18) as u8;
        s
    }

    /// Add two field elements.
    fn add(a: &Fe, b: &Fe) -> Fe {
        let mut r = [0i64; 10];
        let mut i = 0;
        while i < 10 {
            r[i] = a.0[i] + b.0[i];
            i += 1;
        }
        Fe(r)
    }

    /// Subtract two field elements: a - b.
    fn sub(a: &Fe, b: &Fe) -> Fe {
        let mut r = [0i64; 10];
        let mut i = 0;
        while i < 10 {
            r[i] = a.0[i] - b.0[i];
            i += 1;
        }
        Fe(r)
    }

    /// Carry-reduce a field element after addition/subtraction.
    fn carry_reduce(a: &Fe) -> Fe {
        let mut h = a.0;
        let mut i = 0;
        while i < 9 {
            if i % 2 == 0 {
                let carry = h[i] >> 26;
                h[i] &= 0x3ffffff;
                h[i + 1] += carry;
            } else {
                let carry = h[i] >> 25;
                h[i] &= 0x1ffffff;
                h[i + 1] += carry;
            }
            i += 1;
        }
        // Limb 9: carry wraps around with factor 19.
        let carry = h[9] >> 25;
        h[9] &= 0x1ffffff;
        h[0] += carry * 19;
        // One more carry from limb 0.
        let carry = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += carry;
        Fe(h)
    }

    /// Multiply two field elements mod p.
    fn mul(a: &Fe, b: &Fe) -> Fe {
        let a = &a.0;
        let b = &b.0;

        // Precompute 2*b[i] for odd indices, 19*b[i] for reduction.
        let b1_19 = 19 * b[1];
        let b2_19 = 19 * b[2];
        let b3_19 = 19 * b[3];
        let b4_19 = 19 * b[4];
        let b5_19 = 19 * b[5];
        let b6_19 = 19 * b[6];
        let b7_19 = 19 * b[7];
        let b8_19 = 19 * b[8];
        let b9_19 = 19 * b[9];

        // a[i] * 2 for use in certain products (where one index is odd).
        let a1_2 = 2 * a[1];
        let a3_2 = 2 * a[3];
        let a5_2 = 2 * a[5];
        let a7_2 = 2 * a[7];
        let a9_2 = 2 * a[9];

        let mut h = [0i64; 10];

        h[0] = a[0]*b[0] + a1_2*b9_19 + a[2]*b8_19 + a3_2*b7_19 + a[4]*b6_19
             + a5_2*b5_19 + a[6]*b4_19 + a7_2*b3_19 + a[8]*b2_19 + a9_2*b1_19;
        h[1] = a[0]*b[1] + a[1]*b[0] + a[2]*b9_19 + a[3]*b8_19 + a[4]*b7_19
             + a[5]*b6_19 + a[6]*b5_19 + a[7]*b4_19 + a[8]*b3_19 + a[9]*b2_19;
        h[2] = a[0]*b[2] + a1_2*b[1] + a[2]*b[0] + a3_2*b9_19 + a[4]*b8_19
             + a5_2*b7_19 + a[6]*b6_19 + a7_2*b5_19 + a[8]*b4_19 + a9_2*b3_19;
        h[3] = a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0] + a[4]*b9_19
             + a[5]*b8_19 + a[6]*b7_19 + a[7]*b6_19 + a[8]*b5_19 + a[9]*b4_19;
        h[4] = a[0]*b[4] + a1_2*b[3] + a[2]*b[2] + a3_2*b[1] + a[4]*b[0]
             + a5_2*b9_19 + a[6]*b8_19 + a7_2*b7_19 + a[8]*b6_19 + a9_2*b5_19;
        h[5] = a[0]*b[5] + a[1]*b[4] + a[2]*b[3] + a[3]*b[2] + a[4]*b[1]
             + a[5]*b[0] + a[6]*b9_19 + a[7]*b8_19 + a[8]*b7_19 + a[9]*b6_19;
        h[6] = a[0]*b[6] + a1_2*b[5] + a[2]*b[4] + a3_2*b[3] + a[4]*b[2]
             + a5_2*b[1] + a[6]*b[0] + a7_2*b9_19 + a[8]*b8_19 + a9_2*b7_19;
        h[7] = a[0]*b[7] + a[1]*b[6] + a[2]*b[5] + a[3]*b[4] + a[4]*b[3]
             + a[5]*b[2] + a[6]*b[1] + a[7]*b[0] + a[8]*b9_19 + a[9]*b8_19;
        h[8] = a[0]*b[8] + a1_2*b[7] + a[2]*b[6] + a3_2*b[5] + a[4]*b[4]
             + a5_2*b[3] + a[6]*b[2] + a7_2*b[1] + a[8]*b[0] + a9_2*b9_19;
        h[9] = a[0]*b[9] + a[1]*b[8] + a[2]*b[7] + a[3]*b[6] + a[4]*b[5]
             + a[5]*b[4] + a[6]*b[3] + a[7]*b[2] + a[8]*b[1] + a[9]*b[0];

        Fe::carry_reduce(&Fe(h))
    }

    /// Square a field element mod p.
    fn sq(a: &Fe) -> Fe {
        Fe::mul(a, a)
    }

    /// Compute a^(2^n) by repeated squaring.
    fn sq_n(a: &Fe, n: u32) -> Fe {
        let mut r = *a;
        let mut i = 0;
        while i < n {
            r = Fe::sq(&r);
            i += 1;
        }
        r
    }

    /// Compute the multiplicative inverse mod p using Fermat's little theorem:
    /// a^(-1) = a^(p-2) mod p, where p = 2^255 - 19.
    /// p-2 = 2^255 - 21.
    fn invert(a: &Fe) -> Fe {
        // Using addition chain for p-2 = 2^255 - 21.
        let z2 = Fe::sq(a);                 // a^2
        let z9 = Fe::sq_n(&z2, 2);          // a^8
        let z9 = Fe::mul(&z9, a);           // a^9
        let z11 = Fe::mul(&z9, &z2);        // a^11
        let z_5_0 = Fe::sq(&z11);           // a^22
        let z_5_0 = Fe::mul(&z_5_0, &z9);  // a^31 = a^(2^5 - 1)
        let z_10_0 = Fe::sq_n(&z_5_0, 5);
        let z_10_0 = Fe::mul(&z_10_0, &z_5_0); // a^(2^10 - 1)
        let z_20_0 = Fe::sq_n(&z_10_0, 10);
        let z_20_0 = Fe::mul(&z_20_0, &z_10_0); // a^(2^20 - 1)
        let z_40_0 = Fe::sq_n(&z_20_0, 20);
        let z_40_0 = Fe::mul(&z_40_0, &z_20_0); // a^(2^40 - 1)
        let z_50_0 = Fe::sq_n(&z_40_0, 10);
        let z_50_0 = Fe::mul(&z_50_0, &z_10_0); // a^(2^50 - 1)
        let z_100_0 = Fe::sq_n(&z_50_0, 50);
        let z_100_0 = Fe::mul(&z_100_0, &z_50_0); // a^(2^100 - 1)
        let z_200_0 = Fe::sq_n(&z_100_0, 100);
        let z_200_0 = Fe::mul(&z_200_0, &z_100_0); // a^(2^200 - 1)
        let z_250_0 = Fe::sq_n(&z_200_0, 50);
        let z_250_0 = Fe::mul(&z_250_0, &z_50_0); // a^(2^250 - 1)
        let z_255_5 = Fe::sq_n(&z_250_0, 5);
        Fe::mul(&z_255_5, &z11) // a^(2^255 - 21) = a^(p-2)
    }

    /// Conditional swap: if swap != 0, swap a and b.
    fn cswap(a: &mut Fe, b: &mut Fe, swap: i64) {
        let mask = -swap; // 0 or -1 (all bits set)
        let mut i = 0;
        while i < 10 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
            i += 1;
        }
    }

    /// Multiply by a small constant (121666 for Curve25519 a24).
    fn mul_small(a: &Fe, c: i64) -> Fe {
        let mut h = [0i64; 10];
        let mut i = 0;
        while i < 10 {
            h[i] = a.0[i] * c;
            i += 1;
        }
        Fe::carry_reduce(&Fe(h))
    }
}

/// Clamp a 32-byte scalar per RFC 7748.
fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut e = *scalar;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    e
}

/// Montgomery ladder for X25519: compute scalar * point on Curve25519.
/// Both scalar and point are 32-byte little-endian encodings.
fn montgomery_ladder(scalar: &[u8; 32], u_coord: &Fe) -> Fe {
    let x_1 = *u_coord;
    let mut x_2 = Fe::ONE;
    let mut z_2 = Fe::ZERO;
    let mut x_3 = *u_coord;
    let mut z_3 = Fe::ONE;
    let mut swap: i64 = 0;

    let mut pos: i32 = 254;
    while pos >= 0 {
        let byte = scalar[(pos / 8) as usize];
        let bit = ((byte >> (pos as u8 % 8)) & 1) as i64;
        let s = swap ^ bit;
        Fe::cswap(&mut x_2, &mut x_3, s);
        Fe::cswap(&mut z_2, &mut z_3, s);
        swap = bit;

        let a = Fe::add(&x_2, &z_2);
        let a = Fe::carry_reduce(&a);
        let aa = Fe::sq(&a);
        let b = Fe::sub(&x_2, &z_2);
        let b = Fe::carry_reduce(&b);
        let bb = Fe::sq(&b);
        let e = Fe::sub(&aa, &bb);
        let e = Fe::carry_reduce(&e);
        let c = Fe::add(&x_3, &z_3);
        let c = Fe::carry_reduce(&c);
        let d = Fe::sub(&x_3, &z_3);
        let d = Fe::carry_reduce(&d);
        let da = Fe::mul(&d, &a);
        let cb = Fe::mul(&c, &b);
        let sum = Fe::add(&da, &cb);
        let sum = Fe::carry_reduce(&sum);
        let diff = Fe::sub(&da, &cb);
        let diff = Fe::carry_reduce(&diff);

        x_3 = Fe::sq(&sum);
        z_3 = Fe::mul(&Fe::sq(&diff), &x_1);
        x_2 = Fe::mul(&aa, &bb);
        z_2 = Fe::mul(&e, &Fe::add(&aa, &Fe::mul_small(&e, 121666)));

        pos -= 1;
    }
    Fe::cswap(&mut x_2, &mut x_3, swap);
    Fe::cswap(&mut z_2, &mut z_3, swap);

    Fe::mul(&x_2, &Fe::invert(&z_2))
}

/// X25519 base point multiplication: compute scalar * 9.
/// `scalar` is a 32-byte private key. Returns the 32-byte public key.
pub fn x25519_base_point_mul(scalar: &[u8; 32]) -> [u8; 32] {
    let clamped = clamp(scalar);
    let base = Fe([9, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // u = 9
    let result = montgomery_ladder(&clamped, &base);
    result.to_bytes()
}

/// X25519 shared secret: compute scalar * point.
/// `scalar` is the private key, `point` is the peer's public key (32 bytes each).
/// Returns the 32-byte shared secret.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let clamped = clamp(scalar);
    let u = Fe::from_bytes(point);
    let result = montgomery_ladder(&clamped, &u);
    result.to_bytes()
}
