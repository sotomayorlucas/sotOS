//! Minimal HTTP/1.1 client — request building and response parsing.
//!
//! No heap, no alloc. Fixed-size buffers only. Designed for simple
//! GET/POST requests in a microkernel environment.

/// Maximum body size we can store in a response.
const MAX_BODY: usize = 4096;

/// An HTTP request to build.
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub port: u16,
}

/// A parsed HTTP response.
pub struct HttpResponse {
    pub status_code: u16,
    pub content_length: u32,
    pub body: [u8; MAX_BODY],
    pub body_len: usize,
    /// Length of the headers section (including trailing \r\n\r\n).
    pub headers_len: usize,
}

/// Build an HTTP/1.1 request into `buf`. Returns the number of bytes written.
///
/// Produces a request like:
/// ```text
/// GET /path HTTP/1.1\r\n
/// Host: example.com\r\n
/// Connection: close\r\n
/// \r\n
/// ```
pub fn build_request(req: &HttpRequest, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    // Helper: write bytes to buf, advance pos.
    macro_rules! put {
        ($data:expr) => {
            let d: &[u8] = $data;
            if pos + d.len() > buf.len() {
                return 0;
            }
            buf[pos..pos + d.len()].copy_from_slice(d);
            pos += d.len();
        };
    }

    // Request line: METHOD PATH HTTP/1.1\r\n
    put!(req.method.as_bytes());
    put!(b" ");
    put!(req.path.as_bytes());
    put!(b" HTTP/1.1\r\n");

    // Host header.
    put!(b"Host: ");
    put!(req.host.as_bytes());
    // Append :port if not default.
    if req.port != 80 && req.port != 443 {
        put!(b":");
        let mut port_buf = [0u8; 5];
        let port_len = write_u16(req.port, &mut port_buf);
        put!(&port_buf[..port_len]);
    }
    put!(b"\r\n");

    // Connection: close.
    put!(b"Connection: close\r\n");

    // User-Agent.
    put!(b"User-Agent: sotOS/0.1\r\n");

    // End of headers.
    put!(b"\r\n");

    pos
}

/// Parse an HTTP response from raw TCP data.
/// `data` contains up to `len` bytes of the response.
/// Returns `Some(HttpResponse)` if the headers are complete.
pub fn parse_response(data: &[u8], len: usize) -> Option<HttpResponse> {
    let data = if len < data.len() { &data[..len] } else { data };

    // Find the end of headers: \r\n\r\n.
    let headers_end = find_header_end(data)?;
    let headers_len = headers_end + 4; // Include the \r\n\r\n.

    // Parse status line: "HTTP/1.x NNN ...\r\n"
    let status_code = parse_status_line(data)?;

    // Parse Content-Length header.
    let content_length = parse_content_length(data, headers_end);

    // Extract body.
    let body_start = headers_len;
    let body_available = if body_start < data.len() {
        data.len() - body_start
    } else {
        0
    };
    let body_len = body_available.min(MAX_BODY);

    let mut body = [0u8; MAX_BODY];
    if body_len > 0 {
        body[..body_len].copy_from_slice(&data[body_start..body_start + body_len]);
    }

    Some(HttpResponse {
        status_code,
        content_length,
        body,
        body_len,
        headers_len,
    })
}

/// Find the position of the first \r\n\r\n in `data`.
/// Returns the index of the first \r in the sequence.
fn find_header_end(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == b'\r'
            && data[i + 1] == b'\n'
            && data[i + 2] == b'\r'
            && data[i + 3] == b'\n'
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse the status code from the HTTP status line.
/// Expects "HTTP/1.x NNN" at the start.
fn parse_status_line(data: &[u8]) -> Option<u16> {
    // Minimum: "HTTP/1.0 200" = 12 bytes.
    if data.len() < 12 {
        return None;
    }
    // Check "HTTP/1."
    if data[0] != b'H'
        || data[1] != b'T'
        || data[2] != b'T'
        || data[3] != b'P'
        || data[4] != b'/'
        || data[5] != b'1'
        || data[6] != b'.'
    {
        return None;
    }
    // Skip version digit and space: data[7] = '0' or '1', data[8] = ' '.
    if data[8] != b' ' {
        return None;
    }
    // Parse 3-digit status code at positions 9, 10, 11.
    let d0 = (data[9] as u16).wrapping_sub(b'0' as u16);
    let d1 = (data[10] as u16).wrapping_sub(b'0' as u16);
    let d2 = (data[11] as u16).wrapping_sub(b'0' as u16);
    if d0 > 9 || d1 > 9 || d2 > 9 {
        return None;
    }
    Some(d0 * 100 + d1 * 10 + d2)
}

/// Parse the Content-Length header value from the header section.
fn parse_content_length(data: &[u8], headers_end: usize) -> u32 {
    // Search for "Content-Length: " (case-insensitive on the value part).
    // We do a simple case-sensitive search for the most common form.
    let needle = b"Content-Length: ";
    let needle_lower = b"content-length: ";
    let header_data = &data[..headers_end];

    let mut i = 0;
    while i + needle.len() < header_data.len() {
        let matches = header_matches(header_data, i, needle)
            || header_matches(header_data, i, needle_lower);
        if matches {
            // Parse the decimal number after the colon+space.
            let start = i + needle.len();
            return parse_decimal(header_data, start);
        }
        i += 1;
    }
    0
}

/// Check if `data[offset..]` starts with `needle`.
fn header_matches(data: &[u8], offset: usize, needle: &[u8]) -> bool {
    if offset + needle.len() > data.len() {
        return false;
    }
    let mut i = 0;
    while i < needle.len() {
        if data[offset + i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Parse a decimal number from data starting at `start`, until non-digit.
fn parse_decimal(data: &[u8], start: usize) -> u32 {
    let mut val: u32 = 0;
    let mut i = start;
    while i < data.len() {
        let b = data[i];
        if b < b'0' || b > b'9' {
            break;
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u32);
        i += 1;
    }
    val
}

/// Write a u16 as decimal ASCII into `buf`. Returns the number of bytes written.
fn write_u16(mut val: u16, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
            return 1;
        }
        return 0;
    }
    // Write digits in reverse, then reverse.
    let mut tmp = [0u8; 5];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    if len > buf.len() {
        return 0;
    }
    let mut i = 0;
    while i < len {
        buf[i] = tmp[len - 1 - i];
        i += 1;
    }
    len
}
