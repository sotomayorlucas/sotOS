//! IPv6 packet parsing, building, and ICMPv6 basics.
//!
//! Supports header parse/build, ICMPv6 echo, and neighbor discovery
//! (solicitation/advertisement). No extension header chaining.

// ICMPv6 checksum is computed inline (IPv6 pseudo-header differs from IPv4).

pub const IPV6_HDR_LEN: usize = 40;
pub const PROTO_ICMPV6: u8 = 58;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// ICMPv6 message types.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
pub const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// Ethertype for IPv6 frames.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Parsed IPv6 header.
pub struct Ipv6Header {
    /// Version (4 bits), traffic class (8 bits), flow label (20 bits) packed.
    pub version_tc_flow: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

/// Parse an IPv6 packet. Returns header and payload slice.
pub fn parse(pkt: &[u8]) -> Option<Ipv6Header> {
    if pkt.len() < IPV6_HDR_LEN {
        return None;
    }
    let version_tc_flow = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    let version = (version_tc_flow >> 28) as u8;
    if version != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]);
    let next_header = pkt[6];
    let hop_limit = pkt[7];
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Header {
        version_tc_flow,
        payload_len,
        next_header,
        hop_limit,
        src,
        dst,
    })
}

/// Get the payload slice from a parsed IPv6 packet.
pub fn payload<'a>(pkt: &'a [u8], hdr: &Ipv6Header) -> &'a [u8] {
    let end = IPV6_HDR_LEN + hdr.payload_len as usize;
    if pkt.len() < end {
        &pkt[IPV6_HDR_LEN..]
    } else {
        &pkt[IPV6_HDR_LEN..end]
    }
}

/// Build an IPv6 packet header into `buf`. Returns total length (header + payload).
/// Caller must write payload starting at `buf[IPV6_HDR_LEN..]` before calling,
/// or pass it separately and copy after.
pub fn build(
    src: [u8; 16],
    dst: [u8; 16],
    next_header: u8,
    hop_limit: u8,
    payload_len: u16,
    buf: &mut [u8],
) -> usize {
    let total = IPV6_HDR_LEN + payload_len as usize;
    if buf.len() < total {
        return 0;
    }
    // Version=6, traffic class=0, flow label=0.
    let version_tc_flow: u32 = 6 << 28;
    buf[0..4].copy_from_slice(&version_tc_flow.to_be_bytes());
    buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
    buf[6] = next_header;
    buf[7] = hop_limit;
    buf[8..24].copy_from_slice(&src);
    buf[24..40].copy_from_slice(&dst);
    total
}

/// Compute ICMPv6 checksum using IPv6 pseudo-header.
fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src (16), dst (16), upper-layer length (4), next header (4).
    let mut i = 0;
    while i < 16 {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
        i += 2;
    }
    let len = icmp_data.len() as u32;
    sum += (len >> 16) as u32;
    sum += (len & 0xFFFF) as u32;
    sum += PROTO_ICMPV6 as u32;
    // ICMPv6 data.
    i = 0;
    while i + 1 < icmp_data.len() {
        sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp_data.len() {
        sum += (icmp_data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMPv6 echo request inside a full IPv6 packet.
/// Returns total packet length (IPv6 header + ICMPv6).
pub fn build_icmpv6_echo(
    src: [u8; 16],
    dst: [u8; 16],
    id: u16,
    seq: u16,
    buf: &mut [u8],
) -> usize {
    let icmp_len: usize = 8; // type(1) + code(1) + checksum(2) + id(2) + seq(2)
    let total = IPV6_HDR_LEN + icmp_len;
    if buf.len() < total {
        return 0;
    }

    // Build IPv6 header.
    build(src, dst, PROTO_ICMPV6, 64, icmp_len as u16, buf);

    // ICMPv6 echo request.
    let icmp = &mut buf[IPV6_HDR_LEN..];
    icmp[0] = ICMPV6_ECHO_REQUEST;
    icmp[1] = 0; // code
    icmp[2] = 0; // checksum (filled below)
    icmp[3] = 0;
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());

    let cksum = icmpv6_checksum(&src, &dst, &buf[IPV6_HDR_LEN..total]);
    buf[IPV6_HDR_LEN + 2] = (cksum >> 8) as u8;
    buf[IPV6_HDR_LEN + 3] = (cksum & 0xFF) as u8;

    total
}

/// Check if an ICMPv6 payload is an echo reply. Returns (id, seq) if so.
pub fn is_echo_reply(icmp_data: &[u8]) -> Option<(u16, u16)> {
    if icmp_data.len() < 8 {
        return None;
    }
    if icmp_data[0] != ICMPV6_ECHO_REPLY {
        return None;
    }
    let id = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
    let seq = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);
    Some((id, seq))
}

/// Build an ICMPv6 Neighbor Solicitation for `target_addr`.
/// Returns total IPv6 packet length.
///
/// NS format (RFC 4861):
///   type(1)=135, code(1)=0, checksum(2), reserved(4), target(16)
///   + optional source link-layer address option: type(1)=1, len(1)=1, mac(6)
pub fn build_neighbor_solicitation(
    src: [u8; 16],
    target: [u8; 16],
    src_mac: &[u8; 6],
    buf: &mut [u8],
) -> usize {
    // Solicited-node multicast address: ff02::1:ffXX:XXXX (last 3 bytes of target).
    let mut dst = [0u8; 16];
    dst[0] = 0xFF;
    dst[1] = 0x02;
    dst[11] = 0x01;
    dst[12] = 0xFF;
    dst[13] = target[13];
    dst[14] = target[14];
    dst[15] = target[15];

    let icmp_len: usize = 24 + 8; // NS body(24) + source LL option(8)
    let total = IPV6_HDR_LEN + icmp_len;
    if buf.len() < total {
        return 0;
    }

    build(src, dst, PROTO_ICMPV6, 255, icmp_len as u16, buf);

    let icmp = &mut buf[IPV6_HDR_LEN..];
    icmp[0] = ICMPV6_NEIGHBOR_SOLICITATION;
    icmp[1] = 0; // code
    icmp[2] = 0; // checksum (filled below)
    icmp[3] = 0;
    // Reserved (4 bytes).
    icmp[4] = 0;
    icmp[5] = 0;
    icmp[6] = 0;
    icmp[7] = 0;
    // Target address.
    icmp[8..24].copy_from_slice(&target);
    // Source link-layer address option.
    icmp[24] = 1; // type = source link-layer address
    icmp[25] = 1; // length = 1 (units of 8 bytes)
    icmp[26..32].copy_from_slice(src_mac);

    let cksum = icmpv6_checksum(&src, &dst, &buf[IPV6_HDR_LEN..total]);
    buf[IPV6_HDR_LEN + 2] = (cksum >> 8) as u8;
    buf[IPV6_HDR_LEN + 3] = (cksum & 0xFF) as u8;

    total
}

/// Parsed Neighbor Advertisement fields.
pub struct NeighborAdvert {
    pub router: bool,
    pub solicited: bool,
    pub override_flag: bool,
    pub target: [u8; 16],
    /// Target link-layer address from option, if present.
    pub target_mac: Option<[u8; 6]>,
}

/// Parse an ICMPv6 Neighbor Advertisement from the ICMPv6 payload.
pub fn parse_neighbor_advertisement(icmp_data: &[u8]) -> Option<NeighborAdvert> {
    if icmp_data.len() < 24 {
        return None;
    }
    if icmp_data[0] != ICMPV6_NEIGHBOR_ADVERTISEMENT {
        return None;
    }
    let flags = icmp_data[4];
    let router = flags & 0x80 != 0;
    let solicited = flags & 0x40 != 0;
    let override_flag = flags & 0x20 != 0;
    let mut target = [0u8; 16];
    target.copy_from_slice(&icmp_data[8..24]);

    // Look for target link-layer address option (type=2).
    let mut target_mac = None;
    let mut pos = 24;
    while pos + 2 <= icmp_data.len() {
        let opt_type = icmp_data[pos];
        let opt_len = icmp_data[pos + 1] as usize * 8; // in units of 8 bytes
        if opt_len == 0 {
            break;
        }
        if opt_type == 2 && opt_len >= 8 && pos + 8 <= icmp_data.len() {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&icmp_data[pos + 2..pos + 8]);
            target_mac = Some(mac);
        }
        pos += opt_len;
    }

    Some(NeighborAdvert {
        router,
        solicited,
        override_flag,
        target,
        target_mac,
    })
}

/// Build an ICMPv6 Neighbor Advertisement in response to a solicitation.
/// Returns total IPv6 packet length.
pub fn build_neighbor_advertisement(
    src: [u8; 16],
    dst: [u8; 16],
    target: [u8; 16],
    src_mac: &[u8; 6],
    solicited: bool,
    buf: &mut [u8],
) -> usize {
    let icmp_len: usize = 24 + 8; // NA body(24) + target LL option(8)
    let total = IPV6_HDR_LEN + icmp_len;
    if buf.len() < total {
        return 0;
    }

    build(src, dst, PROTO_ICMPV6, 255, icmp_len as u16, buf);

    let icmp = &mut buf[IPV6_HDR_LEN..];
    icmp[0] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
    icmp[1] = 0; // code
    icmp[2] = 0; // checksum (filled below)
    icmp[3] = 0;
    // Flags: R=0, S=solicited, O=1 (override).
    let mut flags: u8 = 0x20; // Override
    if solicited {
        flags |= 0x40; // Solicited
    }
    icmp[4] = flags;
    icmp[5] = 0;
    icmp[6] = 0;
    icmp[7] = 0;
    // Target address.
    icmp[8..24].copy_from_slice(&target);
    // Target link-layer address option.
    icmp[24] = 2; // type = target link-layer address
    icmp[25] = 1; // length = 1 (units of 8 bytes)
    icmp[26..32].copy_from_slice(src_mac);

    let cksum = icmpv6_checksum(&src, &dst, &buf[IPV6_HDR_LEN..total]);
    buf[IPV6_HDR_LEN + 2] = (cksum >> 8) as u8;
    buf[IPV6_HDR_LEN + 3] = (cksum & 0xFF) as u8;

    total
}

/// Handle an incoming ICMPv6 packet. If it's an echo request, build a reply.
/// Returns the ICMPv6 reply payload length, or None.
pub fn handle_icmpv6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    icmp_data: &[u8],
    reply_buf: &mut [u8],
) -> Option<usize> {
    if icmp_data.len() < 8 {
        return None;
    }
    if icmp_data[0] != ICMPV6_ECHO_REQUEST {
        return None;
    }
    if reply_buf.len() < icmp_data.len() {
        return None;
    }
    // Copy and change type to reply.
    reply_buf[..icmp_data.len()].copy_from_slice(icmp_data);
    reply_buf[0] = ICMPV6_ECHO_REPLY;
    // Zero checksum before recalculating.
    reply_buf[2] = 0;
    reply_buf[3] = 0;
    // For the reply, src and dst are swapped at the caller level.
    // Checksum uses dst_ip as new src, src_ip as new dst.
    let cksum = icmpv6_checksum(dst_ip, src_ip, &reply_buf[..icmp_data.len()]);
    reply_buf[2] = (cksum >> 8) as u8;
    reply_buf[3] = (cksum & 0xFF) as u8;
    Some(icmp_data.len())
}
