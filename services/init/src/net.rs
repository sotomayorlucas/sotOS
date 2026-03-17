// IPC command constants for net service (must match services/net).
pub(crate) const NET_CMD_PING: u64 = 1;
pub(crate) const NET_CMD_DNS_QUERY: u64 = 2;
pub(crate) const NET_CMD_TCP_CONNECT: u64 = 3;
pub(crate) const NET_CMD_TCP_SEND: u64 = 4;
pub(crate) const NET_CMD_TCP_RECV: u64 = 5;
pub(crate) const NET_CMD_TCP_CLOSE: u64 = 6;
pub(crate) const NET_CMD_UDP_BIND: u64 = 8;
pub(crate) const NET_CMD_UDP_SENDTO: u64 = 9;
pub(crate) const NET_CMD_UDP_RECV: u64 = 10;
pub(crate) const NET_CMD_TCP_STATUS: u64 = 11;
pub(crate) const NET_CMD_MIRROR: u64 = 12;
pub(crate) const NET_CMD_UDP_HAS_DATA: u64 = 13;
