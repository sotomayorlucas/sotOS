//! Synchronous IPC endpoints.
//!
//! An endpoint is a kernel object through which threads exchange small
//! messages. The protocol is synchronous rendezvous: the sender blocks
//! until a receiver is ready (or vice versa), and the message is
//! transferred directly via register state — no intermediate buffer.
//!
//! This is the "slow path" IPC for control/setup operations.
//! High-throughput data flows use shared-memory channels instead.

use spin::Mutex;

/// Maximum number of system-wide endpoints.
const MAX_ENDPOINTS: usize = 256;

/// Maximum threads that can be queued waiting to send on one endpoint.
const MAX_SEND_QUEUE: usize = 16;

/// Number of message registers (64-bit words).
pub const MSG_REGS: usize = 8;

/// Endpoint identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointId(pub u32);

/// A fixed-size message that fits in registers.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// Message tag: identifies the operation/type.
    pub tag: u64,
    /// Payload registers.
    pub regs: [u64; MSG_REGS],
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            regs: [0; MSG_REGS],
        }
    }
}

/// Thread ID (imported from sched, but we keep a local alias to avoid
/// circular dependencies at this stage).
type ThreadId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointState {
    /// No one waiting.
    Idle,
    /// A receiver is waiting for a message.
    RecvWait,
    /// Sender(s) waiting for a receiver.
    SendWait,
}

struct Endpoint {
    state: EndpointState,
    /// Thread currently waiting to receive.
    receiver: Option<ThreadId>,
    /// Queue of threads waiting to send.
    send_queue: [Option<ThreadId>; MAX_SEND_QUEUE],
    send_queue_len: usize,
    /// The pending message (set by sender, read by receiver on rendezvous).
    pending_msg: Message,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            receiver: None,
            send_queue: [None; MAX_SEND_QUEUE],
            send_queue_len: 0,
            pending_msg: Message::empty(),
        }
    }
}

static ENDPOINTS: Mutex<[Endpoint; MAX_ENDPOINTS]> =
    Mutex::new([const { Endpoint::new() }; MAX_ENDPOINTS]);
static NEXT_ID: Mutex<u32> = Mutex::new(0);

/// Create a new endpoint. Returns None if no slots available.
pub fn create() -> Option<EndpointId> {
    let mut next = NEXT_ID.lock();
    let id = *next;
    if (id as usize) >= MAX_ENDPOINTS {
        return None;
    }
    *next += 1;
    Some(EndpointId(id))
}
