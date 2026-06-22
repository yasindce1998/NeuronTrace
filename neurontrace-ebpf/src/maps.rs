use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LruHashMap, RingBuf};
use neurontrace_common::{
    GenerationCounter, NtEvent, PolicyKey, PolicyValue, ProcessLabels, RING_BUF_SIZE,
};

#[map]
pub static POLICY_MAP: HashMap<PolicyKey, PolicyValue> =
    HashMap::with_max_entries(1024, 0);

#[map]
pub static LABEL_MAP: LruHashMap<u32, ProcessLabels> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
pub static GENERATION: Array<GenerationCounter> = Array::with_max_entries(1, 0);

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

// PID allowlist: processes in this map bypass all checks (for the controller itself)
#[map]
pub static PID_ALLOWLIST: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
