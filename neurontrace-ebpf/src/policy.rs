use aya_ebpf::helpers::bpf_get_current_cgroup_id;
use neurontrace_common::{EventType, PolicyAction, PolicyKey};

use crate::maps::{GENERATION, LABEL_MAP, PID_ALLOWLIST, POLICY_MAP};

#[inline(always)]
pub fn check_policy(pid: u32, event_type: EventType) -> PolicyAction {
    // Skip if PID is in the allowlist (controller process)
    if unsafe { PID_ALLOWLIST.get(&pid).is_some() } {
        return PolicyAction::Allow;
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let key = PolicyKey {
        cgroup_id,
        event_type: event_type as u8,
        _padding: [0u8; 7],
    };

    match unsafe { POLICY_MAP.get(&key) } {
        Some(value) => match value.action {
            0 => PolicyAction::Allow,
            1 => PolicyAction::Block,
            2 => PolicyAction::Kill,
            3 => PolicyAction::Audit,
            _ => PolicyAction::Block, // default-deny
        },
        None => PolicyAction::Block, // default-deny: no rule = block
    }
}

#[inline(always)]
pub fn check_generation(pid: u32) -> bool {
    let current_gen = match GENERATION.get(0) {
        Some(g) => g.current,
        None => return true, // no generation tracking active
    };

    let labels = match unsafe { LABEL_MAP.get(&pid) } {
        Some(l) => l,
        None => return true, // no labels = no generation violation
    };

    for i in 0..labels.count as usize {
        if i >= neurontrace_common::MAX_LABELS_PER_PROCESS {
            break;
        }
        if labels.labels[i].generation != current_gen && labels.labels[i].generation != 0 {
            return false; // stale generation detected
        }
    }

    true
}
