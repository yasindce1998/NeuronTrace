use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::programs::LsmContext;

use crate::maps::EVENTS;
use crate::policy::{check_generation, check_policy};
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

pub fn handle_ptrace(_ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Ptrace);

    if !check_generation(pid) {
        emit_event(pid, tgid, EventType::Ptrace, PolicyAction::Block);
        return Ok(-1);
    }

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            emit_event(pid, tgid, EventType::Ptrace, PolicyAction::Block);
            Ok(-1)
        }
        PolicyAction::Kill => {
            emit_event(pid, tgid, EventType::Ptrace, PolicyAction::Kill);
            Ok(-9)
        }
        PolicyAction::Audit => {
            emit_event(pid, tgid, EventType::Ptrace, PolicyAction::Audit);
            Ok(0)
        }
    }
}

#[inline(always)]
fn emit_event(pid: u32, tgid: u32, event_type: EventType, action: PolicyAction) {
    if let Some(mut buf) = EVENTS.reserve::<NtEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.pid = pid;
        event.tgid = tgid;
        event.uid = 0;
        event.event_type = event_type as u8;
        event.action_taken = action as u8;
        event._padding = [0u8; 2];
        event.cgroup_id = 0;
        event.timestamp_ns = 0;
        event.path = [0u8; MAX_PATH_LEN];
        event.path_len = 0;
        event.argv = [0u8; MAX_ARGV_LEN];
        event.argv_len = 0;
        event._tail_padding = [0u8; 4];
        buf.submit(0);
    }
}
