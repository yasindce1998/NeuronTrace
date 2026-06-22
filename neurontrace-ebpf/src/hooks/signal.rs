use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::programs::LsmContext;

use crate::maps::{EVENTS, PID_ALLOWLIST};
use crate::policy::check_policy;
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

// Offset of `pid` (tgid in kernel terms) field in task_struct.
// This is the userspace-visible PID. Stable across kernel 5.15+.
const TASK_STRUCT_TGID_OFFSET: usize = 0x398;

pub fn handle_task_kill(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let sender_pid = (pid_tgid >> 32) as u32;

    // Sender in allowlist = always allow (controller sending signals)
    if unsafe { PID_ALLOWLIST.get(&sender_pid).is_some() } {
        return Ok(0);
    }

    // Read target task_struct pointer (arg 0 of task_kill LSM hook)
    let target_task: *const u8 = unsafe { ctx.arg(0) };
    if target_task.is_null() {
        return Ok(0);
    }

    // Read target PID (tgid) from task_struct
    let target_pid: u32 = unsafe {
        match bpf_probe_read_kernel(target_task.add(TASK_STRUCT_TGID_OFFSET) as *const u32) {
            Ok(pid) => pid,
            Err(_) => return Ok(0), // fail-open if we can't read
        }
    };

    // If target is in the allowlist (controller), block the signal
    if unsafe { PID_ALLOWLIST.get(&target_pid).is_some() } {
        emit_event(sender_pid, pid_tgid as u32, PolicyAction::Block, target_pid);
        return Ok(-1); // -EPERM
    }

    // Otherwise check normal policy
    let action = check_policy(sender_pid, EventType::TaskKill);

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            emit_event(sender_pid, pid_tgid as u32, PolicyAction::Block, target_pid);
            Ok(-1)
        }
        PolicyAction::Kill => {
            emit_event(sender_pid, pid_tgid as u32, PolicyAction::Kill, target_pid);
            Ok(-9)
        }
        PolicyAction::Audit => {
            emit_event(sender_pid, pid_tgid as u32, PolicyAction::Audit, target_pid);
            Ok(0)
        }
    }
}

#[inline(always)]
fn emit_event(pid: u32, tgid: u32, action: PolicyAction, target_pid: u32) {
    if let Some(mut buf) = EVENTS.reserve::<NtEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.pid = pid;
        event.tgid = tgid;
        event.uid = 0;
        event.event_type = EventType::TaskKill as u8;
        event.action_taken = action as u8;
        event._padding = [0u8; 2];
        event.cgroup_id = 0;
        event.timestamp_ns = 0;
        event.path = [0u8; MAX_PATH_LEN];
        event.path_len = 0;
        // Store target PID in argv as a simple identifier
        event.argv = [0u8; MAX_ARGV_LEN];
        let target_bytes = target_pid.to_ne_bytes();
        event.argv[0] = target_bytes[0];
        event.argv[1] = target_bytes[1];
        event.argv[2] = target_bytes[2];
        event.argv[3] = target_bytes[3];
        event.argv_len = 4;
        event._tail_padding = [0u8; 4];
        buf.submit(0);
    }
}
