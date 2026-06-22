use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::programs::LsmContext;

use crate::maps::EVENTS;
use crate::policy::{check_generation, check_policy};
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

const MAX_SOCKADDR_LEN: usize = 28;

pub fn handle_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Connect);

    if !check_generation(pid) {
        emit_connect_event(ctx, pid, tgid, PolicyAction::Block);
        return Ok(-1);
    }

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            emit_connect_event(ctx, pid, tgid, PolicyAction::Block);
            Ok(-1)
        }
        PolicyAction::Kill => {
            emit_connect_event(ctx, pid, tgid, PolicyAction::Kill);
            Ok(-9)
        }
        PolicyAction::Audit => {
            emit_connect_event(ctx, pid, tgid, PolicyAction::Audit);
            Ok(0)
        }
    }
}

fn emit_connect_event(ctx: &LsmContext, pid: u32, tgid: u32, action: PolicyAction) {
    if let Some(mut buf) = EVENTS.reserve::<NtEvent>(0) {
        let event = unsafe { &mut *buf.as_mut_ptr() };
        event.pid = pid;
        event.tgid = tgid;
        event.uid = 0;
        event.event_type = EventType::Connect as u8;
        event.action_taken = action as u8;
        event._padding = [0u8; 2];
        event.cgroup_id = 0;
        event.timestamp_ns = 0;
        event.path = [0u8; MAX_PATH_LEN];
        event.path_len = 0;
        event.argv = [0u8; MAX_ARGV_LEN];
        event.argv_len = 0;
        event._tail_padding = [0u8; 4];

        let addr_ptr: *const u8 = unsafe { ctx.arg(1) };
        if !addr_ptr.is_null() {
            let addrlen: i32 = unsafe { ctx.arg(2) };
            let read_len = if addrlen <= 0 {
                0usize
            } else if (addrlen as usize) > MAX_SOCKADDR_LEN {
                MAX_SOCKADDR_LEN
            } else {
                addrlen as usize
            };

            if read_len > 0 {
                if let Ok(tmp) =
                    unsafe { bpf_probe_read_kernel(addr_ptr as *const [u8; MAX_SOCKADDR_LEN]) }
                {
                    let mut i = 0;
                    while i < read_len && i < MAX_PATH_LEN {
                        event.path[i] = tmp[i];
                        i += 1;
                    }
                    event.path_len = read_len as u16;
                }
            }
        }

        buf.submit(0);
    }
}
