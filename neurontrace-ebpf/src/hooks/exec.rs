use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::programs::LsmContext;

use crate::helpers::read_kernel_str;
use crate::maps::EVENTS;
use crate::policy::{check_generation, check_policy};
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

// struct linux_binprm->filename offset (kernel 5.15–6.x)
const BINPRM_FILENAME_OFFSET: usize = 0x38;

pub fn handle_exec(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Exec);

    if !check_generation(pid) {
        let path = read_bprm_filename(ctx);
        emit_event(pid, tgid, EventType::Exec, PolicyAction::Block, &path);
        return Ok(-1);
    }

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            let path = read_bprm_filename(ctx);
            emit_event(pid, tgid, EventType::Exec, PolicyAction::Block, &path);
            Ok(-1)
        }
        PolicyAction::Kill => {
            let path = read_bprm_filename(ctx);
            emit_event(pid, tgid, EventType::Exec, PolicyAction::Kill, &path);
            Ok(-9)
        }
        PolicyAction::Audit => {
            let path = read_bprm_filename(ctx);
            emit_event(pid, tgid, EventType::Exec, PolicyAction::Audit, &path);
            Ok(0)
        }
    }
}

fn read_bprm_filename(ctx: &LsmContext) -> ([u8; MAX_PATH_LEN], u16) {
    let mut buf = [0u8; MAX_PATH_LEN];
    let bprm: *const u8 = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return (buf, 0);
    }
    let filename_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel((bprm.add(BINPRM_FILENAME_OFFSET)) as *const *const u8)
    } {
        Ok(ptr) => ptr,
        Err(_) => return (buf, 0),
    };
    let len = read_kernel_str(filename_ptr, &mut buf);
    (buf, len)
}

fn emit_event(
    pid: u32,
    tgid: u32,
    event_type: EventType,
    action: PolicyAction,
    path: &([u8; MAX_PATH_LEN], u16),
) {
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
        event.path = path.0;
        event.path_len = path.1;
        event.argv = [0u8; MAX_ARGV_LEN];
        event.argv_len = 0;
        event._tail_padding = [0u8; 4];
        buf.submit(0);
    }
}
