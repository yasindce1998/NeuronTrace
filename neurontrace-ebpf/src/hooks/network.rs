use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::programs::LsmContext;

use crate::maps::EVENTS;
use crate::policy::{check_generation, check_policy};
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

// Max sockaddr size we'll capture (covers AF_INET6 = 28 bytes)
const MAX_SOCKADDR_LEN: usize = 28;

pub fn handle_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Connect);

    if !check_generation(pid) {
        let addr = read_sockaddr(ctx);
        emit_event(pid, tgid, EventType::Connect, PolicyAction::Block, &addr);
        return Ok(-1);
    }

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            let addr = read_sockaddr(ctx);
            emit_event(pid, tgid, EventType::Connect, PolicyAction::Block, &addr);
            Ok(-1)
        }
        PolicyAction::Kill => {
            let addr = read_sockaddr(ctx);
            emit_event(pid, tgid, EventType::Connect, PolicyAction::Kill, &addr);
            Ok(-9)
        }
        PolicyAction::Audit => {
            let addr = read_sockaddr(ctx);
            emit_event(pid, tgid, EventType::Connect, PolicyAction::Audit, &addr);
            Ok(0)
        }
    }
}

// socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
// arg 1 = sockaddr pointer, arg 2 = addrlen
fn read_sockaddr(ctx: &LsmContext) -> ([u8; MAX_PATH_LEN], u16) {
    let mut buf = [0u8; MAX_PATH_LEN];
    let addr_ptr: *const u8 = unsafe { ctx.arg(1) };
    if addr_ptr.is_null() {
        return (buf, 0);
    }
    let addrlen: i32 = unsafe { ctx.arg(2) };
    let read_len = if addrlen <= 0 {
        0usize
    } else if (addrlen as usize) > MAX_SOCKADDR_LEN {
        MAX_SOCKADDR_LEN
    } else {
        addrlen as usize
    };

    if read_len == 0 {
        return (buf, 0);
    }

    let tmp: [u8; MAX_SOCKADDR_LEN] = match unsafe {
        bpf_probe_read_kernel(addr_ptr as *const [u8; MAX_SOCKADDR_LEN])
    } {
        Ok(bytes) => bytes,
        Err(_) => return (buf, 0),
    };

    let copy_len = if read_len > MAX_PATH_LEN {
        MAX_PATH_LEN
    } else {
        read_len
    };
    let mut i = 0;
    while i < copy_len {
        buf[i] = tmp[i];
        i += 1;
    }

    (buf, copy_len as u16)
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
