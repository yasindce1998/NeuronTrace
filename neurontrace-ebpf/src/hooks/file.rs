use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::programs::LsmContext;

use crate::helpers::read_kernel_str;
use crate::maps::EVENTS;
use crate::policy::{check_generation, check_policy};
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

// struct file->f_path.dentry: f_path at offset 16, dentry is second ptr at +8
const FILE_DENTRY_OFFSET: usize = 24;
// struct dentry->d_name.name: d_name at offset 32, name ptr at +8
const DENTRY_NAME_OFFSET: usize = 40;

pub fn handle_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Open);

    if !check_generation(pid) {
        let path = read_file_dentry_name(ctx);
        emit_event(pid, tgid, EventType::Open, PolicyAction::Block, &path);
        return Ok(-1);
    }

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            let path = read_file_dentry_name(ctx);
            emit_event(pid, tgid, EventType::Open, PolicyAction::Block, &path);
            Ok(-1)
        }
        PolicyAction::Kill => {
            let path = read_file_dentry_name(ctx);
            emit_event(pid, tgid, EventType::Open, PolicyAction::Kill, &path);
            Ok(-9)
        }
        PolicyAction::Audit => {
            let path = read_file_dentry_name(ctx);
            emit_event(pid, tgid, EventType::Open, PolicyAction::Audit, &path);
            Ok(0)
        }
    }
}

pub fn handle_unlink(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Unlink);

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            let path = read_dentry_name_from_arg(ctx, 1);
            emit_event(pid, tgid, EventType::Unlink, PolicyAction::Block, &path);
            Ok(-1)
        }
        PolicyAction::Kill => {
            let path = read_dentry_name_from_arg(ctx, 1);
            emit_event(pid, tgid, EventType::Unlink, PolicyAction::Kill, &path);
            Ok(-9)
        }
        PolicyAction::Audit => {
            let path = read_dentry_name_from_arg(ctx, 1);
            emit_event(pid, tgid, EventType::Unlink, PolicyAction::Audit, &path);
            Ok(0)
        }
    }
}

pub fn handle_rename(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Rename);

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            let path = read_dentry_name_from_arg(ctx, 1);
            emit_event(pid, tgid, EventType::Rename, PolicyAction::Block, &path);
            Ok(-1)
        }
        PolicyAction::Kill => {
            let path = read_dentry_name_from_arg(ctx, 1);
            emit_event(pid, tgid, EventType::Rename, PolicyAction::Kill, &path);
            Ok(-9)
        }
        PolicyAction::Audit => {
            let path = read_dentry_name_from_arg(ctx, 1);
            emit_event(pid, tgid, EventType::Rename, PolicyAction::Audit, &path);
            Ok(0)
        }
    }
}

// Read filename from struct file->f_path.dentry->d_name.name (arg 0 = struct file *)
fn read_file_dentry_name(ctx: &LsmContext) -> ([u8; MAX_PATH_LEN], u16) {
    let mut buf = [0u8; MAX_PATH_LEN];
    let file_ptr: *const u8 = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return (buf, 0);
    }
    let dentry_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel(file_ptr.add(FILE_DENTRY_OFFSET) as *const *const u8)
    } {
        Ok(ptr) => ptr,
        Err(_) => return (buf, 0),
    };
    let len = read_dentry_name_str(dentry_ptr, &mut buf);
    (buf, len)
}

// Read filename from dentry at a specific ctx arg index
fn read_dentry_name_from_arg(ctx: &LsmContext, arg_idx: usize) -> ([u8; MAX_PATH_LEN], u16) {
    let mut buf = [0u8; MAX_PATH_LEN];
    let dentry_ptr: *const u8 = unsafe { ctx.arg(arg_idx) };
    if dentry_ptr.is_null() {
        return (buf, 0);
    }
    let len = read_dentry_name_str(dentry_ptr, &mut buf);
    (buf, len)
}

// Read d_name.name string from a dentry pointer
fn read_dentry_name_str(dentry_ptr: *const u8, buf: &mut [u8; MAX_PATH_LEN]) -> u16 {
    if dentry_ptr.is_null() {
        return 0;
    }
    let name_ptr: *const u8 = match unsafe {
        bpf_probe_read_kernel(dentry_ptr.add(DENTRY_NAME_OFFSET) as *const *const u8)
    } {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };
    read_kernel_str(name_ptr, buf)
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
