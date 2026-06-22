use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::programs::LsmContext;

use crate::helpers::read_kernel_str;
use crate::maps::EVENTS;
use crate::policy::{check_generation, check_policy};
use neurontrace_common::{EventType, NtEvent, PolicyAction, MAX_ARGV_LEN, MAX_PATH_LEN};

const FILE_DENTRY_OFFSET: usize = 24;
const DENTRY_NAME_OFFSET: usize = 40;

pub fn handle_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let action = check_policy(pid, EventType::Open);

    if !check_generation(pid) {
        emit_file_event(
            ctx,
            pid,
            tgid,
            EventType::Open,
            PolicyAction::Block,
            PathSource::FileDentry,
        );
        return Ok(-1);
    }

    match action {
        PolicyAction::Allow => Ok(0),
        PolicyAction::Block => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Open,
                PolicyAction::Block,
                PathSource::FileDentry,
            );
            Ok(-1)
        }
        PolicyAction::Kill => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Open,
                PolicyAction::Kill,
                PathSource::FileDentry,
            );
            Ok(-9)
        }
        PolicyAction::Audit => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Open,
                PolicyAction::Audit,
                PathSource::FileDentry,
            );
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
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Unlink,
                PolicyAction::Block,
                PathSource::DentryArg(1),
            );
            Ok(-1)
        }
        PolicyAction::Kill => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Unlink,
                PolicyAction::Kill,
                PathSource::DentryArg(1),
            );
            Ok(-9)
        }
        PolicyAction::Audit => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Unlink,
                PolicyAction::Audit,
                PathSource::DentryArg(1),
            );
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
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Rename,
                PolicyAction::Block,
                PathSource::DentryArg(1),
            );
            Ok(-1)
        }
        PolicyAction::Kill => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Rename,
                PolicyAction::Kill,
                PathSource::DentryArg(1),
            );
            Ok(-9)
        }
        PolicyAction::Audit => {
            emit_file_event(
                ctx,
                pid,
                tgid,
                EventType::Rename,
                PolicyAction::Audit,
                PathSource::DentryArg(1),
            );
            Ok(0)
        }
    }
}

enum PathSource {
    FileDentry,
    DentryArg(usize),
}

fn emit_file_event(
    ctx: &LsmContext,
    pid: u32,
    tgid: u32,
    event_type: EventType,
    action: PolicyAction,
    source: PathSource,
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
        event.path = [0u8; MAX_PATH_LEN];
        event.path_len = 0;
        event.argv = [0u8; MAX_ARGV_LEN];
        event.argv_len = 0;
        event._tail_padding = [0u8; 4];

        let dentry_ptr = match source {
            PathSource::FileDentry => read_file_dentry_ptr(ctx),
            PathSource::DentryArg(idx) => {
                let p: *const u8 = unsafe { ctx.arg(idx) };
                if p.is_null() {
                    core::ptr::null()
                } else {
                    p
                }
            }
        };

        if !dentry_ptr.is_null() {
            let name_ptr: *const u8 = match unsafe {
                bpf_probe_read_kernel(dentry_ptr.add(DENTRY_NAME_OFFSET) as *const *const u8)
            } {
                Ok(ptr) => ptr,
                Err(_) => core::ptr::null(),
            };
            if !name_ptr.is_null() {
                event.path_len = read_kernel_str(name_ptr, &mut event.path);
            }
        }

        buf.submit(0);
    }
}

fn read_file_dentry_ptr(ctx: &LsmContext) -> *const u8 {
    let file_ptr: *const u8 = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return core::ptr::null();
    }
    match unsafe { bpf_probe_read_kernel(file_ptr.add(FILE_DENTRY_OFFSET) as *const *const u8) } {
        Ok(ptr) => ptr,
        Err(_) => core::ptr::null(),
    }
}
