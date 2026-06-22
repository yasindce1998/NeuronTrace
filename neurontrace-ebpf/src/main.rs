#![no_std]
#![no_main]
#![deny(warnings)]

mod helpers;
mod hooks;
mod maps;
mod policy;

use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;

#[lsm(hook = "bprm_check_security")]
pub fn nt_exec_check(ctx: LsmContext) -> i32 {
    match hooks::exec::handle_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open on BPF error
    }
}

#[lsm(hook = "file_open")]
pub fn nt_file_open(ctx: LsmContext) -> i32 {
    match hooks::file::handle_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(hook = "inode_unlink")]
pub fn nt_inode_unlink(ctx: LsmContext) -> i32 {
    match hooks::file::handle_unlink(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(hook = "inode_rename")]
pub fn nt_inode_rename(ctx: LsmContext) -> i32 {
    match hooks::file::handle_rename(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(hook = "socket_connect")]
pub fn nt_socket_connect(ctx: LsmContext) -> i32 {
    match hooks::network::handle_connect(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(hook = "ptrace_access_check")]
pub fn nt_ptrace_check(ctx: LsmContext) -> i32 {
    match hooks::ptrace::handle_ptrace(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[lsm(hook = "task_kill")]
pub fn nt_task_kill(ctx: LsmContext) -> i32 {
    match hooks::signal::handle_task_kill(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
