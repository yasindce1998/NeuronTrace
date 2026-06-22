use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use neurontrace_common::MAX_PATH_LEN;

pub fn read_kernel_str(src: *const u8, dst: &mut [u8; MAX_PATH_LEN]) -> u16 {
    if src.is_null() {
        return 0;
    }
    match unsafe { bpf_probe_read_kernel_str_bytes(src, dst) } {
        Ok(s) => s.len() as u16,
        Err(_) => 0,
    }
}
