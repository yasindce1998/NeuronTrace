use neurontrace_common::MAX_PATH_LEN;

extern "C" {
    fn bpf_probe_read_kernel(dst: *mut u8, size: u32, src: *const u8) -> i64;
    fn bpf_probe_read_kernel_str(dst: *mut u8, size: u32, src: *const u8) -> i64;
}

#[inline(always)]
pub fn read_kernel_str(src: *const u8, dst: &mut [u8; MAX_PATH_LEN]) -> u16 {
    if src.is_null() {
        return 0;
    }
    let ret = unsafe { bpf_probe_read_kernel_str(dst.as_mut_ptr(), MAX_PATH_LEN as u32, src) };
    if ret < 0 {
        0
    } else {
        ret as u16
    }
}

#[inline(always)]
pub fn read_kernel_ptr(src: *const u8) -> *const u8 {
    let mut val: *const u8 = core::ptr::null();
    let ret = unsafe {
        bpf_probe_read_kernel(
            &mut val as *mut *const u8 as *mut u8,
            core::mem::size_of::<*const u8>() as u32,
            src,
        )
    };
    if ret < 0 {
        core::ptr::null()
    } else {
        val
    }
}

#[inline(always)]
pub fn read_kernel_u32(src: *const u8) -> Option<u32> {
    let mut val: u32 = 0;
    let ret = unsafe {
        bpf_probe_read_kernel(&mut val as *mut u32 as *mut u8, 4, src)
    };
    if ret < 0 {
        None
    } else {
        Some(val)
    }
}

#[inline(always)]
pub fn read_kernel_bytes(src: *const u8, dst: &mut [u8], len: usize) -> bool {
    if src.is_null() || len == 0 {
        return false;
    }
    let ret = unsafe { bpf_probe_read_kernel(dst.as_mut_ptr(), len as u32, src) };
    ret >= 0
}
