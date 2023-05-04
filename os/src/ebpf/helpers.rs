//! eBPF helper functions
//!
//! 
//! those functions are called in bpf kernel programs
//! 
//! they need to be relocated in `load_prog` section
//! 
//! see `program.rs` for details


use alloc::string::ToString;

use super::{
    retcode::*,
    osutil::*, map::{bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem},
};

/// follow linux convention
pub type BpfHelperFn = fn(u64, u64, u64, u64, u64) -> i64;

pub const HELPER_FN_COUNT: usize = 17;

/// use static to make address never change
/// some function are still in progress, they are redirect to NOP
pub static HELPER_FN_TABLE: [BpfHelperFn; HELPER_FN_COUNT] = [
    bpf_helper_nop,
    bpf_helper_map_lookup_elem,
    bpf_helper_map_update_elem,
    bpf_helper_map_delete_elem,
    bpf_helper_nop, //bpf_helper_probe_read
    bpf_helper_ktime_get_ns,
    bpf_helper_trace_printk,
    bpf_helper_get_prandom_u32,
    bpf_helper_get_smp_processor_id,
    bpf_helper_nop, // bpf_skb_store_bytes
    bpf_helper_nop, // bpf_l3_csum_replace
    bpf_helper_nop, // bpf_l4_csum_replace
    bpf_helper_nop, // bpf_tail_call
    bpf_helper_nop, // bpf_clone_redirect
    bpf_helper_get_current_pid_tgid,
    bpf_helper_nop, // bpf_get_current_uid_gid
    bpf_helper_get_current_comm,
];


/// wrapper function to call bpf_map_lookup_elem with from_user = false
fn bpf_helper_map_lookup_elem(fd: u64, key: u64, value: u64, _4: u64, _5: u64) -> i64 {
    match bpf_map_lookup_elem(fd as u32, key as *const u8, value as *mut u8, 0, false) {
        Ok(val) => val as i64,
        Err(_) => -1
    }
}

/// wrapper function to call bpf_map_update_elem with from_user = false
fn bpf_helper_map_update_elem(fd: u64, key: u64, value: u64, flags: u64, _5: u64) -> i64 {
    match bpf_map_update_elem(fd as u32, key as *const u8, value as *mut u8, flags, false) {
        Ok(val) => val as i64,
        Err(_) => -1
    }
}

/// wrapper function to call bpf_map_delete_elem with from_user = false
fn bpf_helper_map_delete_elem(fd: u64, key: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    match bpf_map_delete_elem(fd as u32, key as *const u8, 0 as *mut u8, 0, false) {
        Ok(val) => val as i64,
        Err(_) => -1
    }
}

fn bpf_helper_nop(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    0
}

/// u64 bpf_ktime_get_ns(void)
/// return current ktime
/// uses os_current_time in `osutils.rs`
fn bpf_helper_ktime_get_ns(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    os_current_time() as i64
}

/// long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
/// print a format string to kernel logs
/// uses os_console_write_str in `osutils.rs`
fn bpf_helper_trace_printk(fmt: u64, fmt_size: u64, p1: u64, p2: u64, p3: u64) -> i64 {
    // // TODO: check pointer
    let fmt = unsafe { core::slice::from_raw_parts(fmt as *const u8, fmt_size as u32 as usize) };
    
    let output = dyn_fmt::Arguments::new(
        unsafe { core::str::from_utf8_unchecked(fmt) },
        &[p1, p2, p3]
    ).to_string();

    os_console_write_str(output.as_str()) //return number of bytes written
}

/// not implemented
fn bpf_helper_get_prandom_u32(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    todo!()
}

/// calls os_get_current_cpu
fn bpf_helper_get_smp_processor_id(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    os_get_current_cpu() as i64
}

/// calls thread.get_pid()
fn bpf_helper_get_current_pid_tgid(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    let thread = os_current_thread();
    let pid = thread.get_pid();
    // NOTE: tgid is the same with pid
    ((pid << 32) | pid) as i64
}

/// get current thread name
fn bpf_helper_get_current_comm(dst: u64, buf_size: u64, _1: u64, _2: u64, _3: u64) -> i64 {
    let thread = os_current_thread();
    let dst_ptr = dst as *mut u8;
    let name = thread.get_name();
    let name_ptr = name.as_bytes();
    let len = name.len();
    if len > buf_size as usize {
        return -1;
    }
    unsafe {
        let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, len);
        dst_slice.copy_from_slice(name_ptr);
        *dst_ptr.add(len) = 0;
    }
    len as i64
}
