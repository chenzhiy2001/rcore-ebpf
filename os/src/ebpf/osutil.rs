

//! OS depedent parts and some helpers 
//! 
//! one needs to change os_* to migrate to another kernel

use super::{
    map::*,
    map::MapAttr,
    map::MapOpAttr,
    retcode::BpfResult,
    tracepoints::KprobeAttachAttr,
    tracepoints::*,
    program::{bpf_program_load_ex, ProgramLoadExAttr, MapFdEntry},
};

use core::{mem::size_of, fmt::Write, iter::Map};

use alloc::{sync::Arc, vec};
use alloc::string::String;
use log::{warn, trace};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use downcast_rs::{impl_downcast, DowncastSync};

use crate::task::TaskControlBlock;

/// ThreadLike is an analog for Linux thread
pub trait ThreadLike : DowncastSync {
    fn get_pid(&self) -> u64;
    fn get_tid(&self) -> u64;
    fn get_name(&self) -> String;
}

impl_downcast!(ThreadLike);

/// in rCore, `TaskControlBlock` is the thread abstract
impl ThreadLike for TaskControlBlock {
    fn get_pid(&self) -> u64 {
        let proc = self.process.upgrade().unwrap();
        return proc.pid.0 as u64;
    }
    fn get_tid(&self) -> u64 {
        return 0; // no viable in rcore tutor
    }
    fn get_name(&self) -> String {
        return String::from("not viable in rcore tutorial")
    }
}

/// get current user thread
pub fn os_current_thread() -> Arc<dyn ThreadLike> {
    if let Some(thread) = crate::task::current_task() {
        thread
    } else {
        panic!("cannot get current thread!")
    }
}

/// get current time
pub fn os_current_time() -> u128 {
   crate::timer::get_time_ms() as u128 * 1_000_000
}

/// get current hart
pub fn os_get_current_cpu() -> u8 {
   0 // not viable
}

/// write a str to kernel log
pub fn os_console_write_str(s: &str) {
    crate::console::Stdout.write_str(s).unwrap();
}

/// # os_copy_from_user
/// copy `len` bytes from user space addresss `usr_addr` to `kern_buf`
pub fn os_copy_from_user(usr_addr: usize, kern_buf: *mut u8, len: usize) -> i32 {
    use crate::mm::translated_byte_buffer;
    use crate::task::current_user_token;
    let t = translated_byte_buffer(current_user_token(), usr_addr as *const u8, len);    
    let mut all = vec![];
    for i in t {
        all.extend(i.to_vec());
    }
    copy(kern_buf, all.as_ptr() as *const u8, len);
    0
}
 
/// # os_copy_to_user
/// copy `len` bytes to user space addresss `usr_addr` from `kern_buf`
pub fn os_copy_to_user(usr_addr: usize, kern_buf: *const u8, len: usize) -> i32 {
    use crate::mm::translated_byte_buffer;
    use crate::task::current_user_token;
    let dst = translated_byte_buffer(current_user_token(), usr_addr as *const u8, len);
    let mut ptr = kern_buf;
    let mut total_len = len as i32;
    for seg in dst {
        let cur_len = seg.len();
        total_len -= cur_len as i32;
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, seg.as_mut_ptr(), cur_len);
            ptr = ptr.add(cur_len);   
        }
    }
    assert_eq!(total_len, 0);
    0
}

/// copy within kernel space
pub fn copy(dst: *mut u8, src: *const u8, len: usize) {
    let from = unsafe { from_raw_parts(src, len) };
    let to = unsafe { from_raw_parts_mut(dst, len) };
    to.copy_from_slice(from);
}

/// compare two pointer `u` `v` for `len` bytes
/// 
/// return 0 on exact equal
pub fn memcmp(u: *const u8, v: *const u8, len: usize) -> bool {
    return unsafe {
        from_raw_parts(u, len) == from_raw_parts(v, len)
    }
}

/// # get_generic_from_user
/// from user space address `user_addr` copy a object with type `T`
/// * T is an generic type that must implment Copy trait
pub fn get_generic_from_user<T: Copy>(user_addr: usize) -> T {
    let size = size_of::<T>();
    let ret = vec![0 as u8; size];
    let buf = ret.as_ptr() as *const T;
    os_copy_from_user(user_addr as usize, buf as *mut u8, size_of::<T>());
    let attr = unsafe {
        *(buf as *const T)
    };
    attr
}

/// convert a `BpfResult` to `i32` for syscall interface
fn convert_result(result: BpfResult) -> i32 {
    match result {
        Ok(val) => val as i32,
        Err(err) => {
            warn!("convert result get error! {:?}", err);
            -1
        }
    }
}

/// wrapper
pub fn sys_bpf_map_create(attr: *const u8, size: usize) -> i32 {
   // assert_eq!(size as usize, size_of::<MapAttr>());
    let map_attr: MapAttr = get_generic_from_user(attr as usize);
    convert_result(bpf_map_create(map_attr))
}

/// wrapper
pub fn sys_bpf_map_lookup_elem(attr: *const u8, size: usize) -> i32 {
   // assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    let ret = bpf_map_lookup_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags, true);
    convert_result(ret)
}

/// wrapper
pub fn sys_bpf_map_update_elem(attr: *const u8, size: usize) -> i32 {
    //assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    let ret = bpf_map_update_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags, true);
    convert_result(ret)
}

/// wrapper
pub fn sys_bpf_map_delete_elem(attr: *const u8, size: usize) -> i32 {
    //assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    let ret = bpf_map_delete_elem(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags, true);
    convert_result(ret)
}

/// wrapper
pub fn sys_bpf_map_get_next_key(attr: *const u8, size: usize) -> i32 {
    let map_op_attr: MapOpAttr = get_generic_from_user(attr as usize);
    let ret = bpf_map_get_next_key(map_op_attr.map_fd, map_op_attr.key as *const u8, map_op_attr.value_or_nextkey as *mut u8, map_op_attr.flags, true);
    convert_result(ret)
}

/// wrapper
pub fn sys_bpf_program_attach(attr: *const u8, size: usize) -> i32 {
  //  assert_eq!(size, size_of::<KprobeAttachAttr>());
    let attach_attr: KprobeAttachAttr = get_generic_from_user(attr as usize);
    let len = attach_attr.str_len as usize;
    let mut target_name_buf = vec![0 as u8; len];
    os_copy_from_user(attach_attr.target as usize, target_name_buf.as_mut_ptr(), len);
    let target_name = unsafe {
        core::str::from_utf8(
            target_name_buf.as_slice()
           // core::slice::from_raw_parts(attach_attr.target, attach_attr.str_len as usize)
        ).unwrap()
    };
    trace!("target name str: {}", target_name);
    convert_result(bpf_program_attach(target_name, attach_attr.prog_fd))
}

/// wrapper
pub fn sys_bpf_program_detach(attr: *const u8, size: usize) -> i32 {
    let detach_attr: KprobeAttachAttr = get_generic_from_user(attr as usize);
    trace!("detach fd {}", detach_attr.prog_fd);
    convert_result(bpf_program_detach(detach_attr.prog_fd))
}

/// wrapper
/// this is a custome function, so we just copy from rCore
pub fn sys_bpf_program_load_ex(prog: &mut [u8], map_info: &[(String, u32)]) -> i32 {
    let ret = convert_result(bpf_program_load_ex(prog, &map_info));
    trace!("load ex ret: {}", ret);
    ret
}

/// # sys_preprocess_bpf_program_load_ex
/// a wrapper that parse the `attr_ptr` and then call `bpf_program_load_ex`
/// # argumetns
/// * attr_ptr - a pointer that should points to a `ProgramLoadExAttr` objects
/// * size - unused
/// # procedure
/// * cast the attr using `get_generic_from_user`
/// * copy the BPF elf from user space 
/// * copy the map fd info if there is one
/// * call `sys_bpf_program_load_ex`
#[allow(unused_mut)]
pub fn sys_preprocess_bpf_program_load_ex(attr_ptr: *const u8, size: usize) -> i32 {

    let attr:ProgramLoadExAttr = get_generic_from_user(attr_ptr as usize);

   trace!("prog load attr\n prog_base:{:x} prog_size={} map_base:{:x} map_num={}", attr.elf_prog, attr.elf_size, attr.map_array as usize, attr.map_array_len);
    let base = attr.elf_prog as usize;
    let size = attr.elf_size as usize;
    let mut prog = vec![0 as u8; size];
    os_copy_from_user(base, prog.as_mut_ptr(), size);
    let arr_len = attr.map_array_len as usize;
    let arr_size = arr_len * core::mem::size_of::<MapFdEntry>();
    let mut map_fd_array = vec![0 as u8; arr_size];
    if arr_size > 0 {
        os_copy_from_user(attr.map_array as usize, map_fd_array.as_mut_ptr(), arr_size);
    }

    let mut map_info = alloc::vec::Vec::new();
    let start = map_fd_array.as_ptr() as *const MapFdEntry;
    for i in 0..arr_len {
        unsafe {
            let entry = &(*start.add(i));
            let name_ptr = entry.name;
            let map_name = read_null_terminated_str(name_ptr);
            trace!("insert map: {} fd: {}", map_name, entry.fd);
            map_info.push((map_name, entry.fd));            
        }   
    }

    sys_bpf_program_load_ex(&mut prog[..], &map_info[..])
}

/// read a C style string from user space pointed by `ptr`
unsafe fn read_null_terminated_str(mut ptr: *const u8) -> String {
    let mut ret = String::new();
    loop {
        let c: u8 = get_generic_from_user(ptr as usize);
        if c == 0 {
            break;
        }
        ret.push(c as char);
        ptr = ptr.add(1);
    }
    ret
}