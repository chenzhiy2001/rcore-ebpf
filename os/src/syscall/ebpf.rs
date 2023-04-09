//! eBPF system call 
//!
//! - bpf(2)
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(unreachable_patterns)]

use log::info;

use super::*;

use crate::ebpf::{
    consts::BpfCommand,
    osutil::*,
};
use core::convert::TryFrom;

pub fn sys_bpf(cmd: isize, bpf_attr: usize , size: usize) -> isize {
    info!("sys_bpf cmd: {}, bpf_attr: {}, size: {}", cmd, bpf_attr, size);
    let ptr = bpf_attr as *const u8;
    let cmd = cmd as i32;
    if let Ok(bpf_cmd) = BpfCommand::try_from(cmd) {
        use BpfCommand::*;
        let ret = match bpf_cmd {
            BPF_MAP_CREATE => sys_bpf_map_create(ptr, size),
            BPF_MAP_LOOKUP_ELEM => sys_bpf_map_lookup_elem(ptr, size),
            BPF_MAP_UPDATE_ELEM => sys_bpf_map_update_elem(ptr, size),
            BPF_MAP_DELETE_ELEM => sys_bpf_map_delete_elem(ptr, size),
            BPF_MAP_GET_NEXT_KEY => sys_bpf_map_get_next_key(ptr, size),
            BPF_PROG_LOAD => todo!(),
            BPF_PROG_ATTACH => sys_bpf_program_attach(ptr, size),
            BPF_PROG_DETACH => sys_bpf_program_detach(ptr, size),
            BPF_PROG_LOAD_EX => sys_preprocess_bpf_program_load_ex(ptr, size),
        };
        if ret < 0 {
            -1
        } else {
           ret as isize
        }
    } else {
        -1
    }
}