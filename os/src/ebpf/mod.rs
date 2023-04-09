//! eBPF utility mods
//!
//! 
//! provides management over so called `bpf_objects`


#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unreachable_code)]

pub mod consts;
mod helpers;
pub mod map;
pub mod program;
pub mod tracepoints;
pub mod retcode;
pub mod osutil;

use lock::Mutex;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use log::trace;
use core::sync::atomic::{AtomicU32, Ordering};
use lazy_static::lazy_static;
use map::SharedBpfMap;
use program::BpfProgram;

/// currently, a BpfObject is either a map or a program 
/// they are identified by a `fd`
pub enum BpfObject {
    Map(SharedBpfMap),
    Program(Arc<BpfProgram>),
}

impl BpfObject {
    /// get the map
    pub fn is_map(&self) -> Option<&SharedBpfMap> {
        match &self {
            BpfObject::Map(map) => Some(map),
            _ => None,
        }
    }
    /// get the program
    pub fn is_program(&self) -> Option<&Arc<BpfProgram>> {
        match &self {
            BpfObject::Program(program) => Some(program),
            _ => None,
        }
    }
}

/// to avoid conflict with real fd
const BPF_FD_BASE: u32 = 0x70000000;

/// Bpf Objects are store in a index, with key = fd, value = Arc<Object> 
lazy_static! {
    static ref BPF_FD_COUNTER: AtomicU32 = AtomicU32::new(BPF_FD_BASE);
    pub static ref BPF_OBJECTS: Mutex<BTreeMap<u32, BpfObject>> = Mutex::new(BTreeMap::new());
}

/// use atomic fetch and add for concurrency
pub fn bpf_allocate_fd() -> u32 {
    BPF_FD_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// insert into kv
pub fn bpf_object_create(fd: u32, obj: BpfObject) {
    trace!("bpf object create (fd):{:x}", fd);
    BPF_OBJECTS.lock().insert(fd, obj);
}

pub fn bpf_object_create_map(fd: u32, map: SharedBpfMap) {
    bpf_object_create(fd, BpfObject::Map(map));
}

pub fn bpf_object_create_program(fd: u32, prog: BpfProgram) {
    bpf_object_create(fd, BpfObject::Program(Arc::new(prog)));
}

pub fn bpf_object_remove(fd: u32) -> Option<BpfObject> {
    BPF_OBJECTS.lock().remove(&fd)
}
