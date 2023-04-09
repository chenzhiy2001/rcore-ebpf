
//! eBPF maps interal 
//!
//! defines the trait the a BPF map the must have

use super::{
    MapAttr,
    BpfResult,
};


use core::{slice};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use super::osutil::{copy, memcmp};

#[derive(Debug, Clone, Copy)]
pub struct InternalMapAttr {
    pub key_size: usize,
    pub value_size: usize,
    pub max_entries: usize,
}

impl From<MapAttr> for InternalMapAttr {
    fn from(attr: MapAttr) -> Self {
        Self {
            key_size: attr.key_size as usize,
            value_size: attr.value_size as usize,
            max_entries: attr.max_entries as usize,
        }
    }
}

pub trait BpfMap {
    /// lookup: get kv
    fn lookup(&self, key: *const u8, value: *mut u8) -> BpfResult;
    /// update: update or insert v by k
    fn update(&mut self, key: *const u8, value: *const u8, flags: u64) -> BpfResult;
    /// delete: delete a kv by k
    fn delete(&mut self, key: *const u8) -> BpfResult;
    /// used when iterate through hashmap
    fn next_key(&self, key: *const u8, next_key: *mut u8) -> BpfResult;
    fn get_attr(&self) -> InternalMapAttr;

    // this lookup is intended for the helper function
    fn lookup_helper(&self, key: *const u8) -> BpfResult;
}




