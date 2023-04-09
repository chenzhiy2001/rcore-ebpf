//! eBPF array map
//!
//! 
//! a simple array implementation
//! assume that all pointer are in kernel space

use super::{
    BpfResult,
    retcode::BpfErrorCode::*,
    osutil::{memcmp, copy},
};
use super::internal::{
    InternalMapAttr,
    BpfMap,
};


use alloc::vec::Vec;

pub struct ArrayMap {
    attr: InternalMapAttr,
    storage: Vec<u8>,
}

impl ArrayMap {
    pub fn new(attr: InternalMapAttr) -> Self {
        let size = attr.max_entries * attr.value_size;
        let mut storage = Vec::with_capacity(size);
        storage.resize(size, 0u8);
        Self { attr, storage }
    }

    /// get element kernel space address by index
    /// needs to dereference to get the actual value
    fn get_element_addr(&self, index: usize) -> usize {
        let offset = self.attr.value_size * index;
        self.storage.as_ptr() as usize + offset
    }
}


impl BpfMap for ArrayMap {
    fn lookup(&self, key: *const u8, value: *mut u8) -> BpfResult {
        let index = unsafe { *(key as *const u32) } as usize;
        if index >= self.attr.max_entries {
            return Err(ENOENT);
        }
        let p = self.get_element_addr(index);
        copy(value, p as *const u8, self.attr.value_size);
        Ok(0)
    }

    fn update(&mut self, key: *const u8, value: *const u8, _flags: u64) -> BpfResult {
        let index = unsafe { *(key as *const u32) } as usize;
        if index >= self.attr.max_entries {
            return Err(ENOENT);
        }

        let p = self.get_element_addr(index);
        copy(p as *mut u8, value, self.attr.value_size);
        Ok(0)
    }

    fn delete(&mut self, _key: *const u8) -> BpfResult {
        Err(EINVAL)
    }

    fn next_key(&self, key: *const u8, next_key: *mut u8) -> BpfResult {
        let out = next_key as *mut u32;
        let index = unsafe { *(key as *const u32) } as usize;
        if index >= self.attr.max_entries {
            unsafe {
                *out = 0u32;
            }
            return Ok(0);
        }

        if index < self.attr.max_entries - 1 {
            unsafe {
                *out = (index + 1) as u32;
            }
            Ok(0)
        } else {
            Err(ENOENT)
        }
    }

    fn get_attr(&self) -> InternalMapAttr {
        self.attr
    }

    fn lookup_helper(&self, key: *const u8) -> BpfResult {
        let index = unsafe { *(key as *const u32) } as usize;
        if index >= self.attr.max_entries {
            return Err(ENOENT);
        }

        Ok(self.get_element_addr(index))
    }
}
