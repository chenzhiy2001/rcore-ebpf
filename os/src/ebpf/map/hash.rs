//! eBPF hash map
//!
//! 
//! a hash table implementation
//! does not differ much from traditional hash index
//! assume that all pointer are in kernel space

use super::{
    BpfResult,
    consts::*,
    retcode::BpfErrorCode::*,
    osutil::{memcmp, copy},
};
use super::internal::{
    InternalMapAttr,
    BpfMap,
};

use alloc::{boxed::Box,
            collections::BTreeMap};

use alloc::vec;
use alloc::vec::Vec;

use core::{slice};

type HashCode = u32;
type MapKey = Box<[u8]>;
type MapValue = Box<[u8]>;

/// hash map is internal a BTreeMap
pub struct HashMap {
    attr: InternalMapAttr,
    map: BTreeMap<HashCode, Vec<(MapKey, MapValue)>>,
    total_elems: usize, // total number of elements
}


impl HashMap {
    pub fn new(attr: InternalMapAttr) -> Self {
        let map = BTreeMap::new();
        Self {
            attr,
            map,
            total_elems: 0,
        }
    }

    /// get hash value from what kptr points to 
    fn hash(kptr: *const u8, ksize: usize) -> HashCode {
        let seed: HashCode = 131313;
        let mut hash: HashCode = 0;
        for &i in unsafe { slice::from_raw_parts(kptr, ksize) } {
            hash = hash.wrapping_mul(seed).wrapping_add(i as HashCode);
        }
        hash
    }

    /// find value by key that kptr points to
    fn find(&self, kptr: *const u8) -> Option<&MapValue> {
        let hashcode = HashMap::hash(kptr, self.attr.key_size);
        if let Some(kvlist) = self.map.get(&hashcode) {
            for kv in kvlist {
                let len = self.attr.key_size;
                if memcmp(kv.0.as_ptr(), kptr, len) {
                    return Some(&kv.1)
                }
            }
        }
        None
    }

    /// rehash 
    fn alloc(size: usize) -> Box<[u8]> {
        let mut storage = Vec::with_capacity(size);
        storage.resize(size, 0u8);
        storage.into_boxed_slice()
    }
}

/// implement four operations for hashmap
impl BpfMap for HashMap {
    fn lookup(&self, key: *const u8, value: *mut u8) -> BpfResult {
        if let Some(mv) = self.find(key) {
            copy(value, mv.as_ptr(), self.attr.value_size);
            Ok(0)
        } else {
            Err(ENOENT)
        }
    }

    fn update(&mut self, key: *const u8, value: *const u8, flags: u64) -> BpfResult {
        // handle different flags, only 1 flags could be given

        // check flags
        if !(flags == BPF_ANY || flags == BPF_EXIST || flags == BPF_NOEXIST) {
            return Err(EINVAL);
        }

        // handle different cases
        let key_size = self.attr.key_size;
        let value_size = self.attr.value_size;
        if let Some(v) = self.find(key) {
            match flags {
                BPF_ANY | BPF_EXIST => {
                    copy(v.as_ptr() as *mut u8, value, value_size);
                    Ok(0)
                }
                _ => Err(EEXIST), // existing entry
            }
        } else {
            match flags {
                BPF_ANY | BPF_NOEXIST => {
                    if self.total_elems >= self.attr.max_entries {
                        return Err(ENOMEM); // should we return something else?
                    }
                    // create one, copy key and value into kernel space
                    let mut map_key = HashMap::alloc(key_size);
                    let mut map_value = HashMap::alloc(value_size);
                    copy(map_key.as_mut_ptr(), key, key_size);
                    copy(map_value.as_mut_ptr(), value, value_size);

                    let hashcode = HashMap::hash(key, key_size);
                    if let Some(vec) = self.map.get_mut(&hashcode) {
                        vec.push((map_key, map_value));
                    } else {
                        let vec = vec![(map_key, map_value)];
                        self.map.insert(hashcode, vec);
                    }
                    self.total_elems += 1;
                    Ok(0)
                }
                _ => Err(ENOENT),
            }
        }
    }

    fn delete(&mut self, key: *const u8) -> BpfResult {
        let hashcode = HashMap::hash(key, self.attr.key_size);
        if let Some(kvlist) = self.map.get_mut(&hashcode) {
            for (i, kv) in kvlist.iter().enumerate() {
                if memcmp(kv.0.as_ptr(), key, self.attr.key_size) {
                    let _ = kvlist.remove(i);
                    self.total_elems -= 1;

                    // remove the empty Vec to avoid problems in next_key
                    if kvlist.is_empty() {
                        let _ = self.map.remove(&hashcode);
                    }
                    return Ok(0);
                
                }
            }
        }
        Err(ENOENT)
    }

    fn next_key(&self, key: *const u8, next_key: *mut u8) -> BpfResult {
        let key_size = self.attr.key_size;
        let hashcode = HashMap::hash(key, key_size);

        let get_first_key = || {
            //returns the first valid key
            if let Some((_, first_vec)) = self.map.first_key_value() {
                let first_kv = first_vec.first().unwrap();
                copy(next_key, first_kv.0.as_ptr(), key_size);
                Ok(0)
            } else {
                // the hash map is empty
                Err(ENOENT)
            }
        };

        let mut iter = self.map.range(hashcode..);
        match iter.next() {
            Some((_, vec)) => {
                let mut opt_idx = None;
                for (i, kv) in vec.iter().enumerate() {
                    if memcmp(kv.0.as_ptr(), key, key_size) {
                        opt_idx = Some(i);
                        break;
                    }
                }
                if opt_idx.is_none() {
                    return get_first_key();
                }

                let index = opt_idx.unwrap();
                if index < vec.len() - 1 {
                    copy(next_key, vec[index + 1].0.as_ptr(), key_size);
                    return Ok(0);
                }

                // move on to next entry
                if let Some((_, next_vec)) = iter.next() {
                    let first_kv = next_vec.first().unwrap();
                    copy(next_key, first_kv.0.as_ptr(), key_size);
                    Ok(0)
                } else {
                    Err(ENOENT)
                }
            }
            None => get_first_key(),
        }
    }

    fn get_attr(&self) -> InternalMapAttr {
        self.attr
    }

    fn lookup_helper(&self, key: *const u8) -> BpfResult {
        match self.find(key) {
            Some(map_key) => Ok(map_key.as_ptr() as usize),
            None => Err(ENOENT),
        }
    }
}
