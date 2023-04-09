use crate::mm::{raw_frame_alloc, raw_frame_dealloc};

pub const PAGE_SIZE: usize = crate::config::PAGE_SIZE;

/// optional function to initialize anything needed
pub fn init_osutils() {
}

/// Allocate a page of memory, return virtual address
/// The page need to be readable and executable by user, and writable by kernel
pub fn alloc_page() -> usize {
    let pa = raw_frame_alloc().unwrap().into();
    let va = pa; // identity mapping in kernel
    va
}

/// Deallocate a page of memory from virtual address
pub fn dealloc_page(va: usize) {
    let pa = va;
    raw_frame_dealloc(pa.into());
}

/// Copy memory from src to dst, uses virtual address in kernel
pub fn byte_copy(dst_addr: usize, src_addr: usize, len: usize) {
    let dst = dst_addr as *mut u8;
    let src = src_addr as *const u8;
    unsafe {
        core::ptr::copy(src, dst, len);
    }
}

/// Convert symbol to address for kprobe registering, not required
pub fn symbol_to_addr(symbol: &str) -> Option<usize> {
    None
}