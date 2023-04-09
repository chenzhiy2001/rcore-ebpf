use lock::Mutex;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use lazy_static::*;

use super::{byte_copy, alloc_page};
pub use super::osutils::*;

const BREAKPOINT_LENGTH: usize = 2;
const BREAKPOINTS_PER_PAGE: usize = PAGE_SIZE / BREAKPOINT_LENGTH;
const C_EBREAK: u16 = 0x9002;

/// Inject breakpoints into the given address range
pub fn inject_breakpoints(addr: usize, length: Option<usize>) {
    let ebreak = C_EBREAK; // C.EBREAK
    let bp_len = BREAKPOINT_LENGTH;

    let bp_count = match length {
        Some(len) => {
            assert!(len % bp_len == 0);
            len / bp_len
        }
        None => 1,
    };
    for i in 0..bp_count {
        byte_copy(addr + i * bp_len, (&ebreak as *const u16) as usize, bp_len);
    }
}

struct BreakpointPage {
    pub nr_free: usize,
}

lazy_static! {
    static ref FREE_BREAKPOINTS: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());
    static ref BREAKPOINT_PAGES: Mutex<BTreeMap<usize, BreakpointPage>> =
        Mutex::new(BTreeMap::new());
}

/// allocate a ebreak breakpoint not occupied by other kretprobes
pub fn alloc_breakpoint() -> usize {
    let mut free_bps = FREE_BREAKPOINTS.lock();
    if free_bps.len() != 0 {
        let addr = free_bps.pop_first().unwrap();
        let base = addr & !(PAGE_SIZE - 1);
        let mut pages = BREAKPOINT_PAGES.lock();
        let page = pages.get_mut(&base).unwrap();
        page.nr_free -= 1;
        return addr;
    } else {
        // new page of breakpoints
        let base = alloc_page();
        inject_breakpoints(base, Some(PAGE_SIZE));
        for i in 1..BREAKPOINTS_PER_PAGE {
            free_bps.insert(base + i * BREAKPOINT_LENGTH);
        }

        let page = BreakpointPage {
            nr_free: BREAKPOINTS_PER_PAGE - 1,
        };
        BREAKPOINT_PAGES.lock().insert(base, page);
        return base;
    }
}

/// free a breakpoint from kretprobe
pub fn free_breakpoint(addr: usize) {
    let mut free_bps = FREE_BREAKPOINTS.lock();
    free_bps.insert(addr);

    let base = addr & !(PAGE_SIZE - 1);
    let mut pages = BREAKPOINT_PAGES.lock();
    let page = pages.get_mut(&base).unwrap();
    page.nr_free += 1;

    if page.nr_free == BREAKPOINTS_PER_PAGE && pages.len() > 1 {
        for i in 0..BREAKPOINTS_PER_PAGE {
            free_bps.remove(&(base + i * BREAKPOINT_LENGTH));
        }
        pages.remove(&base);
    }
}
