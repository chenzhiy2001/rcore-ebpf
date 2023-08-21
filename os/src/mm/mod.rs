mod address;
mod frame_allocator;
mod heap_allocator;
mod memory_set;
mod page_table;

pub use address::VPNRange;
pub use address::{PhysAddr, PhysPageNum, StepByOne, VirtAddr, VirtPageNum};
pub use frame_allocator::{frame_alloc, frame_alloc_more, frame_dealloc, FrameTracker,raw_frame_alloc,raw_frame_dealloc};
pub use memory_set::remap_test;
pub use memory_set::{kernel_token, MapArea, MapPermission, MapType, MemorySet, KERNEL_SPACE};
use page_table::PTEFlags;
pub use page_table::{
    translated_byte_buffer, translated_ref, translated_refmut, translated_str, PageTable,
    PageTableEntry, UserBuffer, UserBufferIterator,
};

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    KERNEL_SPACE.exclusive_access().activate();
}

//todo put uprobe util funcs to one file
use core::arch::asm;
use MapType::Framed;
/// only use this for uprobe
#[no_mangle]
pub extern "C" fn get_new_page(addr: usize, len: usize) -> usize{
    //println!("get_new_page");
    let binding = crate::task::current_process();
    // println!("Getting PCB in get_new_page");
    let mut current_proc = binding.inner_exclusive_access();
    let ebreak_addr = current_proc.memory_set.find_free_area(addr, len);
    current_proc.memory_set.push(MapArea::new(ebreak_addr, VirtAddr(ebreak_addr.0+len), Framed, MapPermission::R | MapPermission::W| MapPermission::X| MapPermission::U), None);
    unsafe {asm!("fence.i");}
    ebreak_addr.0
}
/// only use this for uprobe
#[no_mangle]
pub extern "C" fn set_writeable(addr: usize){
    //println!("set_writable. addr is {:x}",addr);
    let binding = crate::task::current_process();
    // println!("Getting PCB in set_writeable");
    let current_proc = binding.inner_exclusive_access();
    current_proc.memory_set.page_table.translate(VirtAddr(addr).floor()).unwrap().set_writable();
    //page_table_entry.bits = page_table_entry.bits | ((1 << 2) as usize);//(1 << 2) is PTEFlags::W; 
    //println!("setted!");
    unsafe {asm!("fence.i");}
}