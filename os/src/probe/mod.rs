pub mod kprobes;
pub mod kretprobes;
pub mod osutils;
pub use osutils::init_osutils;

use kprobes::{Handler, HandlerFn};
pub use arch::TrapFrame;
use alloc::sync::Arc;

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[path = "arch/riscv/mod.rs"]
pub mod arch;

pub struct KProbeArgs {
    pub pre_handler: Arc<Handler>,
    pub post_handler: Option<Arc<Handler>>,
    // Extra user-defined data. Kprobes will not touch it and pass it to handler as-is.
    pub user_data: usize,
}

pub struct KRetProbeArgs {
    pub exit_handler: Arc<Handler>,
    pub entry_handler: Option<Arc<Handler>>,
    pub limit: Option<usize>,
    pub user_data: usize,
}

impl KProbeArgs {
    pub fn from(handler: HandlerFn) -> Self {
        Self {
            pre_handler: Arc::new(handler),
            post_handler: None,
            user_data: 0,
        }
    }
}

impl KRetProbeArgs {
    pub fn from(handler: HandlerFn) -> Self {
        Self {
            exit_handler: Arc::new(handler),
            entry_handler: None,
            limit: None,
            user_data: 0,
        }
    }
}

pub fn register_kprobe(addr: usize, args: KProbeArgs) -> Option<()> {
    match kprobes::register_kprobe(addr, args) {
        true => Some(()),
        false => None,
    }
}

pub fn unregister_kprobe(addr: usize) -> Option<()> {
    match kprobes::unregister_kprobe(addr) {
        true => Some(()),
        false => None,
    }
}

pub fn register_kretprobe(addr: usize, args: KRetProbeArgs) -> Option<()> {
    match kretprobes::register_kretprobe(addr, args) {
        true => Some(()),
        false => None,
    }
}

pub fn unregister_kretprobe(addr: usize) -> Option<()> {
    match kretprobes::unregister_kretprobe(addr) {
        true => Some(()),
        false => None,
    }
}

/// This function should be called from the trap handler when a breakpoint is hit.
#[no_mangle]
pub fn kprobes_breakpoint_handler(tf: &mut TrapFrame) {
    let handled = kprobes::kprobe_trap_handler(tf);
    if !handled {
        kretprobes::kretprobe_trap_handler(tf);
    }
}

mod tests;
pub fn run_tests() {
    tests::kprobes_test::run_kprobes_tests();
    tests::kretprobes_test::run_kretprobes_test();
}