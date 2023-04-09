use super::kretprobes::{register_kretprobe};
use alloc::sync::Arc;
use super::{KRetProbeArgs, TrapFrame};
use super::trapframe::*;

#[inline(never)]
fn recursive_fn(i: isize) -> isize {
    if i >= 5 {
        return 100;
    }

    println!("in recursive_fn({})", i);
    return i + recursive_fn(i + 1);
}

fn test_entry_handler(tf: &mut TrapFrame, _data: usize) -> isize {
    println!("entering fn, a0 = {}", get_reg(tf, 10));
    0
}

fn test_exit_handler(tf: &mut TrapFrame, _data: usize) -> isize {
    println!("exiting fn, a0 = {}", get_reg(tf, 10));
    0
}

pub fn run_kretprobes_test() {
    let args = KRetProbeArgs {
        exit_handler: Arc::new(test_exit_handler),
        entry_handler: Some(Arc::new(test_entry_handler)),
        limit: None,
        user_data: 0,
    };
    register_kretprobe(recursive_fn as usize, args);
    recursive_fn(1);
}
