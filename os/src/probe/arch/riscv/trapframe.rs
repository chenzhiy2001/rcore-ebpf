pub use crate::trap::TrapContext as TrapFrame;

pub fn get_trapframe_pc(tf: &TrapFrame) -> usize {
    tf.sepc
}

pub fn set_trapframe_pc(tf: &mut TrapFrame, pc: usize) {
    tf.sepc = pc;
}

pub fn get_trapframe_ra(tf: &TrapFrame) -> usize {
    tf.x[1]
}

pub fn set_trapframe_ra(tf: &mut TrapFrame, ra: usize) {
    tf.x[1] = ra;
}

pub fn get_reg(tf: &TrapFrame, reg: u32) -> usize {
    let index = reg as usize;
    if index != 0 {
        tf.x[index]
    } else {
        0
    }
}

pub fn set_reg(tf: &mut TrapFrame, reg: u32, val: usize) {
    let index = reg as usize;
    if index != 0 {
        tf.x[index] = val;
    }
}
