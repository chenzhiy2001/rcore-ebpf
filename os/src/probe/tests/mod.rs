pub mod kprobes_test;
pub mod kretprobes_test;
pub use super::{kprobes, kretprobes, KProbeArgs, KRetProbeArgs};
pub use super::TrapFrame;
pub use super::arch::trapframe;