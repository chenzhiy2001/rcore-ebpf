mod ns16550a;

use core::fmt::Debug;

use crate::board::CharDeviceImpl;
use crate::board::DebugDeviceImpl;
use alloc::sync::Arc;
use lazy_static::*;
pub use ns16550a::NS16550a;

pub trait CharDevice {
    fn init(&self);
    fn read(&self) -> u8;
    fn write(&self, ch: u8);
    fn handle_irq(&self);
}

lazy_static! {
    pub static ref UART: Arc<CharDeviceImpl> = Arc::new(CharDeviceImpl::new());
    pub static ref UART1: Arc<DebugDeviceImpl> = Arc::new(DebugDeviceImpl::new());
}
