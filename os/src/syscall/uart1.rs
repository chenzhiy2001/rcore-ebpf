use crate::{drivers::chardev::{UART1, CharDevice}, board::DebugDeviceImpl};

pub fn sys_uart1_read()->isize{
        UART1.read() as isize

}
pub fn sys_uart1_write(c:usize)->isize{
UART1.write(c as u8);
1
}

pub fn sys_uart1_flush()->isize{
    UART1.flush();
    0
}