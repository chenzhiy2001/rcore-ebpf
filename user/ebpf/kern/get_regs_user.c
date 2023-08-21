#include "bpf.h"
#include "uprobe.h"

int bpf_prog(struct uprobe_bpf_ctx *ctx) {
  bpf_trace_printk("%", 0, 0, 0); //Rust Fotmat! 
  bpf_trace_printk("M", 0, 0, 0); //M = messages. R = registers.
  bpf_trace_printk(" Time: {}",bpf_ktime_get_ns(),0,0);
  bpf_trace_printk(" vCPU: {}",bpf_get_smp_processor_id(),0,0);

  // report tracepoint address
  bpf_trace_printk(" User Addr = {}", ctx->paddr, 0, 0);

  i64 id = bpf_get_current_pid_tgid();
  int pid = id & 0xffffffff;
  bpf_trace_printk(" PID: {}", pid, 0, 0);

  // report registers
  bpf_trace_printk(" Registers:",0,0,0);
  for (int i = 0; i < 32; ++i) {
    bpf_trace_printk(" x{}:", i,0,0);
    bpf_trace_printk("{},", ctx->tf.regs[i], 0, 0);
  }
  bpf_trace_printk("#", 0, 0, 0);
  bpf_trace_printk("00", 0, 0, 0); //todo: modulo 256 checksum
  return 0;
}