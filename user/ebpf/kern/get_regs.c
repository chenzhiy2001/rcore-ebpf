#include "bpf.h"
#include "kprobe.h"

int bpf_prog(struct kprobe_bpf_ctx *ctx) {
  bpf_trace_printk("%", 0, 0, 0); //Rust Fotmat! 
  bpf_trace_printk("R", 0, 0, 0); 
  // report registers
  for (int i = 0; i < 32; ++i) {
    bpf_trace_printk("{}", ctx->tf.regs[i], 0, 0);
  }
  bpf_trace_printk("#", 0, 0, 0);
  bpf_trace_printk("00", 0, 0, 0); //todo: modulo 256 checksum
  return 0;
}