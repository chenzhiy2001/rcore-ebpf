#ifndef __LIBS_KPROBE_H__
#define __LIBS_KPROBE_H__

typedef unsigned long long size_t;

#define KPROBE_TYPE_KPROBE 0
#define KRPOBE_TYPE_KRETPROBE_ENTRY 1
#define KPROBE_TYPE_KRETPROBE_EXIT 2

struct kprobe_bpf_ctx {
  size_t ptype;
  size_t paddr;
  struct {
    union {
      size_t regs[32];
      struct {
        size_t zero;
        size_t ra;
        size_t sp;
        size_t gp;
        size_t tp;
        size_t t0;
        size_t t1;
        size_t t2;
        size_t s0;
        size_t s1;
        size_t a0;
        size_t a1;
        size_t a2;
        size_t a3;
        size_t a4;
        size_t a5;
        size_t a6;
        size_t a7;
        size_t s2;
        size_t s3;
        size_t s4;
        size_t s5;
        size_t s6;
        size_t s7;
        size_t s8;
        size_t s9;
        size_t s10;
        size_t s11;
        size_t t3;
        size_t t4;
        size_t t5;
        size_t t6;
      } general;
    };
    size_t sstatus;
    size_t sepc;
  } tf;
};

#endif