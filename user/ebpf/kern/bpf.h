#pragma once

typedef long long i64;
typedef unsigned long long u64;

static void (*bpf_print_str)(const char *s, int len) = (void*) 9;
static int (*__bpf_trace_printk)(const char *fmt, int fmt_size, long p1, long p2, long p3) = (void*) 6;
static void* (*bpf_map_lookup_elem)(int map_fd, const void *key, void *value) = (void*) 1;
static int (*bpf_map_update_elem)(int map_fd, const void *key, const void *value, u64 flags) = (void*) 2;
static u64 (*bpf_ktime_get_ns)() = (void*) 5;
static int (*bpf_get_smp_processor_id)() = (void*) 8;
static i64 (*bpf_get_current_pid_tgid)() = (void*) 14;
static int (*bpf_get_current_comm)(char *buf, int max_size) = (void*) 16;

#define bpf_trace_printk(fmt, p1, p2, p3) do { \
    const char _fmt[] = fmt; \
    __bpf_trace_printk(_fmt, sizeof(_fmt), p1, p2, p3); \
} while (0)

#define bpf_trace_print_str(s, len) __bpf_trace_printk(s, len, 0, 0, 0)
#define bpf_trace_puts(s) bpf_trace_printk(s, 0, 0, 0)
