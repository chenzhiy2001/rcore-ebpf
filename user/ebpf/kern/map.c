#include "bpf.h"

extern int map_fd;

int foo() {
  bpf_trace_printk("enter map.o!\n", 0, 0, 0);
  bpf_trace_printk("map fd {}\n", map_fd, 0, 0);
  int key, old_value, new_value;
  key = 0;
  bpf_map_lookup_elem(map_fd, &key, &old_value);
  new_value = old_value + 1;

  bpf_map_update_elem(map_fd, &key, &new_value, 0);
  bpf_trace_printk("inc value from {} to {}\n", old_value, new_value, 0);

  return 1;
}
