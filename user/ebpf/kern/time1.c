#include "bpf.h"

extern int time_counters;

int main()
{    
    int cpu = bpf_get_smp_processor_id();
    u64 t1 = bpf_ktime_get_ns();
    bpf_map_update_elem(time_counters, &cpu, &t1, 0);
    return 0;
}
