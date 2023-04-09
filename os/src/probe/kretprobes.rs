use lock::Mutex;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use lazy_static::*;

use super::arch::{
    alloc_breakpoint, free_breakpoint, get_trapframe_pc, get_trapframe_ra, set_trapframe_pc,
    set_trapframe_ra,
};
use super::kprobes::{register_kprobe, unregister_kprobe, Handler};
use super::{KProbeArgs, KRetProbeArgs, TrapFrame};

/// instances: the function is entered but has not returned, leaving the probe hanging
/// instance_limit: the maximum number of instances allowed, limits probing of recursive functions
/// misses: the number of times the instance limit was reached and retprobe was not executed
struct KRetProbe {
    entry_handler: Option<Arc<Handler>>,
    exit_handler: Arc<Handler>,
    instance_limit: usize,
    user_data: usize,
    nr_instances: usize,
    nr_misses: usize,
}

struct KRetProbeInstance {
    pub entry_addr: usize, // used to obtain associated KRetProbe
    pub ret_addr: usize,
}

lazy_static! {
    /// address -> KRetProbe instance
    static ref KRETPROBES: Mutex<BTreeMap<usize, KRetProbe>> = Mutex::new(BTreeMap::new());
    /// breakpoint addr -> (pc, ra) in original trapframe
    /// the breakpoint is in a trampoline area, where every ebreak is associated with a kretprobe instance
    /// pc is used to obtain associated KRetProbe from the above map
    /// ra is used to restore the original trapframe since it is modified to execute post_handler
    static ref INSTANCES: Mutex<BTreeMap<usize, KRetProbeInstance>> = Mutex::new(BTreeMap::new());
}

impl KRetProbe {
    pub fn new(
        exit_handler: Arc<Handler>,
        entry_handler: Option<Arc<Handler>>,
        limit: Option<usize>,
        user_data: usize,
    ) -> Self {
        let instance_limit = limit.unwrap_or(usize::max_value());
        Self {
            entry_handler,
            exit_handler,
            instance_limit,
            user_data,
            nr_instances: 0,
            nr_misses: 0,
        }
    }
}

impl KRetProbeInstance {
    pub fn new(entry_addr: usize, ret_addr: usize) -> Self {
        Self {
            entry_addr,
            ret_addr,
        }
    }
}

/// a kretprobe is registered by registering a kprobe with this as the handler
/// executes pre_handler like kprobe, then changes ra to a breakpoint trampoline to execute exit_handler in kretprobe
/// meanwhile saves pc and ra in INSTANCES to restore trapframe later
fn kretprobe_kprobe_pre_handler(tf: &mut TrapFrame, _data: usize) -> isize {
    let pc = get_trapframe_pc(tf);
    let mut kretprobes = KRETPROBES.lock();
    let probe = kretprobes.get_mut(&pc).unwrap();
    if probe.nr_instances >= probe.instance_limit {
        probe.nr_misses += 1;
        return 0;
    }

    probe.nr_instances += 1;
    if let Some(handler) = &probe.entry_handler {
        let _ = handler(tf, probe.user_data);
    }

    let ra = get_trapframe_ra(tf);
    let instance = KRetProbeInstance::new(pc, ra);
    let bp_addr = alloc_breakpoint();
    // save pc and ra to restore trapframe later
    INSTANCES.lock().insert(bp_addr, instance);
    set_trapframe_ra(tf, bp_addr);
    0
}

/// this will be called when the breakpoint in the trampoline area is hit
/// restores trapframe and executes exit_handler
pub fn kretprobe_trap_handler(tf: &mut TrapFrame) -> bool {
    // lock KRETPROBES first to avoid dead lock
    let mut kretprobes = KRETPROBES.lock();

    let pc = get_trapframe_pc(tf);
    let mut instance_map = INSTANCES.lock();
    let instance = instance_map.get(&pc).unwrap();

    let probe = kretprobes.get_mut(&instance.entry_addr).unwrap();
    let _ = (probe.exit_handler)(tf, probe.user_data);
    probe.nr_instances -= 1;

    let ra = instance.ret_addr;
    set_trapframe_pc(tf, ra);
    set_trapframe_ra(tf, ra);
    free_breakpoint(pc);
    instance_map.remove(&pc).unwrap();
    true
}

/// register a kretprobe by registering a kprobe with kretprobe_kprobe_pre_handler as the handler
pub fn register_kretprobe(entry_addr: usize, args: KRetProbeArgs) -> bool {
    if !register_kprobe(entry_addr, KProbeArgs::from(kretprobe_kprobe_pre_handler)) {
        return false;
    }

    let probe = KRetProbe::new(
        args.exit_handler,
        args.entry_handler,
        args.limit,
        args.user_data,
    );
    KRETPROBES.lock().insert(entry_addr, probe);
    true
}

pub fn unregister_kretprobe(entry_addr: usize) -> bool {
    let mut kretprobes = KRETPROBES.lock();
    if let Some(probe) = kretprobes.get(&entry_addr) {
        if probe.nr_instances > 0 {
            false
        } else {
            let ok = unregister_kprobe(entry_addr);
            if ok {
                kretprobes.remove(&entry_addr).unwrap();
            }
            ok
        }
    } else {
        false
    }
}

use super::osutils::symbol_to_addr;
pub fn register_kretprobe_with_symbol(symbol: &str, args: KRetProbeArgs) -> bool {
    if let Some(addr) = symbol_to_addr(symbol) {
        register_kretprobe(addr, args)
    } else {
        false
    }
}

pub fn unregister_kretprobe_with_symbol(symbol: &str) -> bool {
    if let Some(addr) = symbol_to_addr(symbol) {
        unregister_kretprobe(addr)
    } else {
        false
    }
}
