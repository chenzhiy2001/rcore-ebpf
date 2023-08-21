//! eBPF tracepoints
//!
//! attach a program to hookpoints
//!
//! currently we only support Kprobe and Uprobe_syncfunc

use crate::probe::{arch::trapframe::TrapFrame, kprobes::unregister_kprobe};
use alloc::string::{ToString, String};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{collections::BTreeMap, vec};
use lazy_static::lazy_static;
use ruprobes::{uprobe_register, ProbePlace, ProbeType}; //todo where is unregister?
use spin::Mutex as spin_Mutex;

use lock::Mutex;
use trapframe::{TrapFrame as UprobeCrateTrapframe, UserContext,GeneralRegs};

use super::{
    retcode::BpfErrorCode::{self, *},
    retcode::*,
    BpfObject::*,
    *,
};
use crate::probe::{register_kprobe, register_kretprobe, KProbeArgs, KRetProbeArgs};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KprobeAttachAttr {
    /// kernel hookpoint symbol name
    pub target: *const u8,
    pub str_len: u32,
    pub prog_fd: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TracepointType {
    //  = ProbType + ProbePlace in rCore-ebpf
    KProbe,
    KRetProbeEntry,
    KRetProbeExit,
    UProbe_Insn,
    URetProbeEntry_Insn, //javascript-level long names :(
    URetProbeExit_Insn,
    UProbe_SyncFunc,
    URetProbeEntry_SyncFunc,
    URetProbeExit_SyncFunc,
}

use TracepointType::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// tracepoint abstraction, currently only for Kprobe
pub struct Tracepoint {
    pub tp_type: TracepointType,
    /// Kprobe attach address
    pub token: usize,
}

impl Tracepoint {
    pub fn new(tp_type: TracepointType, token: usize) -> Self {
        Self { tp_type, token }
    }
}

lazy_static! {
    static ref ATTACHED_PROGS: Mutex<BTreeMap<Tracepoint, Vec<Arc<BpfProgram>>>> =
        Mutex::new(BTreeMap::new());
}

/// # run attached programs
/// run all programs that attached to that tracepoint
/// # arguments
/// * tracepoint - tracepoint that is triggered
/// * ctx - the current context infomation
/// # prodecure
/// * get the bpf program object by tracepoint.token
/// * run them one by one, order is preserved
fn run_attached_programs(tracepoint: &Tracepoint, ctx: *const u8) {
    let map = ATTACHED_PROGS.lock();
    let programs = map.get(tracepoint).unwrap();
    for program in programs {
        let _result = program.run(ctx);
        // error!("run resultadr: {}", result);
    }
}

#[repr(C)]
/// kProbe context are just registers, or Trapframe
struct KProbeBPFContext {
    ptype: usize,
    paddr: usize,
    tf: TrapFrame,
}

impl KProbeBPFContext {
    pub fn new(tf: &TrapFrame, probed_addr: usize, t: usize) -> Self {
        KProbeBPFContext {
            ptype: t,
            paddr: probed_addr,
            tf: tf.clone(),
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        unsafe { core::mem::transmute(self) }
    }
}

#[repr(C)]
/// uProbe context are just registers, or Trapframe
struct UProbeBPFContext {
    ptype: usize,//0 is syncfunc
    paddr: usize,
    tf: TrapFrame,
}

impl UProbeBPFContext {
    pub fn new(tf: &TrapFrame, probed_addr: usize, t: usize) -> Self {
        UProbeBPFContext {
            ptype: t,
            paddr: probed_addr,
            tf: tf.clone(),
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        unsafe { core::mem::transmute(self) }
    }
}

/// the handler function that passed to register kprobe
fn kprobe_handler(tf: &mut TrapFrame, probed_addr: usize) -> isize {
    let tracepoint: Tracepoint = Tracepoint::new(KProbe, probed_addr);
    let ctx = KProbeBPFContext::new(tf, probed_addr, 0);
    info!("run attached progs!");
    run_attached_programs(&tracepoint, ctx.as_ptr());
    info!("run attached progs exit!");

    0
}


fn uprobe_syncfunc_handler(tf: &mut trap_context_riscv::TrapContext, probed_addr: usize) {//tag: uprobe_handler
    let tracepoint:Tracepoint=Tracepoint::new(UProbe_SyncFunc, probed_addr);
    let ctx: UProbeBPFContext = UProbeBPFContext::new(&tf,probed_addr,0);
    info!("run attached progs in uprobe_syncfunc_handler!");
    run_attached_programs(&tracepoint, ctx.as_ptr());
    info!("run attached progs in uprobe_syncfunc_handler exit!");
}


 pub fn nonsense<T:Sized>(cx:&T){//cx: &mut UserContext
    //println!("I'm handler! I'm useless!");
    // println!{"pre_handler: spec:{:#x}", cx.sepc};
}

// /// trapframe and usercontext are basically the same, 
// /// but trapframe is used in OS while usercontext is used in uprobe crate
// fn trapframe_to_usercontext (cx:&mut TrapFrame)->UserContext{
//     UserContext { general: 
//         GeneralRegs {
//             zero:cx.x[0],
//             ra:cx.x[1],
//             sp:  cx.x[2],
//             gp:  cx.x[3],
//             tp:  cx.x[4],
//             t0:  cx.x[5],
//             t1:  cx.x[6],
//             t2:  cx.x[7],
//             s0:  cx.x[8],
//             s1:  cx.x[9],
//             a0:  cx.x[10],
//             a1:  cx.x[11],
//             a2:  cx.x[12],
//             a3:  cx.x[13],
//             a4:  cx.x[14],
//             a5:  cx.x[15],
//             a6:  cx.x[16],
//             a7:  cx.x[17],
//             s2:  cx.x[18],
//             s3:  cx.x[19],
//             s4:  cx.x[20],
//             s5:  cx.x[21],
//             s6:  cx.x[22],
//             s7:  cx.x[23],
//             s8:  cx.x[24],
//             s9:  cx.x[25],
//             s10:  cx.x[26],
//             s11:  cx.x[27],
//             t3:  cx.x[28],
//             t4:  cx.x[29],
//             t5:  cx.x[30],
//             t6:  cx.x[31],
//     }, sstatus: cx.sstatus.bits(), sepc: cx.sepc }
// }

/// unused
fn kretprobe_entry_handler(tf: &mut TrapFrame, probed_addr: usize) -> isize {
    let tracepoint = Tracepoint::new(KRetProbeEntry, probed_addr);
    let ctx = KProbeBPFContext::new(tf, probed_addr, 1);
    run_attached_programs(&tracepoint, ctx.as_ptr());
    0
}

/// unused
fn kretprobe_exit_handler(tf: &mut TrapFrame, probed_addr: usize) -> isize {
    let tracepoint = Tracepoint::new(KRetProbeExit, probed_addr);
    let ctx = KProbeBPFContext::new(tf, probed_addr, 2);
    run_attached_programs(&tracepoint, ctx.as_ptr());
    0
}

/// since rCore does not support symbol table
/// we hardcode attached function to syscall::fs::sys_open
fn resolve_symbol(symbol: &str) -> Option<usize> {
    //addr = 0x0000000080207b4a
    //panic!("resolve symbol need hardcoded symbol")
    //symbol_to_addr(symbol)
    Some(crate::syscall::fs::sys_open as usize)
}
/// parse tracepoint types
fn parse_tracepoint<'a>(
    target: &'a str,
) -> Result<(TracepointType, String, Option<String>), BpfErrorCode> {
    // in rCore-Tutorial we put name2addr outside of OS. so
    // fn_name is actually just a string of address like "0x80200000"
    // but in future we may consider put name2addr back to kernel, so 
    // we don't change fn_name variable name here.
    let fn_name_not_exist_msg = "FN_NAME_NOT_EXIST_MSG".to_string();
    let parts: Vec<String> = target.split("$").map(|s| s.to_string()).collect();
    let how_many_parts = parts.len();
    let type_str = &parts[0];
    let fn_name = if how_many_parts == 2 {
        &parts[1]
    } else if how_many_parts == 3 {
        &parts[2]
    } else {
        &fn_name_not_exist_msg
    };
    let user_program_path_not_exist_msg: String = "USER_PROGRAM_PATH_NOT_EXIST".to_string();
    let user_program_path = if how_many_parts == 3 { &parts[1] } else { &user_program_path_not_exist_msg };
    // let pos = target.find('$').ok_or(EINVAL)?;
    // let type_str = &target[0..pos];
    // let fn_name = &target[(pos + 1)..];

    // determine tracepoint type
    let tp_type: TracepointType;
    if type_str.eq_ignore_ascii_case("kprobe") {
        tp_type = KProbe;
    } else if type_str.eq_ignore_ascii_case("kretprobe@entry") {
        tp_type = KRetProbeEntry;
    } else if type_str.eq_ignore_ascii_case("kretprobe@exit") {
        tp_type = KRetProbeExit;
    } else if type_str.eq_ignore_ascii_case("uprobe_insn") {
        //this solution is ugly but works. maybe we can find better solutions later.
        tp_type = UProbe_Insn;
    } else if type_str.eq_ignore_ascii_case("uretprobe_insn@entry") {
        tp_type = URetProbeEntry_Insn;
    } else if type_str.eq_ignore_ascii_case("uretprobe_insn@exit") {
        tp_type = URetProbeExit_Insn;
    } else if type_str.eq_ignore_ascii_case("uprobe_syncfunc") {
        tp_type = UProbe_SyncFunc;
    } else if type_str.eq_ignore_ascii_case("uretprobe_syncfunc@entry") {
        tp_type = URetProbeEntry_SyncFunc;
    } else if type_str.eq_ignore_ascii_case("uretprobe_syncfunc@exit") {
        tp_type = URetProbeExit_SyncFunc;
    } else {
        return Err(EINVAL);
    }
    let return_ty_type = tp_type;
    let return_fn_name = fn_name.clone();
    let return_user_program_path = user_program_path.clone();
    Ok((return_ty_type, return_fn_name, Some(return_user_program_path)))
}

/// # bpf_program_attach
/// attach a program to a hookpoint
/// # arguments
/// * target - a str that represents hookpoint symbol
/// * prog_fd - the fd of the bpf program
/// # prodecure
/// * get the bpf program object by prog_fd
/// * get the tracepoint by target name
/// * add program to tracepoint handlers
///  if it is the first time a program is attached to, register the kprobe
/// # return value
/// * OK(0) on success
pub fn bpf_program_attach(target: &str, prog_fd: u32) -> BpfResult {
    // check program fd
    let program = {
        let objs = BPF_OBJECTS.lock();

        match objs.get(&prog_fd) {
            Some(bpf_obj) => {
                let shared_program = bpf_obj.is_program().unwrap();
                Ok(shared_program.clone())
            }
            _ => Err(ENOENT),
        }
    }?;
    let (tp_type, addr_string, user_program_path) = parse_tracepoint(target)?;
    //let addr = resolve_symbol(&fn_name).ok_or(ENOENT)?;
    debug!("addr string is {:?}", addr_string);
    let addr:usize = usize::from_str_radix(&addr_string[2..], 16).unwrap();
    //let addr = addr_string.parse::<usize>().unwrap();

    let tracepoint = Tracepoint::new(tp_type, addr);

    let mut map = ATTACHED_PROGS.lock();
    if let Some(programs) = map.get_mut(&tracepoint) {
        for other_prog in programs.iter() {
            if Arc::ptr_eq(&program, other_prog) {
                return Err(EAGAIN);
            }
        }
        programs.push(program);
    } else {
        match tp_type {
            KProbe => {
                let args = KProbeArgs {
                    pre_handler: Arc::new(kprobe_handler),
                    post_handler: None,
                    user_data: addr,
                };
                let _ = register_kprobe(addr, args).ok_or(EINVAL)?;
                map.insert(tracepoint, vec![program]);
            }
            KRetProbeEntry | KRetProbeExit => {
                let args = KRetProbeArgs {
                    exit_handler: Arc::new(kretprobe_exit_handler),
                    entry_handler: Some(Arc::new(kretprobe_entry_handler)),
                    limit: None,
                    user_data: addr,
                };
                let _ = register_kretprobe(addr, args).ok_or(EINVAL)?;

                let dual_tp: Tracepoint;
                if tp_type == KRetProbeEntry {
                    dual_tp = Tracepoint::new(KRetProbeExit, addr);
                } else {
                    dual_tp = Tracepoint::new(KRetProbeEntry, addr);
                }
                map.insert(tracepoint, vec![program]);
                map.insert(dual_tp, vec![]);
            }
            UProbe_Insn => todo!(),
            URetProbeEntry_Insn => todo!(),
            URetProbeExit_Insn => todo!(),
            UProbe_SyncFunc => { //tag: uprobe_handler
                uprobe_register(user_program_path.unwrap().to_string(), addr,  Arc::new(spin_Mutex::new(uprobe_syncfunc_handler)),None, ruprobes::ProbeType::SyncFunc);  
                map.insert(tracepoint, vec![program]);
            }
            URetProbeEntry_SyncFunc => todo!(),
            URetProbeExit_SyncFunc => todo!(),
        }
    }
    // trace!(
    //     "bpf prog attached! tracepoint symbol:{} addr: {:x}",
    //     fn_name,
    //     addr
    // );
    trace!(
        "bpf prog attached! tracepoint addr: {:x}",
        addr
    );
    Ok(0)
}

/// # bpf_program_detach
/// detach a program from hookpoint
/// # arguments
/// * prog_fd - the fd of the bpf program
/// # prodecure
/// * get the bpf program object by prog_fd
/// * remove program from tracepoint handlers
/// # return value
/// * OK(0) on success
pub fn bpf_program_detach(prog_fd: u32) -> BpfResult {
    if let Some(prog) = bpf_object_remove(prog_fd) {
        let prog = prog.is_program().unwrap();
        let mut map = ATTACHED_PROGS.lock();
        let mut t = Tracepoint::new(TracepointType::KProbe, 0);
        let mut id = 0;
        for (k, v) in map.iter() {
            let mut find = false;
            for (i, p) in v.iter().enumerate() {
                if Arc::ptr_eq(p, &prog) {
                    t = k.clone();
                    id = i;
                    find = true;
                }
            }
            if find {
                break;
            }
        }
        let v = map.get_mut(&t).unwrap();
        v.remove(id);
        //unregister_kprobe(t.token);
        Ok(0)
    } else {
        Err(ENOENT)
    }
}
