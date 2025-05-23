#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

#[uprobe]
pub fn egprobe(ctx: ProbeContext) -> u32 {
    match try_egprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[repr(C)]
struct BufferInfo {
    buf: *const u8,
    len: u32,
}

#[map(name = "BUFFER_MAP")]
static mut BUFFER_MAP: HashMap<u32, BufferInfo> = HashMap::with_max_entries(1024, 0);

fn try_egprobe(ctx: ProbeContext) -> Result<u32, u32> {
    let tgid: u32 = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    let buf: *const u8 = ctx.arg(1).ok_or(0_u32)?;
    let len: u32 = ctx.arg(2).ok_or(0_u32)?;
    let info: BufferInfo = BufferInfo { buf, len };
    unsafe {
        BUFFER_MAP.insert(&tgid, &info, 0);
    }

    info!(&ctx, "function SSL_write called by libssl.so.3");
    Ok(0)
}

#[repr(C)]
struct Event {
    pid: u32,
    len: u32,
    data: [u8; 256],
}

#[map(name = "SSL_RING")]
static mut SSL_RING: RingBuf = RingBuf::with_byte_size(4096, 0);

#[uretprobe]
pub fn egprobe_ret(ctx: RetProbeContext) -> u32 {
    match try_egprobe_ret(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_egprobe_ret(ctx: RetProbeContext) -> Result<u32, u32> {
    let tgid: u32 = (bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    let ret_val: i64 = ctx.ret().ok_or(1u32)?;
    if ret_val <= 0 {
        unsafe {
            BUFFER_MAP.remove(&tgid);
        }
        return Ok(0);
    }
    let info: &BufferInfo = unsafe { BUFFER_MAP.get(&tgid).ok_or(1u32)? };

    let to_cp = if ret_val as u32 >= info.len {
        info.len
    } else {
        ret_val as u32
    };

    let mut ev = Event {
        pid: tgid,
        len: to_cp,
        data: [0u8; 256],
    };

    let copy_len = if to_cp as usize > ev.data.len() {
        ev.data.len()
    } else {
        to_cp as usize
    };

    unsafe {
        bpf_probe_read_user_str_bytes(info.buf, &mut ev.data[..copy_len]).map_err(|_| 1u32)?;
    }

    unsafe {
        SSL_RING.output(&ev, 0);
    }
    info!(&ctx, "PID :: {} :: LEN :: {}", ev.pid, ev.len);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
