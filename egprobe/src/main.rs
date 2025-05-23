use aya::{maps::RingBuf, programs::UProbe};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

#[repr(C)]
struct Event {
    pid: u32,
    len: u32,
    data: [u8; 256],
}

fn to_ascii_printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (32..=126).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/egprobe"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let Opt { pid } = opt;
    let program: &mut UProbe = ebpf.program_mut("egprobe").unwrap().try_into()?;
    program.load()?;
    program.attach(
        Some("SSL_write"),
        0,
        "/lib/x86_64-linux-gnu/libssl.so.3",
        None,
    )?;

    let mut rbuf = RingBuf::try_from(ebpf.map_mut("SSL_RING").unwrap()).unwrap();
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Ctrl-C received, exiting loop.");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {
                if let Some(entry) = rbuf.next() {
                    let event: &Event = unsafe { &*(entry.as_ptr() as *const Event) };
                    let len = event.len as usize;
                    let data = &event.data[..len.min(event.data.len())];
                    println!("Received SSL_write data: {}", to_ascii_printable(data));
                }
            }
        }
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    Ok(())
}
