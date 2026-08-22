//! ebpf-loader/src/main.rs
//! لودر فایروال با قابلیت Pinning جداول در BPF Filesystem.

use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::{debug, warn};
use std::fs;
use std::path::Path;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,

    #[clap(short, long)]
    skb: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kernel-space"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let bpffs_dir = Path::new("/sys/fs/bpf/ai_ida");
    let _ = fs::create_dir_all(bpffs_dir);

    if let Some(map) = ebpf.map_mut("REPUTATION_MAP") {
        let path = bpffs_dir.join("reputation_map");
        let _ = fs::remove_file(&path);
        let _ = map.pin(&path);
    }
    if let Some(map) = ebpf.map_mut("PORT_GATE_MAP") {
        let path = bpffs_dir.join("port_gate_map");
        let _ = fs::remove_file(&path);
        let _ = map.pin(&path);
    }
    if let Some(map) = ebpf.map_mut("RATE_LIMIT_MAP") {
        let path = bpffs_dir.join("rate_limit_map");
        let _ = fs::remove_file(&path);
        let _ = map.pin(&path);
    }

    let Opt { iface, skb } = opt;

    let program: &mut Xdp = ebpf
        .program_mut("ai_ida_firewall")
        .context("failed to find eBPF program 'ai_ida_firewall'")?
        .try_into()?;

    program.load()?;

    let flags = if skb || iface == "lo" {
        XdpFlags::SKB_MODE
    } else {
        XdpFlags::default()
    };

    program
        .attach(&iface, flags)
        .context("failed to attach the XDP program to network interface")?;

    println!("===========================================================");
    println!("🛡️  AI-IDA Kernel Firewall Subsystem (Phase 2 Active)");
    println!("📡 Attached to interface: '{}' with flags: {:?}", iface, flags);
    println!("📌 Pinned BPF Maps to /sys/fs/bpf/ai_ida/");
    println!("⚡ Line-rate Data Plane is enforcing RFC & Static rules");
    println!("🛑 Press Ctrl-C to detach and exit");
    println!("===========================================================");

    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    
    // cleanup: detach the XDP program and remove pinned maps
    let _ = fs::remove_dir_all(bpffs_dir);
    println!("\n[AI-IDA] Safely detached from network stack. Exiting...");

    Ok(())
}