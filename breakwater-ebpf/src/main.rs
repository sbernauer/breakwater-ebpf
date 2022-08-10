use aya::{include_bytes_aligned, Bpf, util::nr_cpus};
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, LevelFilter};
use rlimit::{getrlimit, Resource};
use simplelog::{TermLogger, ConfigBuilder, ColorChoice, TerminalMode};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Info,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let nr_cpus = nr_cpus()?;
    info!("System has {nr_cpus} cores");
    let current_memlock_limits = getrlimit(Resource::MEMLOCK)?;
    info!("Current locked memory limits: {current_memlock_limits:?}");

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/breakwater-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/breakwater-ebpf"
    ))?;
    BpfLogger::init(&mut bpf)?;
    let program: &mut Xdp = bpf.program_mut("breakwater_ebpf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
