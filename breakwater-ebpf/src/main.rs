use std::time::Duration;

use anyhow::Context;
use aya::maps::PerCpuArray;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, util::nr_cpus, Bpf};
use aya_log::BpfLogger;
use breakwater_ebpf_common::{Framebuffer, FRAMEBUFFER_CHUNK_SIZE_BYTES};
use clap::Parser;
use log::{info, LevelFilter};
use rlimit::{getrlimit, Resource};
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    assert_eq!(
        FRAMEBUFFER_CHUNK_SIZE_BYTES % 4,
        0,
        "The value of FRAMEBUFFER_CHUNK_SIZE_BYTES must be a multiple of 4 as we are storing u32 in it"
    );

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

    let framebuffer_map: PerCpuArray<_, Framebuffer> =
        PerCpuArray::try_from(bpf.map_mut("FRAMEBUFFER")?)?;

    tokio::spawn(async move {
        loop {
            let framebuffer_chunks = framebuffer_map
                .get(&0, 0)
                .expect("Failed to get framebuffer chunk from ebpf map");
            framebuffer_chunks
                .iter()
                .enumerate()
                .for_each(|(cpu_id, framebuffer_chunk)| {
                    info!(
                        "Framebuffer from core {cpu_id} (first 10 bytes): {:?}",
                        &framebuffer_chunk.pixels[..10]
                    );
                });
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
