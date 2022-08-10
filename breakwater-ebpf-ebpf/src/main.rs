#![no_std]
#![no_main]

mod bindings;
mod helpers;

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use breakwater_ebpf_common::{Framebuffer, FRAMEBUFFER_CHUNK_SIZE_BYTES, HEIGHT, WIDTH};
use helpers::{ptr_at, ETH_P_IP4, ETH_P_IP6};
use memoffset::offset_of;

use crate::bindings::ethhdr;

#[map(name = "FRAMEBUFFER")]
static mut FRAMEBUFFER: PerCpuArray<Framebuffer> = PerCpuArray::<_>::with_max_entries(
    WIDTH as u32 * HEIGHT as u32 / FRAMEBUFFER_CHUNK_SIZE_BYTES as u32 + 1,
    0,
);

#[xdp(name = "breakwater_ebpf")]
pub fn breakwater_ebpf(ctx: XdpContext) -> u32 {
    match try_breakwater_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_breakwater_ebpf(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(unsafe {
        *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? //
    });
    if h_proto == ETH_P_IP4 {
        info!(&ctx, "received IPv4 packet");
    } else if h_proto == ETH_P_IP6 {
        info!(&ctx, "received IPv6 packet");
    }

    set_pixel(0, 0, 0xffff_ffff);
    set_pixel(1, 0, 0x1234_5678);

    Ok(xdp_action::XDP_PASS)
}

/// TODO: Don't use this function as it's slow.
/// Instead set the pixels from the main loop and do some efficient update
#[inline]
fn set_pixel(x: u16, y: u16, rgb: u32) {
    let pixel_index = x + y * WIDTH;
    let chunk = pixel_index / FRAMEBUFFER_CHUNK_SIZE_BYTES;
    unsafe {
        if let Some(chunk) = FRAMEBUFFER.get_ptr_mut(chunk as u32) {
            let pixel_index_within_chunk = pixel_index % FRAMEBUFFER_CHUNK_SIZE_BYTES;
            (*chunk).pixels[pixel_index_within_chunk as usize] = rgb;
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
