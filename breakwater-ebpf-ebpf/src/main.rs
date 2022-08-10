#![no_std]
#![no_main]

mod bindings;
mod helpers;

use aya_bpf::{
    bindings::xdp_action::{self, XDP_PASS},
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};

use breakwater_ebpf_common::{Framebuffer, FRAMEBUFFER_CHUNK_SIZE_BYTES, HEIGHT, WIDTH};
use helpers::{ptr_at, ETH_P_IP6};
use memoffset::offset_of;

use crate::{
    bindings::{ethhdr, ipv6hdr},
    helpers::ETH_HDR_LEN,
};

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
    if h_proto != ETH_P_IP6 {
        return Ok(XDP_PASS);
    }

    let x = u16::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, daddr) + 8)? });
    let y = u16::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, daddr) + 10)? });
    let rgba =
        u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, daddr) + 12)? });

    set_pixel(x, y, rgba);

    Ok(XDP_PASS)
}

/// Don't call this function multiple times per packet.
/// Instead set the pixels from the main loop and do some more efficient update.
/// It's ok to call this once [for every packet]
#[inline]
fn set_pixel(x: u16, y: u16, rgb: u32) {
    let pixel_index = x as u32 + y as u32 * WIDTH as u32;
    let chunk = pixel_index / FRAMEBUFFER_CHUNK_SIZE_BYTES as u32;
    unsafe {
        if let Some(chunk) = FRAMEBUFFER.get_ptr_mut(chunk) {
            let pixel_index_within_chunk = pixel_index % (FRAMEBUFFER_CHUNK_SIZE_BYTES / 4) as u32;
            (*chunk).pixels[pixel_index_within_chunk as usize] = rgb;
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
