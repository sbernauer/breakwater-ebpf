#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action::{XDP_PASS, XDP_ABORTED},
    macros::{xdp, map},
    programs::XdpContext, maps::Array,
};
// use aya_log_ebpf::info;
use breakwater_common::{SCREEN_WIDTH, SCREEN_HEIGHT, PB_COMMAND_LENGTH};
use core::mem;
use memoffset::offset_of;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;
use bindings::{ethhdr, iphdr, udphdr};

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_P_UDP: u8 = 0x11;
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();
const UDP_MAX_DATAGRAM_SIZE: usize = 65_507;

#[map(name = "FRAMEBUFFER")]
static mut FRAMEBUFFER: Array<u32> = Array::with_max_entries(SCREEN_WIDTH * SCREEN_HEIGHT, 0);

#[xdp(name="breakwater")]
pub fn breakwater(ctx: XdpContext) -> u32 {
    match unsafe { try_breakwater(ctx) } {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

unsafe fn try_breakwater(ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "received a packet");

    // Ignore non-IP traffic
    let eth_proto = u16::from_be(*ptr_at(&ctx, offset_of!(ethhdr, h_proto))?);
    if eth_proto != ETH_P_IP {
        return Ok(XDP_PASS);
    }
    // We currently don't support IP options
    let ip_header_len = u8::from_be(*ptr_at(&ctx, ETH_HDR_LEN)?) & 0x0f; // We have to use offset and bitmask instead of `offset_of` as we miss the ihl from iphdr
    if ip_header_len != 5 { // Ip header must have length 5 (20 bytes)
        return Ok(XDP_PASS);
    }
    // Ignore non-UDP traffic
    let ip_proto = u8::from_be(*ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))?);
    if ip_proto != IP_P_UDP {
        return Ok(XDP_PASS);
    }
    // info!(&ctx, "It was a UDP packet");
    // Ignore traffic send to port other than 1234
    let udp_dest_port = u16::from_be(*ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest))?);
    if udp_dest_port != 1234 {
        return Ok(XDP_PASS);
    }
    // info!(&ctx, "It was a UDP packet to port 1234");

    let udp_start = ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    // let ip_saddr = u32::from_be(*ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?);

    let mut i = udp_start;
    for _ in 0..UDP_MAX_DATAGRAM_SIZE / PB_COMMAND_LENGTH / 2 + 1 { // We need to unroll the loop for the ebpf verifier. With this we limit the loop to max N iterations
        if i + PB_COMMAND_LENGTH > ctx.data_end() {
            break;
        }

        if *(i as *const u8) == b'P' && *((i + 1) as *const u8) == b'B' {
            let x = u16::from_be(*((i + 2) as *const u16));
            let y = u16::from_be(*((i + 4) as *const u16));
            let rgb = u32::from_be(*((i + 5) as *const u32)) << 8;

            let fb_index = x as u32 + y as u32 * SCREEN_WIDTH;
            let _ = FRAMEBUFFER.set(fb_index, &rgb, 0);
        } else {
            break; // Got invalid input, skipping
        }


        i += PB_COMMAND_LENGTH;
    }

    Ok(XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
