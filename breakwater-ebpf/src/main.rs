#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext, maps::Array,
};
use aya_log_ebpf::info;
use breakwater_common::{SCREEN_WIDTH, SCREEN_HEIGHT};

#[map(name = "FRAMEBUFFER")]
static mut FB: Array<u32> = Array::with_max_entries(SCREEN_WIDTH * SCREEN_HEIGHT, 0);

#[xdp(name="breakwater")]
pub fn breakwater(ctx: XdpContext) -> u32 {
    match unsafe { try_breakwater(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_breakwater(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
