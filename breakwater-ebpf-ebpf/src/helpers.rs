use aya_bpf::programs::XdpContext;
use core::mem;

pub const ETH_P_IP4: u16 = 0x0800;
pub const ETH_P_IP6: u16 = 0x86dd;

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
