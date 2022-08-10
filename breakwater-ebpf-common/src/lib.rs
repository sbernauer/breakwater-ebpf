#![no_std]

pub const WIDTH: u16 = 1920;
pub const HEIGHT: u16 = 1080;

// We need to split the Framebuffer in chunks otherwise we get
// * In case of a Array: A StackOverflow when reading the data in userspace
// * In case of a PerCpuArray: The maximum allowed value size is 8192 u32s (32768 bytes)
// We try to make the chunks as large as possible to avoid syscalls when reading the maps from userspace
pub const FRAMEBUFFER_CHUNK_SIZE: u16 = 8192;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FramebufferChunk {
    pub pixels: [u32; FRAMEBUFFER_CHUNK_SIZE as usize],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FramebufferChunk {}
