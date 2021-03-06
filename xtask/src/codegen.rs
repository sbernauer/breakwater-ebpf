use aya_gen::btf_types;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("breakwater-ebpf/src");
    let names: Vec<&str> = vec!["ethhdr", "iphdr", "udphdr"];
    let bindings = btf_types::generate(Path::new("/sys/kernel/btf/vmlinux"), &names)?;
    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let mut out = File::create(dir.join("bindings.rs"))?;
    write!(out, "{}", bindings)?;
    Ok(())
}
