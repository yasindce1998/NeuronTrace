use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let stub_path = out_dir.join("neurontrace-ebpf");

    if !stub_path.exists() {
        fs::write(&stub_path, [0x7f, 0x45, 0x4c, 0x46]).unwrap();
    }

    println!("cargo::rerun-if-changed=build.rs");
}
