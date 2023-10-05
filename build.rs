use std::fs::create_dir_all;
use std::path::Path;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "./src/bpf/ifunc.bpf.c";

fn main() {
    create_dir_all("./src/bpf/.output").unwrap();
    let path = Path::new("./src/bpf/.output/ifunc.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(path)
        .expect("bpf compile failed");
    println!("cargo:return-if-changed={}", SRC);
}
