use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=./spqlios");

    let cmake_loc = cmake::Config::new("./spqlios")
        .define("ENABLE_TESTING", "OFF")
        .build();

    println!(
        "cargo::rustc-link-search={}",
        cmake_loc.join("lib").to_string_lossy()
    );
    println!("cargo::rustc-link-lib=spqlios");

    let bindings = bindgen::builder()
        .header("bindgen.h")
        .clang_arg(format!("-I{}", cmake_loc.join("include").to_string_lossy()))
        .generate()
        .unwrap();

    let outdir = std::env::var("OUT_DIR").unwrap();

    bindings
        .write_to_file(PathBuf::from(outdir).join("bindings.rs"))
        .unwrap();
}
