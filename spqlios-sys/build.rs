use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=./spqlios");

    let cmake_loc = cmake::Config::new("./spqlios")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("ENABLE_TESTING", "OFF")
        .build();

    println!(
        "cargo::rustc-link-search=native={}",
        cmake_loc.join("lib").to_string_lossy()
    );
    println!("cargo::rustc-link-lib=static=spqlios");

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
