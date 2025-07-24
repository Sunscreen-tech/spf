use std::{path::Path, process::Output};

fn validate_command_output(output: Output, panic_msg: &str) {
    println!("===stderr===");
    println!("{}", String::from_utf8_lossy(&output.stderr));

    println!("===stdout===");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.status.success() {
        panic!("{}", panic_msg);
    }
}

#[cfg(feature = "cuda")]
fn compile_as_cuda() {
    const ARCH: &[&str] = &[
        "sm_89", "sm_90", "sm_90a", "sm_100", "sm_100a", "sm_101", "sm_101a", "sm_120", "sm_120a",
    ];

    let gencode_flags = ARCH
        .iter()
        .flat_map(|x| {
            [
                "--generate-code".to_owned(),
                format!("arch=compute_89,code={x}"),
            ]
        })
        .collect::<Vec<_>>();

    use std::{path::PathBuf, process::Command};

    use find_cuda_helper::find_cuda_root;

    let outdir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let cuda_root = find_cuda_root().unwrap();

    let nvcc = cuda_root.join("bin").join("nvcc");

    println!("cargo:rerun-if-changed=gpu_src");

    let src_file = Path::new(".").join("gpu_src").join("main.cu");

    for config in ["test", "release"] {
        let binary = outdir.join(format!("sunscreen_gpu_runtime.{config}.fatbin"));
        let dst_dir = outdir.join(src_file.parent().unwrap());

        match std::fs::create_dir_all(&dst_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("{}", e),
        }

        println!("Compiling {:#?}...", src_file);

        let c = Command::new(&nvcc)
            .arg("-Werror")
            .arg("all-warnings")
            .arg("-c")
            .arg("--relocatable-device-code")
            .arg("true")
            .arg("--generate-line-info")
            .arg("-O4")
            .args(&gencode_flags)
            .args(["--generate-code", "arch=compute_75,code=sm_75"])
            .arg("-D")
            .arg(config.to_uppercase())
            .arg("--fatbin")
            .arg("-o")
            .arg(&binary)
            .arg(&src_file)
            .output()
            .unwrap();

        validate_command_output(c, "nvcc compilation failed.");
    }
}

fn main() {
    #[cfg(feature = "cuda")]
    compile_as_cuda();
}
