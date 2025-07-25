use std::{
    path::{Path, PathBuf},
    process::Output,
};

#[allow(unused)]
fn validate_command_output(output: Output, panic_msg: &str) {
    println!("===stderr===");
    println!("{}", String::from_utf8_lossy(&output.stderr));

    println!("===stdout===");
    println!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.status.success() {
        panic!("{}", panic_msg);
    }
}

#[allow(unused)]
fn recursive_files_by_extension(root: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files_with_extension = vec![];
    let file_entries = std::fs::read_dir(root).unwrap();

    for f in file_entries {
        let f = f.unwrap();

        if f.file_type().unwrap().is_dir() {
            let mut subdir_files = recursive_files_by_extension(&f.path(), extension);
            files_with_extension.append(&mut subdir_files);
        } else if f.file_name().to_str().unwrap().ends_with(extension) {
            files_with_extension.push(f.path());
        }
    }

    files_with_extension
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

    let shaders_dir = PathBuf::from(".").join("gpu_src");

    let cu_files = recursive_files_by_extension(&shaders_dir, ".cu");

    let nvcc = cuda_root.join("bin").join("nvcc");
    let nvlink = cuda_root.join("bin").join("nvlink");

    println!("cargo:rerun-if-changed=gpu_src");

    for config in ["test", "release"] {
        let mut ptx_files = vec![];

        for src_file in cu_files.iter() {
            let dst_dir = outdir.join(src_file.parent().unwrap());
            let filename = src_file.file_name().unwrap().to_string_lossy().into_owned();

            match std::fs::create_dir_all(&dst_dir) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("{}", e),
            }

            println!("Compiling {src_file:#?}...");

            let ptx_file = dst_dir.join(format!("{filename}.ptx"));

            let c = Command::new(&nvcc)
                .arg("-Werror")
                .arg("all-warnings")
                .arg("-I")
                .arg("src/cuda_impl/shaders/include")
                .arg("--ptx")
                .arg("--relocatable-device-code")
                .arg("true")
                .arg("--generate-line-info")
                .arg("-O4")
                .args(&gencode_flags)
                .arg("-D")
                .arg("CUDA_C")
                .arg("-D")
                .arg(config.to_uppercase())
                .arg("-o")
                .arg(&ptx_file)
                .arg(src_file)
                .output()
                .unwrap();

            ptx_files.push(ptx_file);

            validate_command_output(c, "nvcc compilation failed.");
        }

        let binary = outdir.join(format!("sunscreen_tfhe_gpu.{config}.fatbin"));

        let c = Command::new(&nvlink)
            .arg("--arch")
            .arg("sm_89")
            .arg("-o")
            .arg(&binary)
            .arg("--verbose")
            .args(ptx_files)
            .output()
            .unwrap();

        validate_command_output(c, "nvcc linking failed.");
    }
}

fn main() {
    #[cfg(feature = "cuda")]
    compile_as_cuda();
}
