#[cfg(feature = "gpu")]
mod gpu {
    use std::{
        path::{Path, PathBuf},
        process::Output,
    };

    #[allow(unused)]
    pub fn validate_command_output(output: Output, panic_msg: &str) {
        println!("===stderr===");
        println!("{}", String::from_utf8_lossy(&output.stderr));

        println!("===stdout===");
        println!("{}", String::from_utf8_lossy(&output.stdout));
        if !output.status.success() {
            panic!("{}", panic_msg);
        }
    }

    #[allow(unused)]
    pub fn recursive_files_by_extension(root: &Path, extension: &str) -> Vec<PathBuf> {
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

    enum Precision {
        F32,
        F64,
    }

    fn gen_twiddles(file: &Path, precision: Precision) {
        use rug::Float;

        let mut lines = String::new();

        let (complex_ty, suffix, ty) = match precision {
            Precision::F32 => ("float2", "f", "F32"),
            Precision::F64 => ("double2", "", "F64"),
        };

        lines += "#pragma once\n\n";

        fn format_value(x: &Float, suffix: &'static str) -> String {
            if *x == 0.0 {
                format!("0.0{suffix}")
            } else {
                format!("{:<.50e}{suffix}", x.to_f64())
            }
        }

        for (dir_suffix, inv_val) in [("_", -2.0), ("_INV_", 2.0)] {
            lines += &format!("const __device__ {complex_ty} TWIDDLES{dir_suffix}{ty}[] = {{");

            for n in [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
                let n_float = rug::Float::with_val(256, n);

                for j in 0..n {
                    let x: Float = Float::with_val(256, inv_val) * j / n_float.clone();
                    let s = x.clone().sin_pi();
                    let c = x.clone().cos_pi();

                    lines += &format!(
                        "\n\t{{\n\t\t{},\n\t\t{}\n\t}}",
                        format_value(&c, suffix),
                        format_value(&s, suffix)
                    );

                    if !(n == 4096 && j == n - 1) {
                        lines += ","
                    }
                }
            }

            lines += "\n};\n";
        }

        let _ = std::fs::write(file, lines);
    }

    pub fn codegen() {
        let outdir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let codegen_dir = outdir.join("codegen");

        let _ = std::fs::create_dir(&codegen_dir);

        gen_twiddles(&codegen_dir.join("fft_constants_f32.cuh"), Precision::F32);
        gen_twiddles(&codegen_dir.join("fft_constants_f64.cuh"), Precision::F64);
    }
}

#[cfg(feature = "gpu")]
use gpu::*;

#[cfg(feature = "cuda")]
mod cuda {
    use std::path::Path;

    pub fn compile_as_cuda() {
        const ARCH: &[&str] = &[
            "sm_70", "sm_75", "sm_89", "sm_90", "sm_90a", "sm_100", "sm_100a", "sm_101", "sm_101a",
            "sm_120", "sm_120a",
        ];

        let gencode_flags = ARCH
            .iter()
            .flat_map(|x| {
                [
                    "--generate-code".to_owned(),
                    format!("arch=compute_70,code={x}"),
                ]
            })
            .collect::<Vec<_>>();

        use std::{path::PathBuf, process::Command};

        use find_cuda_helper::find_cuda_root;

        let outdir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let cuda_root = find_cuda_root().unwrap();

        let nvcc = cuda_root.join("bin").join("nvcc");

        let src_file = Path::new(".").join("gpu_src").join("main.cu");

        for config in ["test", "release"] {
            let binary = outdir.join(format!("sunscreen_tfhe_gpu.{config}.fatbin"));
            let dst_dir = outdir.join(src_file.parent().unwrap());

            match std::fs::create_dir_all(&dst_dir) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("{}", e),
            }

            println!("Compiling {src_file:#?}...");

            let c = Command::new(&nvcc)
                .arg("-Werror")
                .arg("all-warnings")
                .arg("--generate-line-info")
                .arg("--std=c++20")
                .arg("--expt-relaxed-constexpr")
                .arg("-O4")
                //.arg("--use_fast_math")
                .args(&gencode_flags)
                .arg("-I")
                .arg(outdir.join("codegen"))
                .arg("-D")
                .arg(config.to_uppercase())
                .arg("--fatbin")
                .arg("-o")
                .arg(&binary)
                .arg(&src_file)
                .output()
                .unwrap();

            super::validate_command_output(c, "nvcc compilation failed.");
        }
    }
}

#[cfg(feature = "cuda")]
use cuda::*;

fn main() {
    println!("cargo:rerun-if-changed=gpu_src");

    #[cfg(feature = "gpu")]
    codegen();

    #[cfg(feature = "cuda")]
    compile_as_cuda();
}
