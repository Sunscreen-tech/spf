use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub model_name: String,
    pub cpu_cores: u32,
    pub cpu_threads: u32,

    /// In GHz
    pub clock_speed: f32,

    /// Option in case on Mac the pmset command doesn't return the lowpowermode field
    pub low_power_mode: Option<bool>,
}

impl std::fmt::Display for CpuInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Model: {}\nCores: {}\nThreads: {}\nClock Speed: {} GHz",
            self.model_name, self.cpu_cores, self.cpu_threads, self.clock_speed
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub gpu_type: String,
    pub gpu_cores: u32,
    pub gpu_memory_gb: Option<f32>,
}

impl std::fmt::Display for GpuInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "GPU: {}\nCores: {:?}\nMemory: {:?}",
            self.gpu_type,
            self.gpu_cores,
            self.gpu_memory_gb
                .map(|gb| format!("{} GB", gb))
                .unwrap_or_else(|| "None".to_string())
        )
    }
}

#[cfg(target_os = "macos")]
fn get_gpu_info() -> Option<GpuInfo> {
    use std::process::Command;

    let output = Command::new("system_profiler")
        .arg("SPDisplaysDataType")
        .output()
        .ok()?;

    let output_str = String::from_utf8(output.stdout).ok()?;

    // Look for the core count line
    let gpu_cores = output_str
        .lines()
        .find(|line| line.trim().starts_with("Total Number of Cores:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|count| count.trim().parse().ok());

    // Get the GPU model
    let gpu_type = output_str
        .lines()
        .find(|line| line.contains("Chipset Model:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Apple Silicon GPU".to_string());

    Some(GpuInfo {
        gpu_type,
        gpu_cores: gpu_cores.unwrap(),
        gpu_memory_gb: None, // Shared with system memory
    })
}

#[cfg(not(target_os = "macos"))]
fn get_gpu_info() -> Option<GpuInfo> {
    use std::process::Command;

    // Try nvidia-smi for NVIDIA GPUs
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=gpu_name,memory.total,cuda_cores",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let info = String::from_utf8(output.stdout).ok()?;
        let parts: Vec<&str> = info.trim().split(',').collect();
        if parts.len() >= 3 {
            return Some(GpuInfo {
                gpu_type: parts[0].trim().to_string(),
                gpu_cores: parts[2].trim().parse().ok().unwrap(),
                gpu_memory_gb: parts[1].trim().parse::<f32>().ok().map(|mb| mb / 1024.0),
            });
        }
    }

    None
}

/// The purpose of this struct is so that when we run benchmarks we can record
/// the system information to not lose track of where the benchmarks were run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub instance_type: String,
    pub cpu_info: CpuInfo,
    pub gpu_info: Option<GpuInfo>,
    pub ram_gb: u64,
}

impl std::fmt::Display for SystemInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "## Instance Type\n{}\n\n### CPU Info\n{}\n\n### GPU Info\n{}\n\n### RAM\n{} GB",
            self.instance_type,
            self.cpu_info,
            self.gpu_info.as_ref().unwrap_or(&GpuInfo {
                gpu_type: "None".to_string(),
                gpu_cores: 0,
                gpu_memory_gb: None
            }),
            self.ram_gb
        )
    }
}

pub fn get_system_info() -> SystemInfo {
    if is_running_on_ec2() {
        get_ec2_info()
    } else {
        get_local_system_info()
    }
}

fn get_ec2_info() -> SystemInfo {
    let client = Client::new();

    // Get EC2 token
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .timeout(Duration::from_secs(1))
        .send()
        .unwrap()
        .text()
        .unwrap();

    // Get instance type
    let instance_type = client
        .get("http://169.254.169.254/latest/meta-data/instance-type")
        .header("X-aws-ec2-metadata-token", token)
        .timeout(Duration::from_secs(1))
        .send()
        .unwrap()
        .text()
        .unwrap();

    let sys = System::new_all();

    let cpu_info = CpuInfo {
        model_name: sys.cpus()[0].brand().to_string(),
        cpu_cores: sysinfo::System::physical_core_count().unwrap_or(0) as u32,
        cpu_threads: sys.cpus().len() as u32,
        clock_speed: sys.cpus()[0].frequency() as f32 / 1000.0, // Convert to GHz
        low_power_mode: check_low_power_mode(),
    };

    let gpu_info = get_gpu_info();
    let ram_gb = sys.total_memory() / 1024 / 1024 / 1024; // Convert from B to GB

    SystemInfo {
        instance_type,
        cpu_info,
        gpu_info,
        ram_gb,
    }
}

fn get_local_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    #[cfg(target_os = "macos")]
    let instance_type = "mac".to_string();

    #[cfg(not(target_os = "macos"))]
    let instance_type = "unknown".to_string();

    let low_power_mode = check_low_power_mode();

    let cpu_info = CpuInfo {
        model_name: sys.cpus()[0].brand().to_string(),
        cpu_cores: sysinfo::System::physical_core_count().unwrap_or(0) as u32,
        cpu_threads: sys.cpus().len() as u32,
        clock_speed: sys.cpus()[0].frequency() as f32 / 1000.0, // Convert to GHz
        low_power_mode,
    };

    let gpu_info = get_gpu_info();
    let ram_gb = sys.total_memory() / 1024 / 1024 / 1024; // Convert from B to GB

    SystemInfo {
        instance_type,
        cpu_info,
        gpu_info,
        ram_gb,
    }
}

pub fn is_running_on_ec2() -> bool {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), 80);

    TcpStream::connect_timeout(&addr, Duration::from_millis(500))
        .map(|_| true)
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn check_low_power_mode() -> Option<bool> {
    use std::process::Command;

    let output = Command::new("pmset")
        .args(["-g"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())?;

    output
        .lines()
        .find(|line| line.trim().starts_with("lowpowermode"))
        .map(|line| line.split_whitespace().nth(1) == Some("1"))
}

#[cfg(not(target_os = "macos"))]
fn check_low_power_mode() -> Option<bool> {
    None
}

pub fn print_system_info() -> SystemInfo {
    let info = get_system_info();
    println!("\nSystem Information:");
    println!("{}\n", info);

    info
}
