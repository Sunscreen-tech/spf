use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "A tool for analyzing noise resulting from various FHE operations", long_about = None)]
pub struct AnalyzeNoise {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze scheme switch's noise. Results will be written to a scheme_switch directory.
    SearchSchemeSwitch(SearchSchemeSwitchCommand),
    AnalyzeSchemeSwitch(AnalyzeSchemeSwitch),
    SecretKeyEncryption(SecretKeyEncryptionCommand),
    AnalyzeCbs(AnalyzeCbs),
    AnalyzeCmux(AnalyzeCMux),
}

#[derive(Debug, Args)]
pub struct SecretKeyEncryptionCommand {
    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation defining the Gaussian noise in the GLWE problem instance.
    pub glwe_sigma: f64,

    #[arg(default_value_t = 1, long)]
    /// The number of polynomials in the GLWE problem instance.
    pub glwe_size: usize,

    #[arg(default_value_t = 2048, long)]
    /// The polynomial degree to use in the GLWE problem instance.
    pub glwe_poly_degree: usize,

    #[arg(default_value_t = 30_000, long)]
    /// The number of samples to collect in noise analysis
    pub sample_count: u32,
}

#[derive(Debug, Args)]
pub struct AnalyzeSchemeSwitch {
    #[arg(default_value_t = 7, long)]
    pub ss_radix_log: usize,

    #[arg(default_value_t = 7, long)]
    pub ss_radix_count: usize,

    #[arg(default_value_t = 2, long)]
    /// The radix decomposition count of the resulting GGSW.
    pub cbs_radix_count: usize,

    #[arg(default_value_t = 7, long)]
    /// The radix decomposition base-log of the resulting GGSW.
    pub cbs_radix_log: usize,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation defining the Gaussian noise in the GLWE problem instance used in
    /// keygen.
    pub sigma: f64,

    #[arg(default_value_t = 1e-4, long)]
    pub end_sigma: f64,

    #[arg(default_value_t = 1.7, long)]
    pub step: f64,

    #[arg(default_value_t = 1, long)]
    pub glwe_size: usize,

    #[arg(default_value_t = 2048, long)]
    pub glwe_poly_degree: usize,

    #[arg(default_value_t = 10_000, long)]
    pub sample_count: usize,

    #[arg(default_value_t = false, long)]
    /// Use ntt rather than fft, which results in lower noise. Currently simulated with n^2 polynomial multiplication, which is significantly slower.
    pub ntt: bool,
}

#[derive(Debug, Args)]
pub struct SearchSchemeSwitchCommand {
    #[arg(default_value_t = 63, long)]
    /// The maximum radix count * radix log
    pub max_decomp: usize,

    #[arg(default_value_t = 45, long)]
    /// The minimum radix count * radix log
    pub min_decomp: usize,

    #[arg(default_value_t = 20, long)]
    /// The maximum scheme switching radix log
    pub max_radix_log: usize,

    #[arg(default_value_t = 1, long)]
    /// The minimum scheme switching radix log
    pub min_radix_log: usize,

    #[arg(default_value_t = 20, long)]
    /// The maximum scheme switching radix decomposition count
    pub max_count: usize,

    #[arg(default_value_t = 2, long)]
    /// The minimum scheme switching radix decomposition count
    pub min_count: usize,

    #[arg(default_value_t = 2, long)]
    /// The radix decomposition count of the resulting GGSW.
    pub cbs_radix_count: usize,

    #[arg(default_value_t = 7, long)]
    /// The radix decomposition base-log of the resulting GGSW.
    pub cbs_radix_log: usize,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation defining the Gaussian noise in the GLWE problem instance used in
    /// keygen.
    pub key_sigma: f64,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation given to the input ciphertext.
    pub input_sigma: f64,

    #[arg(default_value_t = 1, long)]
    /// The number of polynomials in the GLWE problem instance.
    pub glwe_size: usize,

    #[arg(default_value_t = 2048, long)]
    /// The polynomial degree to use in the GLWE problem instance.
    pub glwe_poly_degree: usize,

    #[arg(default_value_t = 10_000, long)]
    /// The number of samples to collect in noise analysis
    pub sample_count: u64,

    #[arg(default_value_t = false, long)]
    /// Use ntt rather than fft, which results in lower noise. Currently simulated with n^2 polynomial multiplication, which is significantly slower.
    pub ntt: bool,
}

#[derive(Debug, Args)]
pub struct AnalyzeCbs {
    #[arg(default_value_t = 2, long)]
    /// The radix decomposition count of the resulting GGSW.
    pub pfks_radix_count: usize,

    #[arg(default_value_t = 17, long)]
    /// The radix decomposition base-log of the resulting GGSW.
    pub pfks_radix_log: usize,

    #[arg(default_value_t = 2, long)]
    /// The radix decomposition count of the resulting GGSW.
    pub pbs_radix_count: usize,

    #[arg(default_value_t = 16, long)]
    /// The radix decomposition base-log of the resulting GGSW.
    pub pbs_radix_log: usize,

    #[arg(default_value_t = 2, long)]
    /// The radix decomposition count of the resulting GGSW.
    pub cbs_radix_count: usize,

    #[arg(default_value_t = 7, long)]
    /// The radix decomposition base-log of the resulting GGSW.
    pub cbs_radix_log: usize,

    #[arg(default_value_t = 6.27510880527384e-05, long)]
    /// The std deviation of the L0 LWE instance.
    pub l0_sigma: f64,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation of the L0 LWE instance.
    pub l1_sigma: f64,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation of the L0 LWE instance.
    pub l2_sigma: f64,

    #[arg(default_value_t = 6.27510880527384e-05, long)]
    /// The std deviation given to the input L0 LWE ciphertext.
    pub input_sigma: f64,

    #[arg(default_value_t = 637, long)]
    /// The number of polynomials in the GLWE problem instance.
    pub l0_lwe_size: usize,

    #[arg(default_value_t = 1, long)]
    /// The number of polynomials in the level 2 GLWE problem instance.
    pub l2_glwe_size: usize,

    #[arg(default_value_t = 2048, long)]
    /// The polynomial degree to use in the level 2 GLWE problem instance.
    pub l2_glwe_poly_degree: usize,

    #[arg(default_value_t = 1, long)]
    /// The number of polynomials in the level 1 GLWE problem instance.
    pub l1_glwe_size: usize,

    #[arg(default_value_t = 2048, long)]
    /// The polynomial degree to use in the level 1 GLWE problem instance.
    pub l1_glwe_poly_degree: usize,

    #[arg(default_value_t = 10_000, long)]
    /// The number of samples to collect in noise analysis
    pub sample_count: u64,
}

#[derive(Debug, Args)]
pub struct AnalyzeCMux {
    #[arg(default_value_t = 2, long)]
    /// The radix decomposition count of the resulting GGSW.
    pub cbs_radix_count: usize,

    #[arg(default_value_t = 7, long)]
    /// The radix decomposition base-log of the resulting GGSW.
    pub cbs_radix_log: usize,

    #[arg(default_value_t = 1, long)]
    /// The number of polynomials in the GLWE problem instance.
    pub glwe_size: usize,

    #[arg(default_value_t = 2048, long)]
    /// The polynomial degree to use in the GLWE problem instance.
    pub glwe_poly_degree: usize,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    pub key_sigma: f64,

    #[arg(default_value_t = 0.00000000000000034667670193445625, long)]
    /// The std deviation of the L0 LWE instance.
    pub start_sigma: f64,

    #[arg(default_value_t = 1000.0, long)]
    pub sigma_inc: f64,

    #[arg(default_value_t = 1e-5, long)]
    pub end_sigma: f64,

    #[arg(default_value_t = 100, long)]
    /// The number of samples to collect in noise analysis
    pub sample_count: u64,

    #[arg(default_value_t = false, long)]
    pub ntt: bool,
}
