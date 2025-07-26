//#[cfg(not(test))]
//const GPU_KERNELS: &[u8] = include_bytes!(concat!(
//    env!("OUT_DIR"),
//    "/sunscreen_tfhe_gpu.release.fatbin"
//));

#[cfg(test)]
const GPU_KERNELS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/sunscreen_tfhe_gpu.test.fatbin"));

#[cfg(test)]
mod tests;
