use serde::{Deserialize, Serialize};
use sunscreen_tfhe::{
    rand::Stddev, GlweDef, LweDef, LweDimension, PolynomialDegree, RadixCount, RadixDecomposition,
    RadixLog, GLWE_1_1024_80, GLWE_1_2048_128, GLWE_5_256_80, LWE_512_80,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Params {
    pub l0_params: LweDef,
    pub l1_params: GlweDef,
    pub l2_params: GlweDef,
    pub cbs_radix: RadixDecomposition,
    pub pbs_radix: RadixDecomposition,
    pub ks_radix: RadixDecomposition,
    pub pfks_radix: RadixDecomposition,
    pub pufks_radix_1: RadixDecomposition,
    pub ss_radix: RadixDecomposition,
}

impl Params {
    pub fn l1_poly_degree(&self) -> PolynomialDegree {
        self.l1_params.dim.polynomial_degree
    }
}

impl Default for Params {
    fn default() -> Self {
        DEFAULT_128
    }
}

pub const DEFAULT_80: Params = Params {
    l0_params: LWE_512_80,
    l1_params: GLWE_1_1024_80,
    l2_params: GLWE_5_256_80,
    cbs_radix: RadixDecomposition {
        radix_log: RadixLog(7),
        count: RadixCount(2),
    },
    pbs_radix: RadixDecomposition {
        radix_log: RadixLog(17),
        count: RadixCount(2),
    },
    pfks_radix: RadixDecomposition {
        radix_log: RadixLog(15),
        count: RadixCount(2),
    },
    pufks_radix_1: RadixDecomposition {
        radix_log: RadixLog(15),
        count: RadixCount(2),
    },
    ks_radix: RadixDecomposition {
        radix_log: RadixLog(1),
        count: RadixCount(12),
    },
    ss_radix: RadixDecomposition {
        radix_log: RadixLog(3),
        count: RadixCount(15),
    },
};

pub const DEFAULT_128: Params = Params {
    l0_params: LweDef {
        dim: LweDimension(637),
        std: Stddev(6.27510880527384e-05),
    },
    l1_params: GLWE_1_2048_128,
    l2_params: GLWE_1_2048_128,
    cbs_radix: RadixDecomposition {
        radix_log: RadixLog(7),
        count: RadixCount(2),
    },
    pbs_radix: RadixDecomposition {
        radix_log: RadixLog(16),
        count: RadixCount(2),
    },
    pfks_radix: RadixDecomposition {
        radix_log: RadixLog(17),
        count: RadixCount(2),
    },
    pufks_radix_1: RadixDecomposition {
        radix_log: RadixLog(15),
        count: RadixCount(2),
    },
    ks_radix: RadixDecomposition {
        radix_log: RadixLog(2),
        count: RadixCount(6),
    },
    ss_radix: RadixDecomposition {
        radix_log: RadixLog(3),
        count: RadixCount(15),
    },
};
