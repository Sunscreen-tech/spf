use std::sync::Arc;

use bumpalo::Bump;
use parasol_concurrency::AtomicRefCell;
use petgraph::stable_graph::NodeIndex;
use sunscreen_tfhe::{
    PolynomialDegree,
    entities::{GlevCiphertext, Polynomial, PolynomialRef},
};

use crate::{
    CiphertextType, Encryption, Evaluation, FheCircuit, FheOp, L0LweCiphertext, L1GgswCiphertext,
    L1GlweCiphertext, L1LweCiphertext, Params, SecretKey,
    crypto::{L1GlevCiphertext, PublicKey},
    fhe_circuit::MuxMode,
    safe_bincode::GetSize,
};

mod bit;
mod generic_int;
mod int;
mod uint;

pub use bit::*;
pub use generic_int::*;
pub use int::*;
pub use uint::*;

/// A context for building FHE circuits out of high-level primitives (e.g.
/// [UIntGraphNodes]).
///
/// # Panics
/// The APIs in this module take the context as an immutable borrow to hide the
/// allocator details from you, but rest assured you'll get a panic if you try
/// to mutate using said primitives concurrently on multiple threads.
pub struct FheCircuitCtx {
    /// The underlying [`FheCircuit`].
    pub circuit: AtomicRefCell<FheCircuit>,
    one_cache: AtomicRefCell<[Option<NodeIndex>; 4]>,
    zero_cache: AtomicRefCell<[Option<NodeIndex>; 4]>,
    allocator: Bump,
}

impl Default for FheCircuitCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl FheCircuitCtx {
    /// Create a new [`FheCircuitCtx`].
    pub fn new() -> Self {
        Self {
            circuit: AtomicRefCell::new(FheCircuit::new()),
            one_cache: AtomicRefCell::new([None; 4]),
            zero_cache: AtomicRefCell::new([None; 4]),
            allocator: Bump::new(),
        }
    }
}

/// Operations one can perform on ciphertexts that encrypt polynomials (e.g. [`L1GlweCiphertext`] and
/// [`L1GlevCiphertext`]).
pub trait PolynomialCiphertextOps {
    /// Encrypt a polynomial under the given secret key. Returns the ciphertext.
    fn encrypt_secret(msg: &PolynomialRef<u64>, enc: &Encryption, sk: &SecretKey) -> Self;

    /// Encrypt a polynomial using the given public key. Returns the ciphertext.
    fn encrypt(msg: &PolynomialRef<u64>, enc: &Encryption, pk: &PublicKey) -> Self;

    /// Decrypt an encrypted polynomial using the given secret key. Returns the message.
    fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> Polynomial<u64>;

    /// Create a trivial encryption of the given polynomial.
    fn trivial_encryption(polynomial: &PolynomialRef<u64>, encryption: &Encryption) -> Self;

    /// Get the polynomial degree of messages for the given params.
    fn poly_degree(params: &Params) -> PolynomialDegree;
}

impl PolynomialCiphertextOps for L1GlweCiphertext {
    fn encrypt_secret(msg: &PolynomialRef<u64>, encryption: &Encryption, sk: &SecretKey) -> Self {
        encryption.encrypt_glwe_l1_secret(msg, sk)
    }

    fn encrypt(msg: &PolynomialRef<u64>, encryption: &Encryption, pk: &PublicKey) -> Self {
        encryption.encrypt_rlwe_l1(msg, pk)
    }

    fn trivial_encryption(polynomial: &PolynomialRef<u64>, encryption: &Encryption) -> Self {
        encryption.trivial_glwe_l1(polynomial)
    }

    fn poly_degree(params: &Params) -> PolynomialDegree {
        params.l1_poly_degree()
    }

    fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> Polynomial<u64> {
        enc.decrypt_glwe_l1(self, sk)
    }
}

/// Operations supported by all ciphertext types.
pub trait CiphertextOps: GetSize + Clone
where
    Self: Sized,
{
    /// This is used internally to facilitate ciphertext conversion.
    const CIPHERTEXT_TYPE: CiphertextType;

    /// Allocate a new trivial zero ciphertext.
    fn allocate(encryption: &Encryption) -> Self;

    /// Encrypt a bit under the given secret key. Returns the ciphertext.
    fn encrypt_secret(msg: bool, encryption: &Encryption, sk: &SecretKey) -> Self;

    /// Decrypt and return the bit message contained in `self`.
    fn decrypt(&self, encryption: &Encryption, sk: &SecretKey) -> bool;

    /// Create an [`FheOp`] input corresponding to this ciphertext.
    fn graph_input(bit: &Arc<AtomicRefCell<Self>>) -> FheOp;

    /// Create an [`FheOp`] output corresponding to this ciphertext.
    fn graph_output(bit: &Arc<AtomicRefCell<Self>>) -> FheOp;

    /// Create a trivial encryption of the given bit message with ciphertext type `Self`.
    ///
    /// # Remarks
    /// In the case of [`L1GgswCiphertext`]s, this will return a pre-encrypted one or zero, as
    /// trivial encryptions of one would require knowing and would reveal the secret key.
    fn trivial_encryption(bit: bool, encryption: &Encryption, eval: &Evaluation) -> Self;

    /// Add an [`FheOp`] corresponding to this ciphertext's trivial one node.
    fn graph_trivial_one() -> FheOp;

    /// Add an [`FheOp`] corresponding to this ciphertext's trivial zero node.
    fn graph_trivial_zero() -> FheOp;
}

impl CiphertextOps for L0LweCiphertext {
    const CIPHERTEXT_TYPE: CiphertextType = CiphertextType::L0LweCiphertext;

    fn allocate(encryption: &Encryption) -> Self {
        encryption.allocate_lwe_l0()
    }

    fn encrypt_secret(msg: bool, encryption: &Encryption, sk: &SecretKey) -> Self {
        encryption.encrypt_lwe_l0_secret(msg, sk)
    }

    fn decrypt(&self, encryption: &Encryption, sk: &SecretKey) -> bool {
        encryption.decrypt_lwe_l0(self, sk)
    }

    fn graph_input(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::InputLwe0(bit.clone())
    }

    fn graph_output(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::OutputLwe0(bit.clone())
    }

    fn trivial_encryption(bit: bool, encryption: &Encryption, _eval: &Evaluation) -> Self {
        if bit {
            encryption.trivial_lwe_l0_one()
        } else {
            encryption.trivial_lwe_l0_zero()
        }
    }

    fn graph_trivial_one() -> FheOp {
        FheOp::OneLwe0
    }

    fn graph_trivial_zero() -> FheOp {
        FheOp::ZeroLwe0
    }
}
impl CiphertextOps for L1LweCiphertext {
    const CIPHERTEXT_TYPE: CiphertextType = CiphertextType::L1LweCiphertext;

    fn allocate(encryption: &Encryption) -> Self {
        encryption.allocate_lwe_l1()
    }

    fn encrypt_secret(msg: bool, encryption: &Encryption, sk: &SecretKey) -> Self {
        encryption.encrypt_lwe_l1_secret(msg, sk)
    }

    fn decrypt(&self, encryption: &Encryption, sk: &SecretKey) -> bool {
        encryption.decrypt_lwe_l1(self, sk)
    }

    fn graph_input(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::InputLwe1(bit.clone())
    }

    fn graph_output(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::OutputLwe1(bit.clone())
    }

    fn trivial_encryption(bit: bool, encryption: &Encryption, _eval: &Evaluation) -> Self {
        if bit {
            encryption.trivial_lwe_l1_one()
        } else {
            encryption.trivial_lwe_l1_zero()
        }
    }

    fn graph_trivial_one() -> FheOp {
        unimplemented!()
    }

    fn graph_trivial_zero() -> FheOp {
        unimplemented!()
    }
}
impl CiphertextOps for L1GgswCiphertext {
    const CIPHERTEXT_TYPE: CiphertextType = CiphertextType::L1GgswCiphertext;

    fn allocate(encryption: &Encryption) -> Self {
        encryption.allocate_ggsw_l1()
    }

    fn encrypt_secret(msg: bool, encryption: &Encryption, sk: &SecretKey) -> Self {
        encryption.encrypt_ggsw_l1_secret(msg, sk)
    }

    fn decrypt(&self, encryption: &Encryption, sk: &SecretKey) -> bool {
        encryption.decrypt_ggsw_l1(self, sk)
    }

    fn graph_input(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::InputGgsw1(bit.clone())
    }

    fn graph_output(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::OutputGgsw1(bit.clone())
    }

    fn trivial_encryption(bit: bool, _encryption: &Encryption, eval: &Evaluation) -> Self {
        if bit {
            eval.l1ggsw_one().to_owned()
        } else {
            eval.l1ggsw_zero().to_owned()
        }
    }

    fn graph_trivial_one() -> FheOp {
        FheOp::OneGgsw1
    }

    fn graph_trivial_zero() -> FheOp {
        FheOp::ZeroGgsw1
    }
}
impl CiphertextOps for L1GlweCiphertext {
    const CIPHERTEXT_TYPE: CiphertextType = CiphertextType::L1GlweCiphertext;

    fn allocate(encryption: &Encryption) -> Self {
        encryption.allocate_glwe_l1()
    }

    fn encrypt_secret(msg: bool, encryption: &Encryption, sk: &SecretKey) -> Self {
        let mut poly = Polynomial::new(&vec![
            0u64;
            encryption.params.l1_params.dim.polynomial_degree.0
        ]);
        poly.coeffs_mut()[0] = msg as u64;

        encryption.encrypt_glwe_l1_secret(&poly, sk)
    }

    fn decrypt(&self, encryption: &Encryption, sk: &SecretKey) -> bool {
        encryption.decrypt_glwe_l1(self, sk).coeffs()[0] == 1
    }

    fn graph_input(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::InputGlwe1(bit.clone())
    }

    fn graph_output(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::OutputGlwe1(bit.clone())
    }

    fn trivial_encryption(bit: bool, encryption: &Encryption, _eval: &Evaluation) -> Self {
        if bit {
            encryption.trivial_glwe_l1_one()
        } else {
            encryption.trivial_glwe_l1_zero()
        }
    }

    fn graph_trivial_one() -> FheOp {
        FheOp::OneGlwe1
    }

    fn graph_trivial_zero() -> FheOp {
        FheOp::ZeroGlwe1
    }
}

impl CiphertextOps for L1GlevCiphertext {
    const CIPHERTEXT_TYPE: CiphertextType = CiphertextType::L1GlevCiphertext;

    fn allocate(encryption: &Encryption) -> Self {
        GlevCiphertext::new(&encryption.params.l1_params, &encryption.params.cbs_radix).into()
    }

    fn decrypt(&self, encryption: &Encryption, sk: &SecretKey) -> bool {
        encryption.decrypt_glev_l1(self, sk).coeffs()[0] == 1
    }

    fn encrypt_secret(msg: bool, encryption: &Encryption, sk: &SecretKey) -> Self {
        let mut poly = Polynomial::zero(encryption.params.l1_params.dim.polynomial_degree.0);
        poly.coeffs_mut()[0] = msg as u64;

        encryption.encrypt_glev_l1_secret(&poly, sk)
    }

    fn graph_input(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::InputGlev1(bit.to_owned())
    }

    fn graph_output(bit: &Arc<AtomicRefCell<Self>>) -> FheOp {
        FheOp::OutputGlev1(bit.to_owned())
    }

    fn graph_trivial_zero() -> FheOp {
        FheOp::ZeroGlev1
    }

    fn graph_trivial_one() -> FheOp {
        FheOp::OneGlev1
    }

    fn trivial_encryption(bit: bool, encryption: &Encryption, _eval: &Evaluation) -> Self {
        if bit {
            encryption.trivial_glev_l1_one()
        } else {
            encryption.trivial_glev_l1_zero()
        }
    }
}

/// A trait indicating one can perform Mux Operations over this ciphertext with a [`L1GgswCiphertext`]
/// select bit. Used to abstract Mux circuits over different ciphertext types.
pub trait Muxable: CiphertextOps {
    /// The type of the `a` and `b` inputs and output of a mux operation. Allows the runtime to
    /// dynamically choose [`FheOp::CMux`] or [`FheOp::GlevCMux`] as appropriate.
    const MUX_MODE: MuxMode;
}

impl Muxable for L1GlweCiphertext {
    const MUX_MODE: MuxMode = MuxMode::Glwe;
}

impl Muxable for L1GlevCiphertext {
    const MUX_MODE: MuxMode = MuxMode::Glev;
}

#[cfg(test)]
mod tests {
    use bit::Bit;
    use generic_int::GenericInt;
    use rand::{RngCore, thread_rng};
    use uint::UInt;

    use crate::test_utils::{
        get_encryption_128, get_evaluation_128, get_secret_keys_128, make_uproc_128,
    };

    use super::*;

    fn roundtrip<T: CiphertextOps, U: Sign>() {
        let sk = get_secret_keys_128();
        let enc = get_encryption_128();

        for _ in 0..32 {
            // Make 16-bit integers.
            let val = thread_rng().next_u64() % 0x10000;
            let ct = GenericInt::<16, T, U>::encrypt_secret(val, &enc, &sk);
            let actual = ct.decrypt(&enc, &sk);

            assert_eq!(val, actual);
        }
    }

    #[test]
    fn can_roundtrip_l0_lwe() {
        roundtrip::<L0LweCiphertext, Unsigned>();
        roundtrip::<L0LweCiphertext, Signed>();
    }

    #[test]
    fn can_roundtrip_l1_lwe() {
        roundtrip::<L1LweCiphertext, Unsigned>();
        roundtrip::<L1LweCiphertext, Signed>();
    }

    #[test]
    fn can_roundtrip_l1_glwe() {
        roundtrip::<L1GlweCiphertext, Unsigned>();
        roundtrip::<L1GlweCiphertext, Signed>();
    }

    #[test]
    fn can_roundtrip_l1_ggsw() {
        roundtrip::<L1GgswCiphertext, Unsigned>();
        roundtrip::<L1GgswCiphertext, Signed>();
    }

    fn input_output<T: CiphertextOps, U: Sign>(test_val: u64) {
        let (uproc, fc) = make_uproc_128();
        let enc = get_encryption_128();

        let input = GenericInt::<16, T, U>::encrypt_secret(
            test_val,
            &get_encryption_128(),
            &get_secret_keys_128(),
        );

        let graph = FheCircuitCtx::new();

        let in_node = input.graph_inputs(&graph);
        let output = in_node.collect_outputs(&graph, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&graph.circuit.borrow(), &fc)
            .unwrap();

        let actual = output.decrypt(&enc, &get_secret_keys_128());
        assert_eq!(actual, test_val);
    }

    #[test]
    fn can_input_output_generic_int_graph_l0_lwe() {
        input_output::<L0LweCiphertext, Unsigned>(1234);
        input_output::<L0LweCiphertext, Signed>(65432);
    }

    #[test]
    fn can_input_output_generic_int_graph_l1_lwe() {
        input_output::<L1LweCiphertext, Unsigned>(1234);
        input_output::<L1LweCiphertext, Signed>(65432);
    }

    #[test]
    fn can_input_output_generic_int_graph_l1_ggsw() {
        input_output::<L1GgswCiphertext, Unsigned>(1234);
        input_output::<L1GgswCiphertext, Signed>(65432);
    }

    #[test]
    fn can_input_output_generic_int_graph_l1_glwe() {
        input_output::<L1GlweCiphertext, Unsigned>(1234);
        input_output::<L1GlweCiphertext, Signed>(65432);
    }

    #[test]
    fn can_convert_ciphertexts() {
        fn convert_test<T: CiphertextOps, U: CiphertextOps, V: Sign>(test_val: u64) {
            let graph = FheCircuitCtx::new();
            let enc = get_encryption_128();
            let (uproc, fc) = make_uproc_128();
            let sk = get_secret_keys_128();

            let val = GenericInt::<16, T, V>::encrypt_secret(test_val, &enc, &sk);

            let inputs = val.graph_inputs(&graph);
            let converted = inputs.convert::<U>(&graph);
            let outputs = converted.collect_outputs(&graph, &enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&graph.circuit.borrow(), &fc)
                .unwrap();

            let actual = outputs.decrypt(&enc, &sk);
            assert_eq!(actual, test_val);
        }

        convert_test::<L0LweCiphertext, L1GgswCiphertext, Unsigned>(1234);
        convert_test::<L0LweCiphertext, L1GgswCiphertext, Signed>(65432);
        convert_test::<L0LweCiphertext, L1GlweCiphertext, Unsigned>(1234);
        convert_test::<L0LweCiphertext, L1GlweCiphertext, Signed>(65432);
        convert_test::<L0LweCiphertext, L1LweCiphertext, Unsigned>(1234);
        convert_test::<L0LweCiphertext, L1LweCiphertext, Signed>(65432);
        convert_test::<L0LweCiphertext, L0LweCiphertext, Unsigned>(1234);
        convert_test::<L0LweCiphertext, L0LweCiphertext, Signed>(65432);

        // GLEV ciphertexts are weird children, so give them a few cases.
        convert_test::<L1GlevCiphertext, L1GgswCiphertext, Unsigned>(1234);
        convert_test::<L1GlevCiphertext, L1GgswCiphertext, Signed>(65432);
        convert_test::<L1GgswCiphertext, L1GlevCiphertext, Unsigned>(1234);
        convert_test::<L1GgswCiphertext, L1GlevCiphertext, Signed>(65432);
        convert_test::<L0LweCiphertext, L1GlevCiphertext, Unsigned>(1234);
        convert_test::<L0LweCiphertext, L1GlevCiphertext, Signed>(65432);
    }

    #[test]
    fn can_cmp() {
        fn case<OutCt: Muxable, U: Sign>(gt: bool, eq: bool, test_vals: (u64, u64)) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.0, enc, &sk);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let expect_gt = a_input
                .cmp::<OutCt>(&b_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);
            let expect_lt = b_input
                .cmp::<OutCt>(&a_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);
            let expect_eq = b_input
                .cmp::<OutCt>(&b_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(expect_gt.decrypt(enc, &sk), gt);
            assert_eq!(expect_lt.decrypt(enc, &sk), !gt);
            assert_eq!(expect_eq.decrypt(enc, &sk), eq);
        }

        fn cases<OutCt: Muxable>() {
            case::<OutCt, Unsigned>(false, false, (43, 42));
            case::<OutCt, Signed>(false, false, (65501, 65500));
            case::<OutCt, Signed>(false, false, (1, 65535));
            case::<OutCt, Unsigned>(false, true, (43, 42));
            case::<OutCt, Signed>(false, true, (65501, 65500));
            case::<OutCt, Signed>(false, true, (1, 65535));
            case::<OutCt, Unsigned>(true, false, (43, 42));
            case::<OutCt, Signed>(true, false, (65501, 65500));
            case::<OutCt, Signed>(true, false, (1, 65535));
            case::<OutCt, Unsigned>(true, true, (43, 42));
            case::<OutCt, Signed>(true, true, (65501, 65500));
            case::<OutCt, Signed>(true, true, (1, 65535));
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    #[test]
    fn can_eq() {
        fn case<OutCt: Muxable, U: Sign>(eq: bool, test_vals: (u64, u64)) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.0, enc, &sk);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let calculated_eq = a_input
                .eq::<OutCt>(&b_input, &ctx)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(calculated_eq.decrypt(enc, &sk), eq);
        }

        fn cases<OutCt: Muxable>() {
            case::<OutCt, Unsigned>(false, (43, 42));
            case::<OutCt, Signed>(false, (65501, 65500));
            case::<OutCt, Unsigned>(true, (43, 43));
            case::<OutCt, Signed>(true, (65501, 65501));
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    // TODO this requires changing the `eq` method to use the correct `resize` method for creating the interleaved
    // input, I am not bothered at this time
    #[test]
    fn can_eq_size_mismatch() {
        fn case<const N: usize, const M: usize, OutCt: Muxable>(eq: bool) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let (val_a, val_b) = if eq { (43, 43) } else { (43, 42) };

            let a = UInt::<N, L1GgswCiphertext>::encrypt_secret(val_a, enc, &sk);
            let b = UInt::<M, L1GgswCiphertext>::encrypt_secret(val_b, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let calculated_eq = a_input
                .eq::<OutCt>(&b_input, &ctx)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(calculated_eq.decrypt(enc, &sk), eq);
        }

        // Test with 8-bit and 16-bit combinations
        case::<8, 16, L1GlweCiphertext>(false);
        case::<8, 16, L1GlweCiphertext>(true);
        case::<16, 8, L1GlweCiphertext>(false);
        case::<16, 8, L1GlweCiphertext>(true);

        case::<8, 16, L1GlevCiphertext>(false);
        case::<8, 16, L1GlevCiphertext>(true);
        case::<16, 8, L1GlevCiphertext>(false);
        case::<16, 8, L1GlevCiphertext>(true);
    }

    #[test]
    fn can_neq() {
        fn case<OutCt: Muxable, U: Sign>(neq: bool, test_vals: (u64, u64)) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.0, enc, &sk);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let calculated_neq = a_input
                .neq::<OutCt>(&b_input, &ctx)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(calculated_neq.decrypt(enc, &sk), neq);
        }

        fn cases<OutCt: Muxable>() {
            case::<OutCt, Unsigned>(false, (43, 43));
            case::<OutCt, Signed>(false, (65501, 65501));
            case::<OutCt, Unsigned>(true, (43, 42));
            case::<OutCt, Signed>(true, (65501, 65500));
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    // TODO this requires changing the `neq` method to use the correct `resize` method for creating the interleaved
    // input, I am not bothered at this time
    #[test]
    fn can_neq_size_mismatch() {
        fn case<const N: usize, const M: usize, OutCt: Muxable>(neq: bool) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let (val_a, val_b) = if neq { (43, 42) } else { (43, 43) };

            let a = UInt::<N, L1GgswCiphertext>::encrypt_secret(val_a, enc, &sk);
            let b = UInt::<M, L1GgswCiphertext>::encrypt_secret(val_b, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let calculated_neq = a_input
                .neq::<OutCt>(&b_input, &ctx)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(calculated_neq.decrypt(enc, &sk), neq);
        }

        // Test with 8-bit and 16-bit combinations
        case::<8, 16, L1GlweCiphertext>(false);
        case::<8, 16, L1GlweCiphertext>(true);
        case::<16, 8, L1GlweCiphertext>(false);
        case::<16, 8, L1GlweCiphertext>(true);

        case::<8, 16, L1GlevCiphertext>(false);
        case::<8, 16, L1GlevCiphertext>(true);
        case::<16, 8, L1GlevCiphertext>(false);
        case::<16, 8, L1GlevCiphertext>(true);
    }

    // TODO this requires changing the `cmp` method to use the correct `resize` method for creating the interleaved
    // input, I am not bothered at this time
    #[test]
    fn can_cmp_size_mismatch() {
        fn case<const N: usize, const M: usize, OutCt: Muxable>(gt: bool, eq: bool) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let a = UInt::<N, L1GgswCiphertext>::encrypt_secret(43, enc, &sk);
            let b = UInt::<M, L1GgswCiphertext>::encrypt_secret(42, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let expect_gt = a_input
                .cmp::<OutCt>(&b_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);
            let expect_lt = b_input
                .cmp::<OutCt>(&a_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);
            let expect_eq = b_input
                .cmp::<OutCt>(&b_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(expect_gt.decrypt(enc, &sk), gt);
            assert_eq!(expect_lt.decrypt(enc, &sk), !gt);
            assert_eq!(expect_eq.decrypt(enc, &sk), eq);
        }

        fn cases<OutCt: Muxable>() {
            case::<8, 16, OutCt>(false, false);
            case::<8, 16, OutCt>(false, true);
            case::<8, 16, OutCt>(true, false);
            case::<8, 16, OutCt>(true, true);

            case::<16, 8, OutCt>(false, false);
            case::<16, 8, OutCt>(false, true);
            case::<16, 8, OutCt>(true, false);
            case::<16, 8, OutCt>(true, true);
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    #[test]
    fn can_cmp_trivial_nontrivial_ggsw() {
        fn case<OutCt: Muxable, U: Sign>(gt: bool, eq: bool, test_vals: (u64, u64)) {
            let enc = &get_encryption_128();
            let eval = &get_evaluation_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::trivial(test_vals.0, enc, eval);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk);

            let a_input = a.graph_inputs(&ctx);
            let b_input = b.graph_inputs(&ctx);

            let expect_gt = a_input
                .cmp::<OutCt>(&b_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);
            let expect_lt = b_input
                .cmp::<OutCt>(&a_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);
            let expect_eq = b_input
                .cmp::<OutCt>(&b_input, &ctx, gt, eq)
                .collect_output(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(expect_gt.decrypt(enc, &sk), gt);
            assert_eq!(expect_lt.decrypt(enc, &sk), !gt);
            assert_eq!(expect_eq.decrypt(enc, &sk), eq);
        }

        fn cases<OutCt: Muxable>() {
            case::<OutCt, Unsigned>(false, false, (43, 42));
            case::<OutCt, Signed>(false, false, (65501, 65500));
            case::<OutCt, Signed>(false, false, (1, 65535));
            case::<OutCt, Unsigned>(false, true, (43, 42));
            case::<OutCt, Signed>(false, true, (65501, 65500));
            case::<OutCt, Signed>(false, true, (1, 65535));
            case::<OutCt, Unsigned>(true, false, (43, 42));
            case::<OutCt, Signed>(true, false, (65501, 65500));
            case::<OutCt, Signed>(true, false, (1, 65535));
            case::<OutCt, Unsigned>(true, true, (43, 42));
            case::<OutCt, Signed>(true, true, (65501, 65500));
            case::<OutCt, Signed>(true, true, (1, 65535));
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    #[test]
    fn can_select() {
        fn case<U: Sign>(test_vals: (u64, u64)) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let sel_false =
                Bit::<L1GgswCiphertext>::encrypt_secret(false, enc, &sk).graph_input(&ctx);
            let sel_true =
                Bit::<L1GgswCiphertext>::encrypt_secret(true, enc, &sk).graph_input(&ctx);

            let a: GenericIntGraphNodes<'_, 16, L1GlweCiphertext, U> =
                GenericInt::<16, L1GlweCiphertext, U>::encrypt_secret(test_vals.0, enc, &sk)
                    .graph_inputs(&ctx)
                    .into();
            let b: GenericIntGraphNodes<'_, 16, L1GlweCiphertext, U> =
                GenericInt::<16, L1GlweCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk)
                    .graph_inputs(&ctx)
                    .into();

            let sel_false = sel_false.select(&a, &b, &ctx).collect_outputs(&ctx, enc);
            let sel_true = sel_true.select(&a, &b, &ctx).collect_outputs(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(sel_false.decrypt(enc, &sk), test_vals.1);
            assert_eq!(sel_true.decrypt(enc, &sk), test_vals.0);
        }

        case::<Unsigned>((42, 24));
        case::<Signed>((65442, 65424));
    }

    #[test]
    fn can_select_plain() {
        fn case<U: Sign>(test_vals: (u64, u64)) {
            let enc = &get_encryption_128();
            let eval = &get_evaluation_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let sel_false =
                Bit::<L1GgswCiphertext>::trivial_encryption(false, enc, eval).graph_input(&ctx);
            let sel_true =
                Bit::<L1GgswCiphertext>::trivial_encryption(true, enc, eval).graph_input(&ctx);

            let a: GenericIntGraphNodes<'_, 16, L1GlweCiphertext, U> =
                GenericInt::<16, L1GlweCiphertext, U>::encrypt_secret(test_vals.0, enc, &sk)
                    .graph_inputs(&ctx)
                    .into();
            let b: GenericIntGraphNodes<'_, 16, L1GlweCiphertext, U> =
                GenericInt::<16, L1GlweCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk)
                    .graph_inputs(&ctx)
                    .into();

            let sel_false = sel_false.select(&a, &b, &ctx).collect_outputs(&ctx, enc);
            let sel_true = sel_true.select(&a, &b, &ctx).collect_outputs(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(sel_false.decrypt(enc, &sk), test_vals.1);
            assert_eq!(sel_true.decrypt(enc, &sk), test_vals.0);
        }

        case::<Unsigned>((42, 24));
        case::<Signed>((65442, 65424));
    }

    #[test]
    fn can_sub() {
        fn case<OutCt: Muxable, U: Sign>(test_vals: (u64, u64, u64)) {
            let enc = &get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (uproc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.0, enc, &sk)
                .graph_inputs(&ctx);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, enc, &sk)
                .graph_inputs(&ctx);

            let c = a.sub::<OutCt>(&b, &ctx).collect_outputs(&ctx, enc);

            uproc
                .lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(c.decrypt(enc, &sk), test_vals.2);
        }

        fn cases<OutCt: Muxable>() {
            case::<OutCt, Unsigned>((42, 16, 26));
            case::<OutCt, Signed>((65531, 65529, 2));
            case::<OutCt, Signed>((65531, 2, 65529));
            case::<OutCt, Signed>((65531, 65533, 65534));
            case::<OutCt, Signed>((2, 65531, 7));
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    #[test]
    fn trivial_generic_int_encryption() {
        fn case<T: CiphertextOps, U: Sign>() {
            let enc = get_encryption_128();
            let eval = &get_evaluation_128();
            let sk = get_secret_keys_128();

            let expected = thread_rng().next_u64() % (0x1 << 32);

            let val = GenericInt::<32, T, U>::trivial(expected, &enc, eval);

            assert_eq!(val.decrypt(&enc, &sk), expected);
        }

        case::<L0LweCiphertext, Unsigned>();
        case::<L0LweCiphertext, Signed>();
        case::<L1LweCiphertext, Unsigned>();
        case::<L1LweCiphertext, Signed>();
        case::<L1GlweCiphertext, Unsigned>();
        case::<L1GlweCiphertext, Signed>();
        case::<L1GgswCiphertext, Unsigned>();
        case::<L1GgswCiphertext, Signed>();
    }

    #[test]
    fn can_resize() {
        fn case<T: CiphertextOps, U: Sign>(test_vals: (u64, u64, u64)) {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (proc, fc) = make_uproc_128();

            let val = GenericInt::<16, T, U>::encrypt_secret(test_vals.0, &enc, &sk);
            let res = val
                .graph_inputs(&ctx)
                .resize(&ctx, 24)
                .collect_outputs(&ctx, &enc);

            proc.lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(res.decrypt(&enc, &sk), test_vals.1);

            let res = val
                .graph_inputs(&ctx)
                .resize(&ctx, 8)
                .collect_outputs(&ctx, &enc);

            proc.lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(res.decrypt(&enc, &sk), test_vals.2);
        }

        case::<L0LweCiphertext, Unsigned>((1234, 1234, 210));
        case::<L0LweCiphertext, Signed>((1234, 1234, 82));
        case::<L0LweCiphertext, Signed>((65432, 16777112, 152));
        // unimplemented
        //case::<L1LweCiphertext>();
        case::<L1GlweCiphertext, Unsigned>((1234, 1234, 210));
        case::<L1GlweCiphertext, Signed>((1234, 1234, 82));
        case::<L1GlweCiphertext, Signed>((65432, 16777112, 152));
        case::<L1GgswCiphertext, Unsigned>((1234, 1234, 210));
        case::<L1GgswCiphertext, Signed>((1234, 1234, 82));
        case::<L1GgswCiphertext, Signed>((65432, 16777112, 152));
    }

    #[test]
    fn can_add() {
        fn case<OutCt: Muxable, U: Sign>(test_vals: (u64, u64, u64)) {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (proc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.0, &enc, &sk)
                .graph_inputs(&ctx);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, &enc, &sk)
                .graph_inputs(&ctx);

            let c = a.add::<OutCt>(&b, &ctx).collect_outputs(&ctx, &enc);

            println!("{:#?}", *ctx.circuit.borrow());

            proc.lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(c.decrypt(&enc, &sk), test_vals.2);
        }

        fn cases<OutCt: Muxable>() {
            case::<OutCt, Unsigned>((42, 16, 58));
            case::<OutCt, Signed>((65530, 16, 10));
            case::<OutCt, Signed>((65530, 65529, 65523));
            case::<OutCt, Signed>((65528, 2, 65530));
        }

        cases::<L1GlweCiphertext>();
        cases::<L1GlevCiphertext>();
    }

    #[test]
    fn can_mul() {
        fn case<OutCt: Muxable, U: Sign>(test_vals: (u64, u64, u64)) {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();
            let ctx = FheCircuitCtx::new();
            let (proc, fc) = make_uproc_128();

            let a = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.0, &enc, &sk)
                .graph_inputs(&ctx);
            let b = GenericInt::<16, L1GgswCiphertext, U>::encrypt_secret(test_vals.1, &enc, &sk)
                .graph_inputs(&ctx);

            let c = a.mul::<OutCt>(&b, &ctx).collect_outputs(&ctx, &enc);

            proc.lock()
                .unwrap()
                .run_graph_blocking(&ctx.circuit.borrow(), &fc)
                .unwrap();

            assert_eq!(c.decrypt(&enc, &sk), test_vals.2);
        }

        case::<L1GlweCiphertext, Unsigned>((42, 16, 672));
        case::<L1GlweCiphertext, Signed>((42, 16, 672));
        case::<L1GlweCiphertext, Signed>((42, 65520 /* -16 */, 64864 /* -672 */));
        case::<L1GlweCiphertext, Signed>((65494 /* -42 */, 65520 /* -16 */, 672));
    }
}
