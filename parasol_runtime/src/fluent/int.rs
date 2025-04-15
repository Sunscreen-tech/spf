use crate::circuits::mul::append_int_multiply;

use super::{
    CiphertextOps, FheCircuit, FheCircuitCtx, Muxable, PackedGenericInt,
    generic_int::{GenericInt, GenericIntGraphNodes, PackedGenericIntGraphNode, Sign},
};

use mux_circuits::comparisons::compare_or_maybe_equal_signed;
use petgraph::stable_graph::NodeIndex;

/// Marker struct
#[derive(Clone)]
pub struct Signed;

impl Sign for Signed {
    fn gen_compare_circuit(max_len: usize, gt: bool, eq: bool) -> mux_circuits::MuxCircuit {
        compare_or_maybe_equal_signed(max_len, gt, eq)
    }

    fn append_multiply<OutCt: Muxable>(
        uop_graph: &mut FheCircuit,
        a: &[NodeIndex],
        b: &[NodeIndex],
    ) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
        append_int_multiply::<OutCt>(uop_graph, a, b)
    }
}

/// Signed variant for [`GenericIntGraphNodes`]
pub type IntGraphNodes<'a, const N: usize, T> = GenericIntGraphNodes<'a, N, T, Signed>;

impl<'a, const N: usize, T: CiphertextOps> IntGraphNodes<'a, N, T> {
    /// Convert this `N`-bit integer to an `M`-bit integer of the same ciphertext type.
    ///
    /// # Remarks
    /// If M > N, this will sign extend the integer.
    /// If M < N, this will truncate the high-order bits with sign bit preserved.
    /// If M == N, why did you call this? In any case, the returned nodes will equal the input nodes.
    ///
    /// This operation is "free" in that it adds no computation to the graph.
    pub fn resize<const M: usize>(&self, ctx: &'a FheCircuitCtx) -> IntGraphNodes<'a, M, T> {
        // add 1 for the sign bit that gets removed in `take`, note the minus 1 in min_len
        let extend = 1 + if M > N { M - N } else { 0 };

        let min_len = M.min(N) - 1;

        let sign_bit = self.bits.last().unwrap();

        let iter = self
            .bits
            .iter()
            .copied()
            .take(min_len)
            .chain((0..extend).map(|_| sign_bit.to_owned()));

        IntGraphNodes::from_bit_nodes(iter, &ctx.allocator)
    }
}

/// Signed variant for [`PackedGenericIntGraphNode`]
pub type PackedIntGraphNode<const N: usize, T> = PackedGenericIntGraphNode<N, T, Signed>;

/// Ssigned variant for [`GenericInt`]
pub type Int<const N: usize, T> = GenericInt<N, T, Signed>;

/// Signed variant for [`PackedGenericInt`]
pub type PackedInt<const N: usize, T> = PackedGenericInt<N, T, Signed>;

#[cfg(test)]
mod tests {
    use crate::{
        DEFAULT_128, L0LweCiphertext, L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext,
        crypto::PublicKey,
        test_utils::{get_encryption_128, get_public_key_128, get_secret_keys_128, make_uproc_128},
    };
    use serde::{Deserialize, Serialize};

    use super::*;

    #[test]
    fn can_roundtrip_packed_int() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();

        let val = PackedInt::<16, L1GlweCiphertext>::encrypt(2u64.pow(16) - 42, &enc, &pk);

        assert_eq!(val.decrypt(&enc, &sk), 2u64.pow(16) - 42);
    }

    #[test]
    fn can_unpack_int() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();
        let (uproc, fc) = make_uproc_128();

        let val = PackedInt::<16, L1GlweCiphertext>::encrypt(2u64.pow(16) - 42, &enc, &pk);

        let ctx = FheCircuitCtx::new();

        let as_unpacked = val
            .graph_input(&ctx)
            .unpack(&ctx)
            .collect_outputs(&ctx, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&ctx.circuit.borrow(), &fc);

        assert_eq!(as_unpacked.decrypt(&enc, &sk), 2u64.pow(16) - 42);
    }

    #[test]
    fn can_pack_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let (uproc, fc) = make_uproc_128();

        let val = Int::<15, L1GlweCiphertext>::encrypt_secret(2u64.pow(15) - 42, &enc, &sk);

        let ctx = FheCircuitCtx::new();

        let actual = val
            .graph_inputs(&ctx)
            .pack(&ctx, &enc)
            .collect_output(&ctx, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&ctx.circuit.borrow(), &fc);

        assert_eq!(actual.decrypt(&enc, &sk), 2u64.pow(15) - 42);
    }

    #[test]
    fn can_safe_deserialize_int() {
        fn case<T: CiphertextOps + for<'a> Deserialize<'a> + Serialize>() {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();

            let val = Int::<15, T>::encrypt_secret(2u64.pow(15) - 42, &enc, &sk);

            let ser = bincode::serialize(&val).unwrap();
            crate::safe_bincode::deserialize::<Int<15, T>>(&ser, &DEFAULT_128).unwrap();
        }

        case::<L0LweCiphertext>();
        case::<L1LweCiphertext>();
        case::<L1GlweCiphertext>();
        case::<L1GlevCiphertext>();
    }

    #[test]
    fn can_safe_deserialize_packed_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedInt::<15, L1GlweCiphertext>::encrypt(2u64.pow(15) - 42, &enc, &pk);

        let ser = bincode::serialize(&val).unwrap();
        crate::safe_bincode::deserialize::<PackedInt<15, L1GlweCiphertext>>(&ser, &DEFAULT_128)
            .unwrap();
    }

    #[test]
    fn can_trivial_encrypt_packed_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val = PackedInt::<15, L1GlweCiphertext>::trivial_encrypt(2u64.pow(15) - 42, &enc);

        assert_eq!(val.decrypt(&enc, &sk), 2u64.pow(15) - 42);
    }
}
