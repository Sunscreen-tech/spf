use crate::circuits::mul::append_uint_multiply;

use super::{
    CiphertextOps, FheCircuit, FheCircuitCtx, Muxable, PackedGenericInt,
    bit::BitNode,
    generic_int::{GenericInt, GenericIntGraphNodes, PackedGenericIntGraphNode, Sign},
};

use mux_circuits::comparisons::compare_or_maybe_equal;
use petgraph::stable_graph::NodeIndex;

/// Marker struct
#[derive(Clone)]
pub struct Unsigned;

impl Sign for Unsigned {
    fn gen_compare_circuit(max_len: usize, gt: bool, eq: bool) -> mux_circuits::MuxCircuit {
        compare_or_maybe_equal(max_len, gt, eq)
    }

    fn append_multiply<OutCt: Muxable>(
        uop_graph: &mut FheCircuit,
        a: &[NodeIndex],
        b: &[NodeIndex],
    ) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
        append_uint_multiply::<OutCt>(uop_graph, a, b)
    }
}

/// Unsigned variant for [`GenericIntGraphNodes`]
pub type UIntGraphNodes<'a, const N: usize, T> = GenericIntGraphNodes<'a, N, T, Unsigned>;

impl<'a, const N: usize, T: CiphertextOps> UIntGraphNodes<'a, N, T> {
    /// Convert this `N`-bit integer to an `M`-bit integer of the same ciphertext type.
    ///
    /// # Remarks
    /// If M > N, this will zero extend the integer with trivial encryptions.
    /// If M < N, this will truncate the high-order bits.
    /// If M == N, why did you call this? In any case, the returned nodes will equal the input nodes.
    ///
    /// This operation is "free" in that it adds no computation to the graph.
    pub fn resize<const M: usize>(&self, ctx: &'a FheCircuitCtx) -> UIntGraphNodes<'a, M, T> {
        let extend = if M > N { M - N } else { 0 };

        let min_len = M.min(N);

        let iter = self
            .bits
            .iter()
            .copied()
            .take(min_len)
            .chain((0..extend).map(|_| BitNode::zero(ctx)));

        UIntGraphNodes::from_bit_nodes(iter, &ctx.allocator)
    }
}

/// Unsigned variant for [`PackedGenericIntGraphNode`]
pub type PackedUIntGraphNode<const N: usize, T> = PackedGenericIntGraphNode<N, T, Unsigned>;

/// Unsigned variant for [`GenericInt`]
pub type UInt<const N: usize, T> = GenericInt<N, T, Unsigned>;

/// Unsigned variant for [`PackedGenericInt`]
pub type PackedUInt<const N: usize, T> = PackedGenericInt<N, T, Unsigned>;

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
    fn can_roundtrip_packed_uint() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();

        let val = PackedUInt::<16, L1GlweCiphertext>::encrypt(42, &enc, &pk);

        assert_eq!(val.decrypt(&enc, &sk), 42);
    }

    #[test]
    fn can_unpack_uint() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();
        let (uproc, fc) = make_uproc_128();

        let val = PackedUInt::<16, L1GlweCiphertext>::encrypt(42, &enc, &pk);

        let ctx = FheCircuitCtx::new();

        let as_unpacked = val
            .graph_input(&ctx)
            .unpack(&ctx)
            .collect_outputs(&ctx, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&ctx.circuit.borrow(), &fc);

        assert_eq!(as_unpacked.decrypt(&enc, &sk), 42);
    }

    #[test]
    fn can_pack_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let (uproc, fc) = make_uproc_128();

        let val = UInt::<15, L1GlweCiphertext>::encrypt_secret(42, &enc, &sk);

        let ctx = FheCircuitCtx::new();

        let actual = val
            .graph_inputs(&ctx)
            .pack(&ctx, &enc)
            .collect_output(&ctx, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&ctx.circuit.borrow(), &fc);

        assert_eq!(actual.decrypt(&enc, &sk), 42);
    }

    #[test]
    fn can_safe_deserialize_uint() {
        fn case<T: CiphertextOps + for<'a> Deserialize<'a> + Serialize>() {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();

            let val = UInt::<15, T>::encrypt_secret(42, &enc, &sk);

            let ser = bincode::serialize(&val).unwrap();
            crate::safe_bincode::deserialize::<UInt<15, T>>(&ser, &DEFAULT_128).unwrap();
        }

        case::<L0LweCiphertext>();
        case::<L1LweCiphertext>();
        case::<L1GlweCiphertext>();
        case::<L1GlevCiphertext>();
    }

    #[test]
    fn can_safe_deserialize_packed_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedUInt::<15, L1GlweCiphertext>::encrypt(42, &enc, &pk);

        let ser = bincode::serialize(&val).unwrap();
        crate::safe_bincode::deserialize::<PackedUInt<15, L1GlweCiphertext>>(&ser, &DEFAULT_128)
            .unwrap();
    }

    #[test]
    fn can_trivial_encrypt_packed_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val = PackedUInt::<15, L1GlweCiphertext>::trivial_encrypt(42, &enc);

        assert_eq!(val.decrypt(&enc, &sk), 42);
    }
}
