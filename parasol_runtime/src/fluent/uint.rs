use crate::circuits::mul::append_uint_multiply;

use super::{
    CiphertextOps, FheCircuit, Muxable, PackedGenericInt,
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

    /// Convert this `old_size`-bit integer to an `new_size`-bit integer of the same ciphertext type.
    ///
    /// # Remarks
    /// If new_size > old_size, this will zero extend the integer with trivial encryptions.
    /// If new_size < old_size, this will truncate the high-order bits.
    /// If new_size == old_size, why did you call this? In any case, the returned nodes will equal the input nodes.
    ///
    /// This operation is "free" in that it adds no computation to the graph.
    fn resize<T: CiphertextOps>(
        input: &[BitNode<T>],
        zero: &BitNode<T>,
        old_size: usize,
        new_size: usize,
    ) -> impl Iterator<Item = BitNode<T>> {
        let extend = new_size.saturating_sub(old_size);

        let min_len = new_size.min(old_size);

        input
            .iter()
            .copied()
            .take(min_len)
            .chain((0..extend).map(|_| zero.to_owned()))
    }
}

/// Unsigned variant for [`GenericIntGraphNodes`]
pub type UIntGraphNodes<'a, const N: usize, T> = GenericIntGraphNodes<'a, N, T, Unsigned>;

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
        fluent::FheCircuitCtx,
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
