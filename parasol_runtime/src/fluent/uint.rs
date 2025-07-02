use crate::{
    L1GlweCiphertext,
    circuits::mul::append_uint_multiply,
    fluent::{DynamicGenericInt, GenericIntGraphNodes, PackedGenericIntGraphNode, PlaintextOps},
};

use super::{
    FheCircuit, Muxable, PackedGenericInt,
    generic_int::{GenericInt, PackedDynamicGenericInt, Sign},
};

use mux_circuits::comparisons::compare_or_maybe_equal;
use petgraph::stable_graph::NodeIndex;
use serde::{Deserialize, Serialize};

/// Marker struct
#[derive(Clone, Serialize, Deserialize)]
pub struct Unsigned;

impl PlaintextOps for u128 {
    fn assert_in_bounds(&self, bits: usize) {
        assert!(bits == 128 || *self < 0x1 << bits);
    }

    fn from_bits<I: Iterator<Item = bool>>(iter: I) -> Self {
        iter.enumerate()
            .fold(0u128, |s, (i, x)| s | ((x as u128) << i))
    }

    fn to_bits(&self, len: usize) -> impl Iterator<Item = bool> {
        (0..len).into_iter().map(|i| ((*self >> i) & 0x1) == 0x1)
    }
}

impl Sign for Unsigned {
    type PlaintextType = u128;

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

    fn resize_config(old_size: usize, new_size: usize) -> (usize, usize, bool) {
        (
            // minimal length to keep is the smaller of the two
            new_size.min(old_size),
            // extend length is the difference between the two if new is larger
            new_size.saturating_sub(old_size),
            // zero extend
            false,
        )
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

/// Unsigned variant for [`DynamicGenericInt`]
pub type DynamicUInt<T> = DynamicGenericInt<T, Unsigned>;

/// Unsigned variant for [`PackedDynamicGenericInt`]
pub type PackedDynamicUInt<T> = PackedDynamicGenericInt<T, Unsigned>;

/// Encrypted unsigned 8 bit integer. This is a specialization of [`UInt`] for 8 bits and [`L1GlweCiphertext`].
pub type UInt8 = UInt<8, L1GlweCiphertext>;

/// Encrypted unsigned 16 bit integer. This is a specialization of [`UInt`] for 16 bits and [`L1GlweCiphertext`].
pub type UInt16 = UInt<16, L1GlweCiphertext>;

/// Encrypted unsigned 32 bit integer. This is a specialization of [`UInt`] for 32 bits and [`L1GlweCiphertext`].
pub type UInt32 = UInt<32, L1GlweCiphertext>;

/// Encrypted unsigned 64 bit integer. This is a specialization of [`UInt`] for 64 bits and [`L1GlweCiphertext`].
pub type UInt64 = UInt<64, L1GlweCiphertext>;

/// Encrypted unsigned 128 bit integer. This is a specialization of [`UInt`] for 128 bits and [`L1GlweCiphertext`].
pub type UInt128 = UInt<128, L1GlweCiphertext>;

/// Encrypted unsigned 256 bit integer. This is a specialization of [`UInt`] for 256 bits and [`L1GlweCiphertext`].
pub type UInt256 = UInt<256, L1GlweCiphertext>;

/// Encrypted packed unsigned 8 bit integer. This is a specialization of [`PackedUInt`] for 8 bits and [`L1GlweCiphertext`].
pub type PackedUInt8 = PackedUInt<8, L1GlweCiphertext>;

/// Encrypted packed unsigned 16 bit integer. This is a specialization of [`PackedUInt`] for 16 bits and [`L1GlweCiphertext`].
pub type PackedUInt16 = PackedUInt<16, L1GlweCiphertext>;

/// Encrypted packed unsigned 32 bit integer. This is a specialization of [`PackedUInt`] for 32 bits and [`L1GlweCiphertext`].
pub type PackedUInt32 = PackedUInt<32, L1GlweCiphertext>;

/// Encrypted packed unsigned 64 bit integer. This is a specialization of [`PackedUInt`] for 64 bits and [`L1GlweCiphertext`].
pub type PackedUInt64 = PackedUInt<64, L1GlweCiphertext>;

/// Encrypted packed unsigned 128 bit integer. This is a specialization of [`PackedUInt`] for 128 bits and [`L1GlweCiphertext`].
pub type PackedUInt128 = PackedUInt<128, L1GlweCiphertext>;

/// Encrypted packed unsigned 256 bit integer. This is a specialization of [`PackedUInt`] for 256 bits and [`L1GlweCiphertext`].
pub type PackedUInt256 = PackedUInt<256, L1GlweCiphertext>;

#[cfg(test)]
mod tests {
    use crate::{
        DEFAULT_128, L0LweCiphertext, L1GlevCiphertext, L1GlweCiphertext, L1LweCiphertext,
        crypto::PublicKey,
        fluent::{CiphertextOps, FheCircuitCtx},
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
    fn can_roundtrip_packed_dyn_uint() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();

        let val = PackedDynamicUInt::<L1GlweCiphertext>::encrypt(42, &enc, &pk, 16);

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
            .run_graph_blocking(&ctx.circuit.borrow(), &fc)
            .unwrap();

        assert_eq!(as_unpacked.decrypt(&enc, &sk), 42);
    }

    #[test]
    fn can_unpack_dyn_uint() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();
        let (uproc, fc) = make_uproc_128();

        let val = PackedDynamicUInt::<L1GlweCiphertext>::encrypt(42, &enc, &pk, 16);

        let ctx = FheCircuitCtx::new();

        let as_unpacked = val
            .graph_input(&ctx)
            .unpack(&ctx)
            .collect_outputs(&ctx, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&ctx.circuit.borrow(), &fc)
            .unwrap();

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
            .run_graph_blocking(&ctx.circuit.borrow(), &fc)
            .unwrap();

        assert_eq!(actual.decrypt(&enc, &sk), 42);
    }

    #[test]
    fn can_pack_dyn_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let (uproc, fc) = make_uproc_128();

        let val = DynamicUInt::<L1GlweCiphertext>::encrypt_secret(42, &enc, &sk, 16);

        let ctx = FheCircuitCtx::new();

        let actual = val
            .graph_inputs(&ctx)
            .pack(&ctx, &enc)
            .collect_output(&ctx, &enc);

        uproc
            .lock()
            .unwrap()
            .run_graph_blocking(&ctx.circuit.borrow(), &fc)
            .unwrap();

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
    fn can_unsafe_deserialize_dyn_uint() {
        fn case<T: CiphertextOps + for<'a> Deserialize<'a> + Serialize>() {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();

            let val = DynamicUInt::<T>::encrypt_secret(42, &enc, &sk, 16);

            let ser = bincode::serialize(&val).unwrap();
            bincode::deserialize::<DynamicUInt<T>>(&ser).unwrap();
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
    fn can_safe_deserialize_packed_dyn_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedDynamicUInt::<L1GlweCiphertext>::encrypt(42, &enc, &pk, 16);

        let ser = bincode::serialize(&val).unwrap();
        crate::safe_bincode::deserialize::<PackedDynamicUInt<L1GlweCiphertext>>(&ser, &DEFAULT_128)
            .unwrap();
    }

    #[test]
    fn can_trivial_encrypt_packed_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val = PackedUInt::<15, L1GlweCiphertext>::trivial_encrypt(42, &enc);

        assert_eq!(val.decrypt(&enc, &sk), 42);
    }

    #[test]
    fn can_trivial_encrypt_packed_dyn_uint() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val = PackedDynamicUInt::<L1GlweCiphertext>::trivial_encrypt(42, &enc, 16);

        assert_eq!(val.decrypt(&enc, &sk), 42);
    }
}
