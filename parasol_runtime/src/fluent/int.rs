use crate::{
    L1GlweCiphertext,
    circuits::mul::append_int_multiply,
    fluent::{DynamicGenericInt, GenericIntGraphNodes, PackedGenericIntGraphNode, PlaintextOps},
};

use super::{
    FheCircuit, Muxable, PackedGenericInt,
    generic_int::{GenericInt, PackedDynamicGenericInt, Sign},
};

use mux_circuits::comparisons::compare_or_maybe_equal_signed;
use petgraph::stable_graph::NodeIndex;
use serde::{Deserialize, Serialize};

/// Marker struct
#[derive(Clone, Serialize, Deserialize)]
pub struct Signed;

impl PlaintextOps for i128 {
    fn assert_in_bounds(&self, bits: usize) {
        let max_val = ((0x1u128 << (bits - 1)) - 1).cast_signed();
        let min_val = -(0x1u128 << (bits - 1)).cast_signed();

        assert!(bits == 128 || *self <= max_val);
        assert!(bits == 128 || *self >= min_val);
    }

    fn from_bits<I: Iterator<Item = bool>>(bits: I) -> Self {
        let mut num_bits = 0;

        let mut val = bits.enumerate().fold(0i128, |s, (i, x)| {
            num_bits += 1;
            s | ((x as i128) << i)
        });

        let sign = (val >> (num_bits - 1)) & 0x1;

        // Sign extend our value to 128-bit.
        for i in num_bits..128 {
            val |= sign << i;
        }

        val
    }

    fn to_bits(&self, len: usize) -> impl Iterator<Item = bool> {
        (0..len).map(|i| ((*self >> i) & 0x1) == 0x1)
    }
}

impl Sign for Signed {
    type PlaintextType = i128;

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

    fn resize_config(old_size: usize, new_size: usize) -> (usize, usize, bool) {
        (
            // minimal length to keep is the smaller of the two minus 1 to exclude the sign bit
            new_size.min(old_size) - 1,
            // extend length is the difference between the two if new is larger plus 1 to include the sign bit
            new_size.saturating_sub(old_size) + 1,
            // sign extend
            true,
        )
    }
}

/// Signed variant for [`GenericIntGraphNodes`]
pub type IntGraphNodes<'a, const N: usize, T> = GenericIntGraphNodes<'a, N, T, Signed>;

/// Signed variant for [`PackedGenericIntGraphNode`]
pub type PackedIntGraphNode<const N: usize, T> = PackedGenericIntGraphNode<N, T, Signed>;

/// Signed variant for [`GenericInt`]
pub type Int<const N: usize, T> = GenericInt<N, T, Signed>;

/// Signed variant for [`PackedGenericInt`]
pub type PackedInt<const N: usize, T> = PackedGenericInt<N, T, Signed>;

/// Signed variant for [`DynamicGenericInt`]
pub type DynamicInt<T> = DynamicGenericInt<T, Signed>;

/// Signed variant for [`PackedDynamicGenericInt`]
pub type PackedDynamicInt<T> = PackedDynamicGenericInt<T, Signed>;

/// Encrypted signed 8 bit integer. This is a specialization of [`Int`] for 8 bits and [`L1GlweCiphertext`].
pub type Int8 = Int<8, L1GlweCiphertext>;

/// Encrypted signed 16 bit integer. This is a specialization of [`Int`] for 16 bits and [`L1GlweCiphertext`].
pub type Int16 = Int<16, L1GlweCiphertext>;

/// Encrypted signed 32 bit integer. This is a specialization of [`Int`] for 32 bits and [`L1GlweCiphertext`].
pub type Int32 = Int<32, L1GlweCiphertext>;

/// Encrypted signed 64 bit integer. This is a specialization of [`Int`] for 64 bits and [`L1GlweCiphertext`].
pub type Int64 = Int<64, L1GlweCiphertext>;

/// Encrypted signed 128 bit integer. This is a specialization of [`Int`] for 128 bits and [`L1GlweCiphertext`].
pub type Int128 = Int<128, L1GlweCiphertext>;

/// Encrypted signed 256 bit integer. This is a specialization of [`Int`] for 256 bits and [`L1GlweCiphertext`].
pub type Int256 = Int<256, L1GlweCiphertext>;

/// Encrypted packed signed 8 bit integer. This is a specialization of [`PackedInt`] for 8 bits and [`L1GlweCiphertext`].
pub type PackedInt8 = PackedInt<8, L1GlweCiphertext>;

/// Encrypted packed signed 16 bit integer. This is a specialization of [`PackedInt`] for 16 bits and [`L1GlweCiphertext`].
pub type PackedInt16 = PackedInt<16, L1GlweCiphertext>;

/// Encrypted packed signed 32 bit integer. This is a specialization of [`PackedInt`] for 32 bits and [`L1GlweCiphertext`].
pub type PackedInt32 = PackedInt<32, L1GlweCiphertext>;

/// Encrypted packed signed 64 bit integer. This is a specialization of [`PackedInt`] for 64 bits and [`L1GlweCiphertext`].
pub type PackedInt64 = PackedInt<64, L1GlweCiphertext>;

/// Encrypted packed signed 128 bit integer. This is a specialization of [`PackedInt`] for 128 bits and [`L1GlweCiphertext`].
pub type PackedInt128 = PackedInt<128, L1GlweCiphertext>;

/// Encrypted packed 256 bit integer. This is a specialization of [`PackedInt`] for 256 bits and [`L1GlweCiphertext`].
pub type PackedInt256 = PackedInt<256, L1GlweCiphertext>;

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
    fn can_roundtrip_packed_int() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();

        let val = PackedInt::<16, L1GlweCiphertext>::encrypt(-42, &enc, &pk);

        assert_eq!(val.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_roundtrip_packed_dyn_int() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();

        let val = PackedDynamicInt::<L1GlweCiphertext>::encrypt(-42, &enc, &pk, 16);

        assert_eq!(val.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_unpack_int() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();
        let (uproc, fc) = make_uproc_128();

        let val = PackedInt::<16, L1GlweCiphertext>::encrypt(-42, &enc, &pk);

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

        assert_eq!(as_unpacked.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_unpack_dyn_int() {
        let enc = get_encryption_128();

        let sk = get_secret_keys_128();
        let pk = get_public_key_128();
        let (uproc, fc) = make_uproc_128();

        let val = PackedDynamicInt::<L1GlweCiphertext>::encrypt(-42, &enc, &pk, 16);

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

        assert_eq!(as_unpacked.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_pack_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let (uproc, fc) = make_uproc_128();

        let val = Int::<15, L1GlweCiphertext>::encrypt_secret(-42, &enc, &sk);

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

        assert_eq!(actual.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_pack_dyn_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let (uproc, fc) = make_uproc_128();

        let val = DynamicInt::<L1GlweCiphertext>::encrypt_secret(-42, &enc, &sk, 15);

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

        assert_eq!(actual.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_safe_deserialize_int() {
        fn case<T: CiphertextOps + for<'a> Deserialize<'a> + Serialize>() {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();

            let val = Int::<15, T>::encrypt_secret(-42, &enc, &sk);

            let ser = bincode::serialize(&val).unwrap();
            crate::safe_bincode::deserialize::<Int<15, T>>(&ser, &DEFAULT_128).unwrap();
        }

        case::<L0LweCiphertext>();
        case::<L1LweCiphertext>();
        case::<L1GlweCiphertext>();
        case::<L1GlevCiphertext>();
    }

    #[test]
    fn can_unsafe_deserialize_dyn_int() {
        fn case<T: CiphertextOps + for<'a> Deserialize<'a> + Serialize>() {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();

            let val = DynamicInt::<T>::encrypt_secret(-42, &enc, &sk, 15);

            let ser = bincode::serialize(&val).unwrap();
            bincode::deserialize::<DynamicInt<T>>(&ser).unwrap();
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

        let val = PackedInt::<15, L1GlweCiphertext>::encrypt(-42, &enc, &pk);

        let ser = bincode::serialize(&val).unwrap();
        crate::safe_bincode::deserialize::<PackedInt<15, L1GlweCiphertext>>(&ser, &DEFAULT_128)
            .unwrap();
    }

    #[test]
    fn can_safe_deserialize_packed_dyn_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();
        let pk = PublicKey::generate(&DEFAULT_128, &sk);

        let val = PackedDynamicInt::<L1GlweCiphertext>::encrypt(-42, &enc, &pk, 15);

        let ser = bincode::serialize(&val).unwrap();
        crate::safe_bincode::deserialize::<PackedDynamicInt<L1GlweCiphertext>>(&ser, &DEFAULT_128)
            .unwrap();
    }

    #[test]
    fn can_trivial_encrypt_packed_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val = PackedInt::<15, L1GlweCiphertext>::trivial_encrypt(-42, &enc);

        assert_eq!(val.decrypt(&enc, &sk), -42);
    }

    #[test]
    fn can_trivial_encrypt_packed_dyn_int() {
        let enc = get_encryption_128();
        let sk = get_secret_keys_128();

        let val = PackedDynamicInt::<L1GlweCiphertext>::trivial_encrypt(-42, &enc, 15);

        assert_eq!(val.decrypt(&enc, &sk), -42);
    }
}
