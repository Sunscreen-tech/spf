use mux_circuits::{
    add::ripple_carry_adder,
    mul::{
        encode_gradeschool_reduction, gradeschool_reduce, partition_integer, unsigned_multiplier,
    },
};
use petgraph::stable_graph::NodeIndex;

use crate::{
    crypto::ciphertext::CiphertextType,
    fhe_circuit::{insert_ciphertext_conversion, FheCircuit},
    fluent::Muxable,
};

/// Compute the product of 2 N-bit unsigned values a and b.
pub fn append_uint_multiply<OutCt: Muxable>(
    uop_graph: &mut FheCircuit,
    a: &[NodeIndex],
    b: &[NodeIndex],
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    // Implement recursive gradeschool multiplication.
    // TODO: switch to Karatsuba when payoff is worth it. See benchmark in `sizes.rs``.
    fn mul_impl<OutCt: Muxable>(
        uop_graph: &mut FheCircuit,
        a: &[NodeIndex],
        b: &[NodeIndex],
    ) -> Vec<NodeIndex> {
        // Always denote the longer operand as a. Since multiplication commutes, we can freely
        // swap the operands. This reduces the number of cases we have to consider.
        let (a, b) = if a.len() < b.len() { (b, a) } else { (a, b) };

        let (a_lo_len, a_hi_len) = partition_integer(a.len());
        let (b_lo_len, b_hi_len) = partition_integer(b.len());

        let (a_lo, a_hi) = a.split_at(a_lo_len);
        let (b_lo, b_hi) = b.split_at(b_lo_len);

        if a_hi_len == 0 && b_hi_len == 0 {
            {
                let mul_block = unsigned_multiplier(a.len(), b.len());

                let interleaved = a
                    .iter()
                    .copied()
                    .chain(b.iter().copied())
                    .collect::<Vec<_>>();

                uop_graph.insert_mux_circuit(&mul_block, &interleaved, OutCt::MUX_MODE)
            }
        } else if b_hi_len == 0 {
            // Since we ensured our larger operand was on top, we don't have to consider only
            // a_hi_len being zero. In this case, we compute
            // `b_lo * a_lo + ((b_lo * a_hi) << a_lo_len)`.

            let a_lo_b_lo = mul_impl::<OutCt>(uop_graph, a_lo, b_lo);
            let a_hi_b_lo = mul_impl::<OutCt>(uop_graph, a_hi, b_lo);

            // The lower a_lo_len bits of a_lo_b_lo simply pass through to the total.
            // We do need to sum the upper b_lo bits of `a_lo_b_lo`` to `a_hi_b_lo``.
            let adder = ripple_carry_adder(b_lo_len, a_hi_len + b_lo_len, false);

            let (lo, hi) = a_lo_b_lo.split_at(a_lo_len);

            let adder_inputs = hi
                .iter()
                .zip(a_hi_b_lo.iter().take(a_lo_len))
                .flat_map(|(x, y)| [*x, *y])
                .chain(a_hi_b_lo.iter().skip(a_lo_len).copied())
                .map(|x| {
                    insert_ciphertext_conversion(
                        uop_graph,
                        x,
                        OutCt::CIPHERTEXT_TYPE,
                        CiphertextType::L1GgswCiphertext,
                    )
                }) // Convert the ciphertexts back to GGSW
                .collect::<Vec<_>>();

            let sum_out = uop_graph.insert_mux_circuit(&adder, &adder_inputs, OutCt::MUX_MODE);

            assert_eq!(lo.len() + sum_out.len(), a.len() + b.len());

            [lo, &sum_out].concat()
        } else {
            // If both operands have high and low pieces, recursively compute the 4
            // partial products and reduce.
            let a_lo_b_lo = mul_impl::<OutCt>(uop_graph, a_lo, b_lo);
            assert_eq!(a_lo_b_lo.len(), a_lo_len + b_lo_len);

            let a_lo_b_hi = mul_impl::<OutCt>(uop_graph, a_lo, b_hi);
            assert_eq!(a_lo_b_hi.len(), a_lo_len + b_hi_len);

            let a_hi_b_lo = mul_impl::<OutCt>(uop_graph, a_hi, b_lo);
            assert_eq!(a_hi_b_lo.len(), a_hi_len + b_lo_len);

            let a_hi_b_hi = mul_impl::<OutCt>(uop_graph, a_hi, b_hi);
            assert_eq!(a_hi_b_hi.len(), a_hi_len + b_hi_len);

            // Sequence the bits of the partial values as prescribed in `gradeschool_reduce`.
            // This circuit can sum 4 appropriately shifted values as per the multiplication algorithm.
            let reduction_bits = encode_gradeschool_reduction(
                a.len(),
                b.len(),
                &a_lo_b_lo,
                &a_lo_b_hi,
                &a_hi_b_lo,
                &a_hi_b_hi,
            );

            let reduction_bits = reduction_bits
                .into_iter()
                .map(|x| {
                    insert_ciphertext_conversion(
                        uop_graph,
                        x,
                        CiphertextType::L1GlweCiphertext,
                        CiphertextType::L1GgswCiphertext,
                    )
                })
                .collect::<Vec<_>>();

            let reduction = gradeschool_reduce(a.len(), b.len());

            uop_graph.insert_mux_circuit(&reduction, &reduction_bits, OutCt::MUX_MODE)
        }
    }

    let result = mul_impl::<OutCt>(uop_graph, a, b);

    let (lo, hi) = result.split_at(a.len());

    (lo.to_owned(), hi.to_owned())
}
