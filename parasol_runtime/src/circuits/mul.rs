use mux_circuits::{
    add::ripple_carry_adder,
    mul::{
        encode_gradeschool_reduction, gradeschool_reduce, partition_integer, unsigned_multiplier,
    },
    neg::negator,
};
use petgraph::stable_graph::NodeIndex;

use crate::{
    FheEdge, FheOp, L1GlweCiphertext,
    crypto::ciphertext::CiphertextType,
    fhe_circuit::{FheCircuit, MuxMode, insert_ciphertext_conversion},
    fluent::Muxable,
};

/// Compute the product of 2 N-bit signed values a and b.
pub fn append_int_multiply<OutCt: Muxable>(
    uop_graph: &mut FheCircuit,
    a: &[NodeIndex],
    b: &[NodeIndex],
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let abs_a = abs(uop_graph, a);
    let abs_b = abs(uop_graph, b);

    let pos_product = mul_impl::<L1GlweCiphertext>(uop_graph, &abs_a, &abs_b);
    let pos_product_ggsw = pos_product
        .iter()
        .map(|&x| {
            insert_ciphertext_conversion(
                uop_graph,
                x,
                CiphertextType::L1GlweCiphertext,
                CiphertextType::L1GgswCiphertext,
            )
        })
        .collect::<Vec<_>>();
    let neg_product = neg(uop_graph, &pos_product_ggsw);
    let s1 = *a.last().unwrap();
    let s2 = *b.last().unwrap();

    let result = pos_product
        .iter()
        .zip(neg_product.iter())
        .map(|(&pos, &neg)| {
            let cmux_11 = uop_graph.add_node(FheOp::CMux);
            uop_graph.add_edge(s1, cmux_11, FheEdge::Sel);
            uop_graph.add_edge(pos, cmux_11, FheEdge::Low);
            uop_graph.add_edge(neg, cmux_11, FheEdge::High);

            let cmux_12 = uop_graph.add_node(FheOp::CMux);
            uop_graph.add_edge(s1, cmux_12, FheEdge::Sel);
            uop_graph.add_edge(neg, cmux_12, FheEdge::Low);
            uop_graph.add_edge(pos, cmux_12, FheEdge::High);

            let cmux_2 = uop_graph.add_node(FheOp::CMux);
            uop_graph.add_edge(s2, cmux_2, FheEdge::Sel);
            uop_graph.add_edge(cmux_11, cmux_2, FheEdge::Low);
            uop_graph.add_edge(cmux_12, cmux_2, FheEdge::High);

            insert_ciphertext_conversion(
                uop_graph,
                cmux_2,
                CiphertextType::L1GlweCiphertext,
                OutCt::CIPHERTEXT_TYPE,
            )
        })
        .collect::<Vec<_>>();

    let (lo, hi) = result.split_at(a.len());

    (lo.to_owned(), hi.to_owned())
}

/// Compute the product of 2 N-bit unsigned values a and b.
pub fn append_uint_multiply<OutCt: Muxable>(
    uop_graph: &mut FheCircuit,
    a: &[NodeIndex],
    b: &[NodeIndex],
) -> (Vec<NodeIndex>, Vec<NodeIndex>) {
    let result = mul_impl::<OutCt>(uop_graph, a, b);

    let (lo, hi) = result.split_at(a.len());

    (lo.to_owned(), hi.to_owned())
}

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

/// Helper function for signed integer multiplication: turn a number into its negation
/// Implementation uses MUX circuits to avoid bootstrapping, thus, input is GGSW and output is GLWE
fn neg(uop_graph: &mut FheCircuit, input: &[NodeIndex]) -> Vec<NodeIndex> {
    let neg_circuit = negator(input.len());

    uop_graph.insert_mux_circuit(&neg_circuit, input, MuxMode::Glwe)
}

/// Helper function for signed integer multiplication: turn a number into its absolute value
/// Input and output are both GGSW
fn abs(uop_graph: &mut FheCircuit, input: &[NodeIndex]) -> Vec<NodeIndex> {
    let input_glwe = input
        .iter()
        .map(|x| {
            insert_ciphertext_conversion(
                uop_graph,
                *x,
                CiphertextType::L1GgswCiphertext,
                CiphertextType::L1GlweCiphertext,
            )
        })
        .collect::<Vec<_>>();

    let neg_input_glwe = neg(uop_graph, input);

    let sel = *input.last().unwrap();

    input_glwe
        .iter()
        .zip(neg_input_glwe.iter())
        .map(|(&bit_for_false, &bit_for_true)| {
            let cmux_node = uop_graph.add_node(FheOp::CMux);
            uop_graph.add_edge(sel, cmux_node, FheEdge::Sel);
            uop_graph.add_edge(bit_for_false, cmux_node, FheEdge::Low);
            uop_graph.add_edge(bit_for_true, cmux_node, FheEdge::High);
            insert_ciphertext_conversion(
                uop_graph,
                cmux_node,
                CiphertextType::L1GlweCiphertext,
                CiphertextType::L1GgswCiphertext,
            )
        })
        .collect()
}
