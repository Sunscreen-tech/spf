use std::{marker::PhantomData, mem::size_of, sync::Arc};

use crate::{
    circuits::mul::append_uint_multiply, crypto::PublicKey, safe_bincode::GetSize, Encryption,
    Evaluation, FheEdge, FheOp, L1GgswCiphertext, L1GlweCiphertext, L1LweCiphertext, SecretKey,
};

use super::{bit::BitNode, CiphertextOps, FheCircuitCtx, Muxable, PolynomialCiphertextOps};

use bumpalo::Bump;
use concurrency::AtomicRefCell;
use mux_circuits::{
    add::ripple_carry_adder,
    and::make_and_circuit,
    comparisons::{compare_equal, compare_not_equal, compare_or_maybe_equal},
    sub::full_subtractor,
};
use petgraph::stable_graph::NodeIndex;
use serde::{Deserialize, Serialize};
use sunscreen_tfhe::entities::Polynomial;

/// A collection of graph nodes resulting from FHE operations over unsigned integers (e.g. the
/// result of adding two 7-bit unsigned values).
///
/// # Remarks
/// This integer is in unpacked form, meaning each bit resides in a different ciphertext of type `T`.
pub struct UIntGraphNodes<'a, const N: usize, T: CiphertextOps> {
    /// The unsigned integer's [`BitNode`]s from least to most significant.
    pub bits: &'a [BitNode<T>],
}

impl<'a, const N: usize, T: CiphertextOps> UIntGraphNodes<'a, N, T> {
    pub(crate) fn from_nodes<I: Iterator<Item = NodeIndex>>(
        iter: I,
        bump: &'a Bump,
    ) -> UIntGraphNodes<'a, N, T> {
        let nodes: &mut [BitNode<T>] = bump.alloc_slice_fill_default(N);

        for (idx, bit_node) in iter.zip(nodes.iter_mut()) {
            bit_node.node = idx
        }

        Self { bits: nodes }
    }

    fn from_bit_nodes<I: Iterator<Item = BitNode<T>>>(
        iter: I,
        bump: &'a Bump,
    ) -> UIntGraphNodes<'a, N, T> {
        let nodes: &mut [BitNode<T>] = bump.alloc_slice_fill_default(N);

        for (idx, bit_node) in iter.zip(nodes.iter_mut()) {
            *bit_node = idx
        }

        Self { bits: nodes }
    }

    /// Convert this [`UIntGraphNodes<T>`] to a [`UIntGraphNodes<U>`]. Usually, you'll use this
    /// to convert to [`L1GgswCiphertext`] so you can perform arithmetic computation over integers.
    pub fn convert<U: CiphertextOps>(&self, graph: &'a FheCircuitCtx) -> UIntGraphNodes<'a, N, U> {
        let iter = self.bits.iter().map(|x| x.convert(graph));

        UIntGraphNodes::from_bit_nodes(iter, &graph.allocator)
    }

    /// Add output nodes to the computation for each of this unsigned integer's bits.
    /// When the [`FheCircuitCtx`]'s DAG finishes computing, the returned [`UInt<N, T>`] will encrypt
    /// the result of this unsigned integer's DAG nodes.
    ///
    /// # Remarks
    /// The returned [`UInt`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::UOpProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::UOpProcessor::spawn_graph`]
    /// is running.
    pub fn collect_outputs(&self, ctx: &FheCircuitCtx, enc: &Encryption) -> UInt<N, T> {
        let result = UInt::new(enc);

        for (prev, res) in self.bits.iter().zip(result.bits.iter()) {
            let mut circuit = ctx.circuit.borrow_mut();

            let output = circuit.add_node(T::graph_output(res));
            circuit.add_edge(prev.node, output, FheEdge::Unary);
        }

        result
    }

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

impl<const N: usize> UIntGraphNodes<'_, N, L1GlweCiphertext> {
    /// Convert this unpacked unsigned integer to packed form.
    ///
    /// # Remarks
    /// This requires T be an [`L1GlweCiphertext`]. If required, use [`Self::convert`] to get into
    /// this form.
    pub fn pack(
        &self,
        ctx: &FheCircuitCtx,
        enc: &Encryption,
    ) -> PackedUIntGraphNode<N, L1GlweCiphertext> {
        assert!(N <= enc.params.l1_poly_degree().0);
        assert!(N > 0);

        let log_n = N.next_power_of_two().ilog2();

        // Multiply the i'th bit polynomial by x^1. When these resultant
        // polynomials are summed, the i'th bit will appear in the x^i
        // term.
        let shifted = self
            .bits
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let mut circuit = ctx.circuit.borrow_mut();

                if i > 0 {
                    let rot = circuit.add_node(FheOp::MulXN(i));
                    circuit.add_edge(x.node, rot, FheEdge::Unary);

                    rot
                } else {
                    x.node
                }
            })
            .collect::<Vec<_>>();

        let mut reduction = shifted;

        // Perform a tree reduction to sum the shifted ciphertexts.
        for _ in 0..log_n {
            assert!(reduction.len() > 1);

            let next = reduction
                .chunks(2)
                .map(|x| {
                    if x.len() == 1 {
                        x[0]
                    } else {
                        let mut circuit = ctx.circuit.borrow_mut();

                        let add = circuit.add_node(FheOp::GlweAdd);
                        circuit.add_edge(x[0], add, FheEdge::Left);
                        circuit.add_edge(x[1], add, FheEdge::Right);

                        add
                    }
                })
                .collect::<Vec<_>>();

            reduction = next;
        }

        assert_eq!(reduction.len(), 1);

        PackedUIntGraphNode {
            id: reduction[0],
            _phantom: PhantomData,
        }
    }
}

impl<'a, const N: usize> UIntGraphNodes<'a, N, L1GgswCiphertext> {
    pub(crate) fn cmp<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
        gt: bool,
        eq: bool,
    ) -> BitNode<OutCt> {
        let max_len = M.max(N);
        let mux_circuit = compare_or_maybe_equal(max_len, gt, eq);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(M).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(N).flat_map(|x| [zero, x.node]))
            .collect::<Vec<_>>();

        let gt = ctx.circuit.borrow_mut().insert_mux_circuit(
            &mux_circuit,
            &interleaved,
            OutCt::MUX_MODE,
        );

        BitNode {
            node: gt[0],
            _phantom: PhantomData,
        }
    }

    /// Compute `self == other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn eq<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        let max_len = M.max(N);
        let mux_circuit = compare_equal(max_len);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(M).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(N).flat_map(|x| [zero, x.node]))
            .collect::<Vec<_>>();

        let eq = ctx.circuit.borrow_mut().insert_mux_circuit(
            &mux_circuit,
            &interleaved,
            OutCt::MUX_MODE,
        );

        BitNode {
            node: eq[0],
            _phantom: PhantomData,
        }
    }

    /// Compute `self != other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn neq<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        let max_len = M.max(N);
        let mux_circuit = compare_not_equal(max_len);

        let zero = ctx.circuit.borrow_mut().add_node(FheOp::ZeroGgsw1);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .chain(self.bits.iter().skip(M).flat_map(|x| [x.node, zero]))
            .chain(other.bits.iter().skip(N).flat_map(|x| [zero, x.node]))
            .collect::<Vec<_>>();

        let eq = ctx.circuit.borrow_mut().insert_mux_circuit(
            &mux_circuit,
            &interleaved,
            OutCt::MUX_MODE,
        );

        BitNode {
            node: eq[0],
            _phantom: PhantomData,
        }
    }

    /// Compute `self > other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn gt<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, true, false)
    }

    /// Compute `self >= other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn ge<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, true, true)
    }

    /// Compute `self < other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn lt<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, false, false)
    }

    /// Compute `self <= other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn le<const M: usize, OutCt: Muxable>(
        &self,
        other: &UIntGraphNodes<M, L1GgswCiphertext>,
        ctx: &FheCircuitCtx,
    ) -> BitNode<OutCt> {
        self.cmp(other, ctx, false, true)
    }

    /// Compute `self - other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn sub<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> UIntGraphNodes<'a, N, OutCt> {
        let mux_circuit = full_subtractor(N, false);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        UIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(N),
            &ctx.allocator,
        )
    }

    /// Compute `self & other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn and<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> UIntGraphNodes<'a, N, OutCt> {
        let mux_circuit = make_and_circuit(N as u16);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        UIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(N),
            &ctx.allocator,
        )
    }

    /// Compute `self + other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn add<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> UIntGraphNodes<'a, N, OutCt> {
        let mux_circuit = ripple_carry_adder(N, N, false);

        let interleaved = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .flat_map(|(a, b)| [a.node, b.node])
            .collect::<Vec<_>>();

        UIntGraphNodes::from_nodes(
            ctx.circuit
                .borrow_mut()
                .insert_mux_circuit(&mux_circuit, &interleaved, OutCt::MUX_MODE)
                .iter()
                .copied()
                .take(N),
            &ctx.allocator,
        )
    }

    /// Compute `self * other`.
    ///
    /// # Remarks
    /// Requires `self` and `other` to be [`L1GgswCiphertext`]s. Use [`Self::convert`] to
    /// change to this type.
    pub fn mul<OutCt: Muxable>(
        &self,
        other: &Self,
        ctx: &'a FheCircuitCtx,
    ) -> UIntGraphNodes<'a, N, OutCt> {
        let a = self.bits.iter().map(|x| x.node).collect::<Vec<_>>();

        let b = other.bits.iter().map(|x| x.node).collect::<Vec<_>>();

        let (lo, _hi) = append_uint_multiply::<OutCt>(&mut ctx.circuit.borrow_mut(), &a, &b);

        // TODO: prune the high bits somehow?

        UIntGraphNodes::from_nodes(lo.into_iter(), &ctx.allocator)
    }
}

/// A graph node that represents an unsigned integer in packed form. See [`PackedUInt`] for a
/// description of packing.
pub struct PackedUIntGraphNode<const N: usize, T: CiphertextOps + PolynomialCiphertextOps> {
    id: NodeIndex,
    _phantom: PhantomData<T>,
}

impl<const N: usize> PackedUIntGraphNode<N, L1GlweCiphertext> {
    /// Convert this integer into unpacked form, where each bit appears in a different ciphertext.
    pub fn unpack<'a>(&self, ctx: &'a FheCircuitCtx) -> UIntGraphNodes<'a, N, L1LweCiphertext> {
        let nodes = (0..N).map(|i| {
            let mut circuit = ctx.circuit.borrow_mut();

            let se = circuit.add_node(FheOp::SampleExtract(i));
            circuit.add_edge(self.id, se, FheEdge::Unary);

            se
        });

        UIntGraphNodes::from_nodes(nodes, &ctx.allocator)
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps> PackedUIntGraphNode<N, T> {
    /// Create an output node in the graph and return the ciphertext.
    ///
    /// # Remarks
    /// The returned [`UInt`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::UOpProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::UOpProcessor::spawn_graph`]
    /// is running.
    pub fn collect_output(&self, ctx: &FheCircuitCtx, enc: &Encryption) -> PackedUInt<N, T> {
        let result = Arc::new(AtomicRefCell::new(T::allocate(enc)));

        let mut circuit = ctx.circuit.borrow_mut();

        let out_node = circuit.add_node(T::graph_output(&result));
        circuit.add_edge(self.id, out_node, FheEdge::Unary);

        PackedUInt { ct: result }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// An unsigned integer store in unpacked form. An `N`-bit unsigned integer encrypts its bits in
/// `N` different ciphertexts of type `T`.
pub struct UInt<const N: usize, T: CiphertextOps> {
    /// The ciphertexts encrypting this unsigned integer's bits in least-to-most significant order.
    pub bits: Vec<Arc<AtomicRefCell<T>>>,
}

impl<const N: usize, T: CiphertextOps> GetSize for UInt<N, T> {
    fn get_size(params: &crate::Params) -> usize {
        N * T::get_size(params) + size_of::<u64>()
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        for b in &self.bits {
            b.borrow().check_is_valid(params)?;
        }

        Ok(())
    }
}

impl<const N: usize, T> UInt<N, T>
where
    T: CiphertextOps,
{
    /// Allocate a new UInt using trivial or precomputed (if T is [`L1GgswCiphertext`]) encryptions
    /// of zero.
    pub fn new(enc: &Encryption) -> Self {
        Self {
            bits: (0..N)
                .map(|_| Arc::new(AtomicRefCell::new(T::allocate(enc))))
                .collect(),
        }
    }

    /// Create a [`UInt`] from a previously encrypted set of type `T` ciphertexts.
    ///
    /// # Remarks
    /// `bits` are ordered from least to most significant.
    pub fn from_bits(bits: Vec<T>) -> Self {
        Self {
            bits: bits
                .into_iter()
                .map(|x| Arc::new(AtomicRefCell::new(x)))
                .collect(),
        }
    }

    /// Encrypts the given integer.
    ///
    /// # Panics
    /// If `val > 2^N`
    pub fn encrypt_secret(val: u64, enc: &Encryption, sk: &SecretKey) -> Self {
        if val > 0x1 << N {
            panic!("Out of bounds");
        }

        Self {
            bits: (0..N)
                .map(|i| {
                    let ct = T::encrypt_secret((val >> i) & 0x1 == 0x1, enc, sk);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
        }
    }

    /// Decrypts this encrypted integer and returns the contained UInt message.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u64 {
        self.with_decryption_fn(|x| x.decrypt(enc, sk))
    }

    /// Add input nodes to the given [`FheCircuitCtx`].
    pub fn graph_inputs<'a>(&self, ctx: &'a FheCircuitCtx) -> UIntGraphNodes<'a, N, T> {
        UIntGraphNodes::from_nodes(
            self.bits
                .iter()
                .map(|b| ctx.circuit.borrow_mut().add_node(T::graph_input(b))),
            &ctx.allocator,
        )
    }

    /// Run a custom (e.g. threshold) decryption algorithm and return the result.
    pub fn with_decryption_fn<F>(&self, f: F) -> u64
    where
        F: Fn(&T) -> bool,
    {
        self.bits.iter().enumerate().fold(0u64, |s, (i, x)| {
            let x = AtomicRefCell::borrow(x);

            s + ((f(&x) as u64) << i)
        })
    }

    /// Create a trivial encryption of `val`.
    ///
    /// # Remarks
    /// If `T` is [`L1GgswCiphertext`], then the result will contain precomputed
    /// rather than trivial ciphertexts.
    pub fn trivial(val: u64, enc: &Encryption, eval: &Evaluation) -> Self {
        if val > 0x1 << N {
            panic!("Out of bounds");
        }

        Self {
            bits: (0..N)
                .map(|i| {
                    let ct = T::trivial_encryption((val >> i) & 0x1 == 0x1, enc, eval);
                    Arc::new(AtomicRefCell::new(ct))
                })
                .collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// An `N`-bit integer encrypted and packed into a single ciphertext of type `T`. Note `T` must
/// allow polynomial messages (e.g. [`L1GlweCiphertext`]).
///
/// # Remarks
/// The plaintext coefficient corresponding to `x**n` contains the `n`-th bit of the integer ordered
/// from least to most significant. For example, the number `10 = 0b1010` would be stored as
/// `0x^0 + 1x^1 + 0x^2 + 1x^3`.
///
/// For integers greater than a few (e.g. 6) bits, packing integers reduces their size for
/// transmission over the wire.
///
/// Packed integers must be unpacked (with [`PackedUIntGraphNode::unpack`]) before you can perform
/// computation.
///
/// # Example
/// ```rust
/// let enc = get_encryption_128();
///
/// let sk = get_secret_keys_128();
/// let pk = get_public_key_128();
/// let (uproc, fc) = make_uproc_128();
///
/// let val = PackedUInt::<16, L1GlweCiphertext>::encrypt(42, &enc, &pk);
///
/// let ctx = FheCircuitCtx::new();
///
/// let as_unpacked = val
///     .graph_input(&ctx)
///     .unpack(&ctx)
///     .collect_outputs(&ctx, &enc);

/// uproc
///     .lock()
///     .unwrap()
///     .run_graph_blocking(&ctx.circuit.borrow(), &fc);
///
/// assert_eq!(as_unpacked.decrypt(&enc, &sk), 42);
/// ```
pub struct PackedUInt<const N: usize, T>
where
    T: CiphertextOps + PolynomialCiphertextOps,
{
    ct: Arc<AtomicRefCell<T>>,
}

impl<const N: usize, T> From<T> for PackedUInt<N, T>
where
    T: CiphertextOps + PolynomialCiphertextOps,
{
    fn from(value: T) -> Self {
        Self {
            ct: Arc::new(AtomicRefCell::new(value)),
        }
    }
}

impl<const N: usize, T: CiphertextOps + PolynomialCiphertextOps> GetSize for PackedUInt<N, T> {
    fn get_size(params: &crate::Params) -> usize {
        T::get_size(params)
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        self.ct.borrow().check_is_valid(params)
    }
}

impl<const N: usize, T> PackedUInt<N, T>
where
    T: CiphertextOps + PolynomialCiphertextOps,
{
    /// Encrypt and pack the given `val` into a single `T` ciphertext.
    /// See [`PackedUInt`] for more details on packing.
    pub fn encrypt(val: u64, enc: &Encryption, pk: &PublicKey) -> Self {
        let msg = Self::encode(val, enc);

        Self {
            ct: Arc::new(AtomicRefCell::new(T::encrypt(&msg, enc, pk))),
        }
    }

    fn encode(val: u64, enc: &Encryption) -> Polynomial<u64> {
        assert!(val < 0x1 << N);
        assert!(N < T::poly_degree(&enc.params).0);

        let mut msg = Polynomial::<u64>::zero(T::poly_degree(&enc.params).0);

        for i in 0..N {
            msg.coeffs_mut()[i] = (val >> i) & 0x1;
        }

        msg
    }

    /// Decrypt this packed encrypted unsigned integer.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> u64 {
        assert!(N < T::poly_degree(&enc.params).0);
        let mut val = 0;

        let poly = <T as PolynomialCiphertextOps>::decrypt(&self.ct.borrow(), enc, sk);

        for i in 0..N {
            val += poly.coeffs()[i] << i;
        }

        val
    }

    /// Creates input nodes in the [`FheCircuitCtx`] graph.
    pub fn graph_input(&self, ctx: &FheCircuitCtx) -> PackedUIntGraphNode<N, T> {
        PackedUIntGraphNode {
            id: ctx.circuit.borrow_mut().add_node(T::graph_input(&self.ct)),
            _phantom: PhantomData,
        }
    }

    /// Trivially encrypt the given value as a [`PackedUInt`].
    pub fn trivial_encrypt(val: u64, enc: &Encryption) -> Self {
        let msg = Self::encode(val, enc);

        Self {
            ct: Arc::new(AtomicRefCell::new(
                <T as PolynomialCiphertextOps>::trivial_encryption(&msg, enc),
            )),
        }
    }

    /// Returns the inner ciphertext.
    pub fn inner(&self) -> T {
        self.ct.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        test_utils::{get_encryption_128, get_public_key_128, get_secret_keys_128, make_uproc_128},
        L0LweCiphertext, L1GlevCiphertext, DEFAULT_128,
    };

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
