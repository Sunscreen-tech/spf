use std::{marker::PhantomData, sync::Arc};

use parasol_concurrency::AtomicRefCell;
use serde::{Deserialize, Serialize};

use super::{CiphertextOps, FheCircuitCtx, uint::UIntGraphNodes};
use crate::{
    Encryption, Evaluation, FheEdge, FheOp, L1GgswCiphertext, L1GlweCiphertext, SecretKey,
    insert_ciphertext_conversion, safe_bincode::GetSize,
};

use petgraph::stable_graph::NodeIndex;

#[derive(Clone, Serialize, Deserialize)]
/// An bit encrypted under ciphertext type `T`.
pub struct Bit<T: CiphertextOps> {
    ct: Arc<AtomicRefCell<T>>,
}

impl<T: CiphertextOps> GetSize for Bit<T> {
    fn get_size(params: &crate::Params) -> usize {
        T::get_size(params)
    }

    fn check_is_valid(&self, params: &crate::Params) -> crate::Result<()> {
        self.ct.borrow().check_is_valid(params)
    }
}

impl<T: CiphertextOps> From<Arc<AtomicRefCell<T>>> for Bit<T> {
    fn from(value: Arc<AtomicRefCell<T>>) -> Self {
        Self { ct: value }
    }
}

impl<T: CiphertextOps> Bit<T> {
    /// Decrypt this bit using the given encryption object and secret key.
    pub fn decrypt(&self, enc: &Encryption, sk: &SecretKey) -> bool {
        self.with_decryption_fn(|x| x.decrypt(enc, sk))
    }

    /// Encrypt a bit under the given secret key.
    pub fn encrypt_secret(val: bool, enc: &Encryption, sk: &SecretKey) -> Self {
        Self {
            ct: Arc::new(AtomicRefCell::new(T::encrypt_secret(val, enc, sk))),
        }
    }

    /// Use this bit as an input to an FHE computation. Adds an `FheOp::Input*` of the appropriate type
    /// corresponding to `T` to the [`FheCircuitCtx`]. Returns a handle to the added [`BitNode`].
    pub fn graph_input(&self, ctx: &FheCircuitCtx) -> BitNode<T> {
        BitNode {
            node: ctx.circuit.borrow_mut().add_node(T::graph_input(&self.ct)),
            _phantom: PhantomData,
        }
    }

    /// Decrypt this bit using a custom (e.g. threshold) decryption function
    pub fn with_decryption_fn<F>(&self, f: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        f(&self.ct.borrow())
    }

    /// Create a trivial encryption of the bit as a `T` ciphertext.
    pub fn trivial_encryption(val: bool, enc: &Encryption, eval: &Evaluation) -> Self {
        Self {
            ct: Arc::new(AtomicRefCell::new(T::trivial_encryption(val, enc, eval))),
        }
    }
}

#[derive(Debug)]
/// A node in an [`FheCircuitCtx`] that represents an encrypted bit of type `T`
pub struct BitNode<T: CiphertextOps> {
    /// The underlying petgraph [`NodeIndex`].
    pub node: NodeIndex,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: CiphertextOps> Clone for BitNode<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: CiphertextOps> Copy for BitNode<T> {}

impl BitNode<L1GgswCiphertext> {
    /// Given two integers `if_true` and `if_false`, adds a computation that returns
    /// `if_true` when this bit encrypts true and `if_false` when this bit encrypts false.
    ///
    /// # Remarks
    /// This operations requires this bit be an [`L1GgswCiphertext`]. You can use [`Self::convert`]
    /// to convert other ciphertext types to this.
    pub fn select<'a, const N: usize>(
        &self,
        if_true: &UIntGraphNodes<'a, N, L1GlweCiphertext>,
        if_false: &UIntGraphNodes<'a, N, L1GlweCiphertext>,
        ctx: &'a FheCircuitCtx,
    ) -> UIntGraphNodes<'a, N, L1GlweCiphertext> {
        let iter = if_true
            .bits
            .iter()
            .zip(if_false.bits.iter())
            .map(|(if_true, if_false)| {
                let mut circuit = ctx.circuit.borrow_mut();
                let mux = circuit.add_node(FheOp::CMux);

                circuit.add_edge(if_false.node, mux, FheEdge::Low);
                circuit.add_edge(if_true.node, mux, FheEdge::High);
                circuit.add_edge(self.node, mux, FheEdge::Sel);

                mux
            });

        UIntGraphNodes::from_nodes(iter, &ctx.allocator)
    }
}

impl<T: CiphertextOps> BitNode<T> {
    /// Add an output node to the computation. When the [`FheCircuitCtx`]'s DAG finishes computing,
    /// the returned [`Bit`] will encrypt the result of this DAG node.
    ///
    /// # Remarks
    /// The returned [`Bit`] has not yet been evaluated and will be a trivial zero until the
    /// computation completes. You should generally submit the computation using
    /// [`crate::UOpProcessor::run_graph_blocking`] before using the returned result.
    ///
    /// Ciphertexts internally use safeguards that will prevent data races, but you may incur
    /// a panic if you attempt to read the ciphertext while [`crate::UOpProcessor::spawn_graph`]
    /// is running.
    pub fn collect_output(&self, ctx: &FheCircuitCtx, enc: &Encryption) -> Bit<T> {
        let mut circuit = ctx.circuit.borrow_mut();
        let output = Arc::new(AtomicRefCell::new(T::allocate(enc)));

        let out_node = circuit.add_node(T::graph_output(&output));
        circuit.add_edge(self.node, out_node, FheEdge::Unary);

        Bit { ct: output }
    }

    /// Add a trivial or precomputed (if GGSW) encryption of one to the graph.
    ///
    /// # Remarks
    /// These encryptions are not guaranteed to be secure, but are useful as constants.
    pub fn one(ctx: &FheCircuitCtx) -> Self {
        let mut circuit = ctx.circuit.borrow_mut();
        let mut one_cache = ctx.one_cache.borrow_mut();

        let one = if let Some(one_node) = one_cache[T::CIPHERTEXT_TYPE as usize] {
            one_node
        } else {
            let one_node = circuit.add_node(T::graph_trivial_one());
            one_cache[T::CIPHERTEXT_TYPE as usize] = Some(one_node);

            one_node
        };

        Self {
            node: one,
            _phantom: PhantomData,
        }
    }

    /// Add a trivial or precomputed (if GGSW) encryption of zero to the graph.
    ///
    /// # Remarks
    /// These encryptions are not guaranteed to be secure, but are useful as constants.
    pub fn zero(ctx: &FheCircuitCtx) -> Self {
        let mut circuit = ctx.circuit.borrow_mut();
        let mut zero_cache = ctx.zero_cache.borrow_mut();

        let zero = if let Some(zero_node) = zero_cache[T::CIPHERTEXT_TYPE as usize] {
            zero_node
        } else {
            let zero_node = circuit.add_node(T::graph_trivial_zero());
            zero_cache[T::CIPHERTEXT_TYPE as usize] = Some(zero_node);

            zero_node
        };

        Self {
            node: zero,
            _phantom: PhantomData,
        }
    }

    /// Convert this [`BitNode<T>`] to type [`BitNode<U>`]. Generally, you'll convert ciphertexts to
    /// `GGSW` to perform computation.
    pub fn convert<U: CiphertextOps>(&self, ctx: &FheCircuitCtx) -> BitNode<U> {
        let node = insert_ciphertext_conversion(
            &mut ctx.circuit.borrow_mut(),
            self.node,
            T::CIPHERTEXT_TYPE,
            U::CIPHERTEXT_TYPE,
        );

        BitNode {
            node,
            _phantom: PhantomData,
        }
    }
}

impl<T: CiphertextOps> Default for BitNode<T> {
    fn default() -> Self {
        Self {
            node: NodeIndex::default(),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{
        DEFAULT_128, L0LweCiphertext, L1GlevCiphertext, L1LweCiphertext,
        fluent::CiphertextOps,
        test_utils::{get_encryption_128, get_secret_keys_128},
    };

    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[test]
    fn can_safe_deserialize_bit() {
        fn case<T: CiphertextOps + for<'a> Deserialize<'a> + Serialize>() {
            let enc = get_encryption_128();
            let sk = get_secret_keys_128();

            let val = Bit::<T>::encrypt_secret(true, &enc, &sk);

            let ser = bincode::serialize(&val).unwrap();
            crate::safe_bincode::deserialize::<Bit<T>>(&ser, &DEFAULT_128).unwrap();
        }

        case::<L0LweCiphertext>();
        case::<L1LweCiphertext>();
        case::<L1GlweCiphertext>();
        case::<L1GlevCiphertext>();
    }
}
