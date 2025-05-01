use std::{borrow::BorrowMut, collections::HashMap, sync::Arc};

use fhe_processor::{FheProcessor, RegisterConfig};
use parasol_concurrency::AtomicRefCell;
use parasol_runtime::{
    Encryption, Evaluation, FheCircuit, L0LweCiphertext, L1GgswCiphertext, L1GlweCiphertext,
    L1LweCiphertext, TrivialOne, TrivialZero, UOpProcessor,
    fluent::{FheCircuitCtx, GenericInt, PackedGenericInt, Sign},
};
use rayon::ThreadPool;
use serde::{Deserialize, Serialize};

use crate::{Error, Memory, Ptr32, Result, Word, tomasulo::scoreboard::ScoreboardEntryRef};

use self::ops::trivially_encrypt_value_l1glwe;

mod args;
pub use args::*;

#[doc(hidden)]
pub mod assembly;
mod ops;

mod fhe_processor;

#[cfg(test)]
mod tests;

pub(crate) use assembly::*;

#[doc(hidden)]
pub enum Ciphertext {
    #[allow(unused)]
    L0Lwe {
        data: Vec<Arc<AtomicRefCell<L0LweCiphertext>>>,
    },
    #[allow(unused)]
    L1Lwe {
        data: Vec<Arc<AtomicRefCell<L1LweCiphertext>>>,
    },
    L1Glwe {
        data: Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>,
    },
    #[allow(unused)]
    L1Ggsw {
        data: Vec<Arc<AtomicRefCell<L1GgswCiphertext>>>,
    },
}

impl Ciphertext {
    pub fn len(&self) -> usize {
        match self {
            Self::L0Lwe { data } => data.len(),
            Self::L1Lwe { data } => data.len(),
            Self::L1Glwe { data } => data.len(),
            Self::L1Ggsw { data } => data.len(),
        }
    }

    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(unused)]
    pub fn unwrap_l1glwe(&self) -> &[Arc<AtomicRefCell<L1GlweCiphertext>>] {
        match self {
            Self::L1Glwe { data } => data,
            _ => panic!("Ciphertext was not L1GlweCiphertext"),
        }
    }

    pub fn try_into_l1glwe(&self) -> Result<&[Arc<AtomicRefCell<L1GlweCiphertext>>]> {
        match self {
            Self::L1Glwe { data } => Ok(data),
            _ => Err(Error::EncryptionMismatch),
        }
    }
}

#[doc(hidden)]
/// The type of value stored in a register.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegisterValueType {
    Plaintext,
    L0LweCiphertext,
    L1LweCiphertext,
    L1GlweCiphertext,
    L1GgswCiphertext,
}

#[doc(hidden)]
pub enum Register {
    Plaintext { val: u128, width: u32 },

    Ciphertext(Ciphertext),
}

impl Register {
    /// How many bits is the value of the register?
    pub fn width(&self) -> usize {
        match self {
            Self::Plaintext { val: _, width } => *width as usize,
            Self::Ciphertext(x) => x.len(),
        }
    }

    /// Is the register a plaintext register?
    pub fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext { val: _, width: _ })
    }

    /// Is the register a ciphertext register?
    pub fn is_ciphertext(&self) -> bool {
        matches!(self, Self::Ciphertext(_))
    }

    /// What type of value is stored in the register?
    pub fn register_value_type(&self) -> RegisterValueType {
        match self {
            Self::Plaintext { val: _, width: _ } => RegisterValueType::Plaintext,
            Self::Ciphertext(Ciphertext::L0Lwe { data: _ }) => RegisterValueType::L0LweCiphertext,
            Self::Ciphertext(Ciphertext::L1Lwe { data: _ }) => RegisterValueType::L1LweCiphertext,
            Self::Ciphertext(Ciphertext::L1Glwe { data: _ }) => RegisterValueType::L1GlweCiphertext,
            Self::Ciphertext(Ciphertext::L1Ggsw { data: _ }) => RegisterValueType::L1GgswCiphertext,
        }
    }

    pub fn from_word(word: &Word) -> Self {
        if word.0[0].is_plaintext() {
            let mut val = 0u128;

            for (i, b) in word.0.iter().enumerate() {
                val |= (b.clone().unwrap_plaintext() as u128) << (8 * i)
            }

            Self::Plaintext { val, width: 32 }
        } else {
            let data = word
                .0
                .iter()
                .flat_map(|x| x.clone().unwrap_ciphertext())
                .collect::<Vec<_>>();

            Self::Ciphertext(Ciphertext::L1Glwe { data })
        }
    }
}

impl Default for Register {
    fn default() -> Self {
        Register::Plaintext { val: 0, width: 32 }
    }
}

/// Checks if the width of two registers is the same.
/// Used inside an instruction implementation.
pub fn check_register_width(
    a: &Register,
    b: &Register,
    instruction_id: usize,
    pc: u32,
) -> Result<()> {
    if a.width() != b.width() {
        return Err(Error::WidthMismatch {
            inst_id: instruction_id,
            pc,
        });
    }

    // TODO, relax the 128-bit limitation.
    if a.width() < 1 || a.width() > 128 {
        return Err(Error::unsupported_width(instruction_id, pc));
    }

    Ok(())
}

/// Convert a plaintext register to a L1 GLWE ciphertext register, or copy
/// the existing ciphertext register if it's already in that form.
///
/// Returns `Err` if the register is not a plaintext or L1 GLWE ciphertext
/// register.
pub fn register_to_l1glwe_by_trivial_lift(
    register: &Register,
    zero: &L1GlweCiphertext,
    one: &L1GlweCiphertext,
) -> Result<Vec<Arc<AtomicRefCell<L1GlweCiphertext>>>> {
    match register {
        Register::Plaintext { val, width } => {
            Ok(trivially_encrypt_value_l1glwe(*val, *width, zero, one))
        }
        Register::Ciphertext(Ciphertext::L1Glwe { data }) => Ok(data.clone()),
        _ => Err(Error::EncryptionMismatch),
    }
}

pub(crate) struct FheProcessorAuxData {
    uop_processor: UOpProcessor,
    flow: std::sync::mpsc::Receiver<()>,
    memory: Option<Arc<Memory>>,
    inflight_memory_ops: HashMap<Ptr32, ScoreboardEntryRef<DispatchIsaOp>>,
    l1glwe_zero: L1GlweCiphertext,
    l1glwe_one: L1GlweCiphertext,
    enc: Encryption,
}

impl FheProcessorAuxData {
    pub fn new(enc: &Encryption, eval: &Evaluation, thread_pool: Option<Arc<ThreadPool>>) -> Self {
        let (uop_processor, flow) = UOpProcessor::new(1024, thread_pool, eval, enc);

        let l1glwe_zero = L1GlweCiphertext::trivial_zero(enc);
        let l1glwe_one = L1GlweCiphertext::trivial_one(enc);

        Self {
            uop_processor,
            flow,
            memory: None,
            inflight_memory_ops: HashMap::new(),
            l1glwe_zero,
            l1glwe_one,
            enc: enc.clone(),
        }
    }
}

/// The Parasol processor that can run programs over encrypted and plaintext data.
pub struct FheComputer {
    processor: FheProcessor,
}

impl FheComputer {
    /// Create a new [`FheComputer`]. Tasks will run on the global [`rayon::ThreadPool`].
    pub fn new(enc: &Encryption, eval: &Evaluation) -> Self {
        let config = RegisterConfig { num_registers: 32 };

        let aux_data = FheProcessorAuxData::new(enc, eval, None);

        let processor = FheProcessor::new(&config, aux_data);

        Self { processor }
    }

    /// Create a new [`FheComputer`]. Tasks will run on the given [`rayon::ThreadPool`].
    pub fn new_with_threadpool(
        enc: &Encryption,
        eval: &Evaluation,
        thread_pool: Arc<ThreadPool>,
    ) -> Self {
        let config = RegisterConfig { num_registers: 32 };

        let aux_data = FheProcessorAuxData::new(enc, eval, Some(thread_pool));

        let processor = FheProcessor::new(&config, aux_data);

        Self { processor }
    }

    /// Run the given FHE program with user specified data and a gas limit, return the used gas and program return value
    pub fn run_program<T: ToArg>(
        &mut self,
        initial_pc: Ptr32,
        memory: &Arc<Memory>,
        args: Args<T>,
        gas_limit: u32,
    ) -> Result<(u32, T)> {
        self.processor
            .run_program(memory, initial_pc, &args, gas_limit)
    }

    /// Run a graph in blocking mode.
    pub(crate) fn run_graph_blocking(&mut self, circuit: &FheCircuit) {
        let uproc = self.processor.aux_data.uop_processor.borrow_mut();
        let fc = &self.processor.aux_data.flow;

        uproc.run_graph_blocking(circuit, fc);
    }

    /// Packs a `GenericInt<N, L1GlweCiphertext, U>` into a `PackedGenericInt<N, L1GlweCiphertext, U>`.
    pub fn pack_int<const N: usize, U: Sign>(
        &mut self,
        input: GenericInt<N, L1GlweCiphertext, U>,
    ) -> PackedGenericInt<N, L1GlweCiphertext, U> {
        let ctx = FheCircuitCtx::new();

        let packed_ct = input
            .graph_inputs(&ctx)
            .pack(&ctx, &self.processor.aux_data.enc)
            .collect_output(&ctx, &self.processor.aux_data.enc);

        self.run_graph_blocking(&ctx.circuit.borrow());
        packed_ct
    }

    /// Unpacks a `PackedGenericInt<N, L1GlweCiphertext, U>` into a `GenericInt<N, L1GlweCiphertext, U>`.
    pub fn unpack_int<const N: usize, U: Sign>(
        &mut self,
        input: PackedGenericInt<N, L1GlweCiphertext, U>,
    ) -> GenericInt<N, L1GlweCiphertext, U> {
        let ctx = FheCircuitCtx::new();

        let unpacked_ct = input
            .graph_input(&ctx)
            .unpack(&ctx)
            .convert(&ctx)
            .collect_outputs(&ctx, &self.processor.aux_data.enc);

        self.run_graph_blocking(&ctx.circuit.borrow());
        unpacked_ct
    }
}

#[cfg(test)]
mod buffer_uint_tests {
    // #[test]
    // fn can_run_on_global_or_local_threadpool() {
    //     fn case(use_global_threadpool: bool) {
    //         let enc = get_encryption_128();
    //         let eval = get_evaluation_128();

    //         let mut cpu = if use_global_threadpool {
    //             FheComputer::new(&enc, &eval)
    //         } else {
    //             FheComputer::new_with_threadpool(&enc, &eval, get_thread_pool())
    //         };

    //         let buffers = vec![
    //             Buffer::cipher_from_value(&32u8, &enc, &get_secret_keys_128()),
    //             Buffer::cipher_from_value(&42u8, &enc, &get_secret_keys_128()),
    //             Buffer::cipher_from_value(&0u8, &enc, &get_secret_keys_128()),
    //         ];

    //         let add_program = &FheProgram {
    //             instructions: vec![
    //                 IsaOp::BindReadOnly(RegisterName::named(0), 0, true),
    //                 IsaOp::BindReadOnly(RegisterName::named(1), 1, true),
    //                 IsaOp::BindReadWrite(RegisterName::named(2), 2, true),
    //                 IsaOp::Load(RegisterName::named(0), RegisterName::named(0), 8),
    //                 IsaOp::Load(RegisterName::named(1), RegisterName::named(1), 8),
    //                 IsaOp::Add(
    //                     RegisterName::named(2),
    //                     RegisterName::named(0),
    //                     RegisterName::named(1),
    //                 ),
    //                 IsaOp::Store(RegisterName::named(2), RegisterName::named(2), 8),
    //             ],
    //         };

    //         cpu.run_program(add_program, &buffers).unwrap();

    //         assert_eq!(
    //             read_result_sk::<u8>(&buffers[2], &enc, &get_secret_keys_128(), true),
    //             74
    //         );
    //     }

    //     case(false);
    //     case(true);
    // }
}
