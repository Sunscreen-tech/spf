use std::sync::{Arc, atomic::AtomicUsize};

use parasol_concurrency::{AtomicRefCell, Spinlock};

use crate::{
    FheEdge, FheOp, Params, circuit_processor::RuntimeError, crypto::ciphertext::Ciphertext,
};

pub(crate) struct Task {
    pub task_id: usize,
    pub num_deps: AtomicUsize,
    pub op: FheOp,
    pub output: Arc<AtomicRefCell<Option<Ciphertext>>>,
    pub inputs: Vec<(Arc<AtomicRefCell<Option<Ciphertext>>>, FheEdge)>,

    /// Here we use [`Mutex`] rather than a spinlock because we don't need to forcibly
    /// unlock this object for reuse.
    pub dependents: Spinlock<Vec<Arc<Task>>>,

    #[cfg(feature = "debug")]
    deps: Vec<Weak<Task>>,
}

impl Task {
    #[inline]
    pub fn validate(&self, params: &Params) -> Result<(), RuntimeError> {
        self.validate_inputs()?;
        self.validate_op(params)?;

        Ok(())
    }

    #[inline]
    fn validate_op(&self, params: &Params) -> Result<(), RuntimeError> {
        if let FheOp::SampleExtract(x) = &self.op {
            if *x >= params.l1_poly_degree().0 {
                return Err(RuntimeError::illegal_sample_extract(*x));
            }
        }

        Ok(())
    }

    #[inline]
    fn validate_op_input(&self, edge: FheEdge, ct: &Option<Ciphertext>) -> Result<(), RuntimeError> {
        if ct.is_none() {
            return Err(RuntimeError::missing_ciphertext_input(self, FheEdge::Unary));
        }

        let ct = ct.as_ref().unwrap();

        let is_valid =
            match (&self.op, edge) {
                (FheOp::OutputLwe0(_), FheEdge::Unary)
                | (FheOp::CircuitBootstrap, FheEdge::Unary) => ct.is_lwe0(),
                (FheOp::OutputLwe1(_), FheEdge::Unary)
                | (FheOp::KeyswitchL1toL0, FheEdge::Unary) => ct.is_lwe1(),
                (FheOp::OutputGlwe1(_), FheEdge::Unary)
                | (FheOp::SampleExtract(_), FheEdge::Unary)
                | (FheOp::MulXN(_), FheEdge::Unary)
                | (FheOp::Not, FheEdge::Unary)
                | (FheOp::GlweAdd, FheEdge::Left)
                | (FheOp::GlweAdd, FheEdge::Right)
                | (FheOp::CMux, FheEdge::Low)
                | (FheOp::CMux, FheEdge::High)
                | (FheOp::MultiplyGgswGlwe, FheEdge::Glwe) => ct.is_glwe1(),
                (FheOp::OutputGlev1(_), FheEdge::Unary)
                | (FheOp::GlevCMux, FheEdge::Low)
                | (FheOp::GlevCMux, FheEdge::High)
                | (FheOp::SchemeSwitch, FheEdge::Unary) => ct.is_glev1(),
                (FheOp::OutputGgsw1(_), FheEdge::Unary)
                | (FheOp::CMux, FheEdge::Sel)
                | (FheOp::GlevCMux, FheEdge::Sel)
                | (FheOp::MultiplyGgswGlwe, FheEdge::Ggsw) => ct.is_ggsw1(),
                _ => unreachable!(),
            };

        if !is_valid {
            Err(RuntimeError::invalid_ciphertext_kind(self, ct, edge))
        } else {
            Ok(())
        }
    }

    #[inline]
    /// Validate that this task has the correct dependencies and arguments.
    fn validate_inputs(&self) -> Result<(), RuntimeError> {
        match &self.op {
            FheOp::InputLwe0(_)
            | FheOp::InputLwe1(_)
            | FheOp::InputGlwe1(_)
            | FheOp::InputGgsw1(_)
            | FheOp::InputGlev1(_)
            | FheOp::ZeroLwe0
            | FheOp::OneLwe0
            | FheOp::ZeroGlwe1
            | FheOp::OneGlwe1
            | FheOp::ZeroGgsw1
            | FheOp::OneGgsw1
            | FheOp::ZeroGlev1
            | FheOp::OneGlev1
            | FheOp::Nop
            | FheOp::Retire => {
                if !self.inputs.is_empty() {
                    Err(RuntimeError::invalid_node_inputs(self))?;
                }
            }
            FheOp::OutputLwe0(_)
            | FheOp::OutputLwe1(_)
            | FheOp::OutputGlwe1(_)
            | FheOp::OutputGgsw1(_)
            | FheOp::OutputGlev1(_)
            | FheOp::SampleExtract(_)
            | FheOp::KeyswitchL1toL0
            | FheOp::Not
            | FheOp::CircuitBootstrap
            | FheOp::SchemeSwitch
            | FheOp::MulXN(_) => {
                if self.inputs.len() != 1 || !matches!(self.inputs[0].1, FheEdge::Unary) {
                    Err(RuntimeError::invalid_node_inputs(self))?;
                }

                let input = self.inputs[0].0.borrow();
                self.validate_op_input(FheEdge::Unary, &input)?;
            }
            FheOp::GlweAdd => {
                let left = self.inputs.iter().find(|x| matches!(x.1, FheEdge::Left));
                let right = self.inputs.iter().find(|x| matches!(x.1, FheEdge::Right));

                if self.inputs.len() != 2 || left.is_none() || right.is_none() {
                    Err(RuntimeError::invalid_node_inputs(self))?;
                }

                let left = left.unwrap().0.borrow();
                self.validate_op_input(FheEdge::Left, &left)?;

                let right = right.unwrap().0.borrow();
                self.validate_op_input(FheEdge::Right, &right)?;
            }
            FheOp::GlevCMux | FheOp::CMux => {
                let sel = self.inputs.iter().find(|x| matches!(x.1, FheEdge::Sel));
                let low = self.inputs.iter().find(|x| matches!(x.1, FheEdge::Low));
                let high = self.inputs.iter().find(|x| matches!(x.1, FheEdge::High));

                if self.inputs.len() != 3 || sel.is_none() || low.is_none() || high.is_none() {
                    Err(RuntimeError::invalid_node_inputs(self))?;
                }

                let sel = sel.unwrap().0.borrow();
                self.validate_op_input(FheEdge::Sel, &sel)?;

                let low = low.unwrap().0.borrow();
                self.validate_op_input(FheEdge::Low, &low)?;

                let high = high.unwrap().0.borrow();
                self.validate_op_input(FheEdge::High, &high)?;
            }
            FheOp::MultiplyGgswGlwe => {
                let glwe = self.inputs.iter().find(|x| matches!(x.1, FheEdge::Glwe));
                let ggsw = self.inputs.iter().find(|x| matches!(x.1, FheEdge::Ggsw));

                if self.inputs.len() != 2 || glwe.is_none() || ggsw.is_none() {
                    Err(RuntimeError::invalid_node_inputs(self))?;
                }

                let glwe = glwe.unwrap().0.borrow();
                self.validate_op_input(FheEdge::Glwe, &glwe)?;

                let ggsw = ggsw.unwrap().0.borrow();
                self.validate_op_input(FheEdge::Ggsw, &ggsw)?;
            }
        }

        Ok(())
    }
}
