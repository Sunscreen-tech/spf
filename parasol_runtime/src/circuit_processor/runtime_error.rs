use log::error;

use crate::{FheEdge, circuit_processor::Task, crypto::ciphertext::Ciphertext};

#[derive(thiserror::Error, Debug, Clone)]
/// An error that occurs when running an FHE circuit. These usually occur when a
/// circuit is malformed (e.g. illegally connecting nodes, using edges incorrectly etc.).
pub struct RuntimeError(pub String);

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl RuntimeError {
    fn error_backtrace(&self) {
        error!(
            "Internal circuit runtime error {}\n at {}",
            self.0,
            std::backtrace::Backtrace::force_capture()
        );
    }

    pub(crate) fn invalid_node_inputs(task: &Task) -> Self {
        let err = Self(format!(
            "Task {:#?} has invalid inputs {:#?}",
            task.op,
            task.inputs.iter().map(|x| x.1).collect::<Vec<_>>()
        ));

        err.error_backtrace();

        err
    }

    pub(crate) fn missing_ciphertext_input(task: &Task, input_type: FheEdge) -> Self {
        let err = Self(format!(
            "Task {:#?} is missing input of type {:#?}.",
            task.op, input_type
        ));

        err.error_backtrace();

        err
    }

    pub(crate) fn illegal_sample_extract(coeff: usize) -> Self {
        let err = Self(format!(
            "SampleExtract task has illegal coefficient index {coeff}"
        ));

        err.error_backtrace();

        err
    }

    pub(crate) fn invalid_ciphertext_kind(
        task: &Task,
        ct: &Ciphertext,
        input_type: FheEdge,
    ) -> Self {
        let err = Self(format!(
            "Task {:#?} got invalid ciphertext type {:#?} for input {:#?}",
            task.op,
            ct.kind_str(),
            input_type
        ));

        err.error_backtrace();

        err
    }

    pub(crate) fn illegal_retire_op() -> Self {
        let err = Self(format!("Encountered an illegal Retire operation"));

        err.error_backtrace();

        err
    }
}
