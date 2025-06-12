use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, Receiver},
};

use crate::circuit_processor::RuntimeError;

/// A callback that fires when all the operations in an [`FheCircuit`](crate::FheCircuit)
/// passed to [`crate::CircuitProcessor::spawn_graph`] or
/// [`crate::CircuitProcessor::run_graph_blocking`] finish.
pub struct CompletionHandler {
    pub(crate) ops_remaining: AtomicUsize,
    pub(crate) callback: Box<dyn Fn(Option<RuntimeError>) + 'static + Sync + Send>,
    pub(crate) error: OnceLock<RuntimeError>,
}

impl CompletionHandler {
    /// Create a [`CompletionHandler`] with the passed callback.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(Option<RuntimeError>) + Sync + Send + 'static,
    {
        Self {
            ops_remaining: AtomicUsize::new(1),
            callback: Box::new(callback),
            error: OnceLock::new(),
        }
    }

    pub(crate) fn dispatch(&self) {
        self.ops_remaining.fetch_add(1, Ordering::Acquire);
    }

    pub(crate) fn retire(&self) {
        if self.ops_remaining.fetch_sub(1, Ordering::Release) == 1 {
            (self.callback)(self.error.get().map(|x| x.to_owned()));
        }
    }

    /// Creates a new [`CompletionHandler`] that notifies the returned recv on completion
    pub fn new_notify() -> (Self, Receiver<Option<RuntimeError>>) {
        let (send, recv) = mpsc::channel();

        (
            Self::new(move |x| send.send(x.map(|x| x.to_owned())).unwrap()),
            recv,
        )
    }
}
