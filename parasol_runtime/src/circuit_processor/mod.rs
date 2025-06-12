use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
};

use log::trace;
use parasol_concurrency::{AtomicRefCell, Spinlock};
use petgraph::{
    Direction,
    graph::NodeIndex,
    visit::{EdgeRef, Topo},
};
use rayon::{ThreadPool, spawn};

use crate::{
    Encryption, Evaluation,
    crypto::{L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext, L1GlweCiphertext},
    fhe_circuit::{FheCircuit, FheEdge, FheOp},
};

mod completion_handler;
pub use completion_handler::*;
mod runtime_error;
pub use runtime_error::*;
mod task;
use task::*;

#[cfg(test)]
mod tests;

#[cfg(feature = "debug")]
pub fn push_completed(id: usize) {
    static COMPLETED_TASKS: OnceLock<ArrayQueue<usize>> = OnceLock::new();

    let queue = COMPLETED_TASKS.get_or_init(|| ArrayQueue::new(8192));

    queue.force_push(id);
}

#[derive(Clone)]
/// A "backend" processor that runs [`FheCircuit`]s.
///
/// # Remarks
/// This processor is designed to immediately execute circuits' tasks as they are issued. This
/// means that the execution DAG is still being built while it's running. The [`Self::spawn_graph`]
/// and [`Self::run_graph_blocking`] methods take as input an [`FheCircuit`] and begin scheduling
/// the execution DAG. The former method returns when all tasks are scheduled, invoking a passed
/// callback when all complete, while the latter blocks until all tasks are complete.
///
/// To limit memory usage, it features `flow_control` whereby the thread issuing
/// tasks must pass the [`Receiver`] returned by [`CircuitProcessor::new`] to the
/// [`Self::spawn_graph`] and [`Self::run_graph_blocking`] methods, which will block the
/// calling thread when the number of in-flight tasks exceeds the `flow_control` value passed to
/// [`CircuitProcessor::new`].
///
/// The `thread_pool` argument is optional. When set, tasks will be scheduled on the specified
/// threadpool. Otherwise, the global rayon threadpool will be used.
pub struct CircuitProcessor {
    flow_control: SyncSender<()>,
    thread_pool: Option<Arc<ThreadPool>>,
    /// An [`Evaluation`] that can perform FHE operations.
    pub eval: Arc<Evaluation>,
    enc: Arc<Encryption>,
    /// A trivial encryption of zero, wrapped in a whole bunch of nonsense so
    /// they can be shared amongst Zero nodes.
    zero_lwe0: L0LweCiphertext,
    one_lwe0: L0LweCiphertext,
    zero_glwe1: L1GlweCiphertext,
    one_glwe1: L1GlweCiphertext,
    zero_ggsw1: L1GgswCiphertext,
    one_ggsw1: L1GgswCiphertext,
    zero_glev1: L1GlevCiphertext,
    one_glev1: L1GlevCiphertext,
}

impl CircuitProcessor {
    /// Create a new [`CircuitProcessor`]. When `thread_pool` is [`None`], the global rayon threadpool
    /// will be used.
    pub fn new(
        flow_control_len: usize,
        thread_pool: Option<Arc<ThreadPool>>,
        eval: &Evaluation,
        enc: &Encryption,
    ) -> (Self, Receiver<()>) {
        let flow_control = sync_channel(flow_control_len);

        for _ in 0..flow_control_len {
            flow_control.0.send(()).unwrap();
        }

        let zero_lwe0 = enc.trivial_lwe_l0_zero();
        let one_lwe0 = enc.trivial_lwe_l0_one();

        let zero_glwe1 = enc.trivial_glwe_l1_zero();
        let one_glwe1 = enc.trivial_glwe_l1_one();

        let zero_ggsw1 = eval.l1ggsw_zero().to_owned();
        let one_ggsw1 = eval.l1ggsw_one().to_owned();

        let zero_glev1 = enc.trivial_glev_l1_zero();
        let one_glev1 = enc.trivial_glev_l1_one();

        let proc = Self {
            flow_control: flow_control.0,
            thread_pool,
            eval: Arc::new(eval.clone()),
            enc: Arc::new(enc.clone()),
            zero_lwe0,
            one_lwe0,
            zero_glwe1,
            one_glwe1,
            zero_ggsw1,
            one_ggsw1,
            zero_glev1,
            one_glev1,
        };

        (proc, flow_control.1)
    }

    /// Dispatch an operation
    ///
    /// # Remarks
    /// Only one thread should dispatch operations at a time, as locking correctness
    /// requires this. Hence the `&mut self`.
    fn dispatch(
        &mut self,
        flow_control: &Receiver<()>,
        task: FheOp,
        deps: &[(Arc<Task>, FheEdge)],
        parent_op: Arc<CompletionHandler>,
    ) -> Arc<Task> {
        static TASK_ID: AtomicUsize = AtomicUsize::new(0);

        flow_control.recv().unwrap();

        // Increase the notify ref count for non-retire instructions.
        if !matches!(task, FheOp::Retire) {
            parent_op.dispatch();
        }

        let mut inputs = vec![];

        for t in deps.iter() {
            inputs.push((t.0.output.clone(), t.1));
        }

        let new_task = Arc::new(Task {
            task_id: TASK_ID.fetch_add(1, Ordering::Relaxed),
            op: task,
            output: Arc::new(AtomicRefCell::new(None)),
            inputs,
            dependents: Spinlock::new(vec![]),
            num_deps: AtomicUsize::new(1),

            #[cfg(feature = "debug")]
            deps: deps.iter().map(|x| Arc::downgrade(&x.0)).collect(),
        });

        trace!("Dispatching task {}", new_task.task_id);

        let parent_op = parent_op.clone();

        for dep in deps {
            // If we acquire the lock, then add ourselves as a dependant and increase the
            // dependency count. Otherwise the dependent task has already completed
            // and notified its subscribers. However, its data is immediately available for
            // use, so we don't update our dependency count, hence nothing needed for the
            // else branch
            if let Some(mut x) = dep.0.dependents.try_lock() {
                new_task.num_deps.fetch_add(1, Ordering::Acquire);
                x.push(new_task.clone());
            }
        }

        if new_task.num_deps.fetch_sub(1, Ordering::Release) == 1 {
            Self::execute_task(&Arc::new(self.clone()), new_task.clone(), parent_op);
        } else {
            trace!(
                "Task blocked on approximately {} dependencies",
                new_task.num_deps.load(Ordering::Relaxed)
            );
        }

        new_task
    }

    fn execute_task(
        uproc: &Arc<Self>,
        task: Arc<Task>,
        completion_handler: Arc<CompletionHandler>,
    ) {
        trace!("Running task {} {:#?}", task.task_id, task.op);

        let uproc_clone = uproc.clone();

        let spawn_wrapper = |task| {
            if let Some(tp) = &uproc.thread_pool {
                tp.spawn(task);
            } else {
                spawn(task);
            }
        };

        spawn_wrapper(move || {
            // Ensure our inputs are visible. This fence should match the one below
            // that our dependencies called.
            std::sync::atomic::fence(Ordering::Acquire);

            // If we've already errored, this task becomes a no-op. We'll continue
            // processing our dependents and let them error to avoid memory leaks
            // due to bad ref-counts.
            if completion_handler.error.get().is_none() {
                if let Err(e) = Self::exec_op(&uproc_clone, &task) {
                    // If another thread errored and beat us, whatever. We'll use that
                    // error.
                    let _ = completion_handler.error.set(e);
                }
            }

            // Ensure that our output is visible to other threads. Acquiring the lock below
            // only installs an Acquire fence, so hardware can move the output write beyond
            // the lock.
            std::sync::atomic::fence(Ordering::Release);

            #[cfg(feature = "debug")]
            push_completed(task.task_id);

            // At this point, our output has been written so we can notify our dependencies
            // their data is available. Dependents contending on this lock can just back off
            // and immediately use the data.
            let mut deps = task.dependents.lock();

            // Notify our dependents that we've finished, which means our output buffer is
            // available for use.
            while let Some(dep) = deps.pop() {
                if dep.num_deps.fetch_sub(1, Ordering::Release) == 1 {
                    Self::execute_task(&uproc_clone, dep, completion_handler.clone());
                }
            }

            // When this instruction retires, keep the mutex locked so any future dependents
            // will just be able to immediately use our data.
            std::mem::forget(deps);

            uproc_clone.flow_control.send(()).unwrap();
            completion_handler.retire();
        });
    }

    fn exec_op(proc: &CircuitProcessor, task: &Task) -> Result<(), RuntimeError> {
        task.validate(&proc.eval.params)?;

        match &task.op {
            FheOp::InputLwe0(x) => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputLwe1(x) => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputGlwe1(x) => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputGgsw1(x) => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputGlev1(x) => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::OutputLwe0(x) => {
                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputLwe1(x) => {
                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputGlwe1(x) => {
                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputGgsw1(x) => {
                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputGlev1(x) => {
                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::CircuitBootstrap => {
                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_lwe0();

                let mut res = proc.enc.allocate_ggsw_l1();

                proc.eval.circuit_bootstrap(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                *output = Some(res.into());
            }
            FheOp::Not => {
                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_glwe1();

                let mut res = proc.enc.allocate_glwe_l1();

                proc.eval.not(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::GlweAdd => {
                // Grab both operands. Since addition commutes, we won't concern ourselves
                // with appropriately selecting the left and right, but just add them
                // in arbitrary order.
                let a = AtomicRefCell::borrow(&task.inputs[0].0);
                let a = a.as_ref().unwrap().borrow_glwe1();

                let b = AtomicRefCell::borrow(&task.inputs[1].0);
                let b = b.as_ref().unwrap().borrow_glwe1();

                let mut res = proc.enc.allocate_glwe_l1();
                proc.eval.xor(&mut res, a, b);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::MultiplyGgswGlwe => {
                let glwe = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Glwe))
                    .unwrap();
                let glwe = AtomicRefCell::borrow(&glwe.0);
                let glwe = glwe.as_ref().unwrap().borrow_glwe1();

                let ggsw = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Ggsw))
                    .unwrap();
                let ggsw = AtomicRefCell::borrow(&ggsw.0);
                let ggsw = ggsw.as_ref().unwrap().borrow_ggsw1();

                let mut res = proc.enc.allocate_glwe_l1();
                proc.eval.multiply_glwe_ggsw(&mut res, glwe, ggsw);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::CMux => {
                let a = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Low))
                    .unwrap();
                let a = AtomicRefCell::borrow(&a.0);
                let a = a.as_ref().unwrap().borrow_glwe1();

                let b = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::High))
                    .unwrap();
                let b = AtomicRefCell::borrow(&b.0);
                let b = b.as_ref().unwrap().borrow_glwe1();

                let sel = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Sel))
                    .unwrap();
                let sel = AtomicRefCell::borrow(&sel.0);
                let sel = sel.as_ref().unwrap().borrow_ggsw1();

                let mut res = proc.enc.allocate_glwe_l1();
                proc.eval.cmux(&mut res, sel, a, b);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::GlevCMux => {
                let a = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Low))
                    .unwrap();
                let a = AtomicRefCell::borrow(&a.0);
                let a = a.as_ref().unwrap().borrow_glev1();

                let b = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::High))
                    .unwrap();
                let b = AtomicRefCell::borrow(&b.0);
                let b = b.as_ref().unwrap().borrow_glev1();

                let sel = task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Sel))
                    .unwrap();
                let sel = AtomicRefCell::borrow(&sel.0);
                let sel = sel.as_ref().unwrap().borrow_ggsw1();

                let mut res = proc.enc.allocate_glev_l1();
                proc.eval.glev_cmux(&mut res, sel, a, b);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::KeyswitchL1toL0 => {
                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_lwe1();

                let mut res = proc.enc.allocate_lwe_l0();

                proc.eval.keyswitch_lwe_l1_lwe_l0(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::SampleExtract(idx) => {
                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_glwe1();

                let mut res = proc.enc.allocate_lwe_l1();

                proc.eval.sample_extract_l1(&mut res, input, *idx);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::ZeroLwe0 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_lwe0.clone().into());
            }
            FheOp::OneLwe0 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_lwe0.clone().into());
            }
            FheOp::ZeroGlwe1 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_glwe1.clone().into());
            }
            FheOp::OneGlwe1 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_glwe1.clone().into());
            }
            FheOp::ZeroGgsw1 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_ggsw1.clone().into());
            }
            FheOp::OneGgsw1 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_ggsw1.clone().into());
            }
            FheOp::ZeroGlev1 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_glev1.clone().into());
            }
            FheOp::OneGlev1 => {
                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_glev1.clone().into());
            }
            FheOp::MulXN(n) => {
                let input = &task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Unary))
                    .unwrap()
                    .0;
                let input = AtomicRefCell::borrow(input);
                let input = input.as_ref().unwrap().borrow_glwe1();

                let mut res = proc.enc.allocate_glwe_l1();

                proc.eval.mul_xn(&mut res, input, *n);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::SchemeSwitch => {
                let input = &task
                    .inputs
                    .iter()
                    .find(|x| matches!(x.1, FheEdge::Unary))
                    .unwrap()
                    .0;
                let input = AtomicRefCell::borrow(input);
                let input = input.as_ref().unwrap().borrow_glev1();

                let mut res = proc.enc.allocate_ggsw_l1();

                proc.eval.scheme_switch(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::Retire => {}
            FheOp::Nop => {}
        }

        Ok(())
    }

    /// Dispatch a graph of tasks to execute subject to flow control.
    ///
    /// # Remarks
    /// Does not block. Invokes the [`CompletionHandler`] when execution finishes.
    /// Attempting to decrypt or otherwise use graph outputs before completion may
    /// result in incorrect answers or may cause underlying [`AtomicRefCell`]s to
    /// panic.
    ///
    /// # Panics
    /// The [`FheCircuit`] graph isn't validated until each individual operation is
    /// scheduled to run. Passing a malformed graph will result in a panic, usually
    /// *on another thread*. Without a debugger attached, this tends to manifest
    /// as a SIGABRT.
    ///
    /// As mentioned above, you must guarantee no outputs of the [`FheCircuit`] are
    /// read until you [`CompletionHandler`] is invoked, lest a race condition occurs.
    /// The underlying [`AtomicRefCell`]s at least ensure a panic occurs rather than
    /// undefined behavior.
    ///
    /// # Incorrect behavior
    /// Passing a graph with a cycle will result in arbitrary behavior and may
    /// give an incorrect answer or result in an error. However, the behavior will
    /// comply with Rust soundness guarantees, won't panic, or leak memory.
    ///
    /// Furthermore, your input circuit must not contain any retire operations.
    pub fn spawn_graph(
        &mut self,
        circuit: &FheCircuit,
        flow_control: &Receiver<()>,
        on_completion: Arc<CompletionHandler>,
    ) {
        let mut iter = Topo::new(&circuit.graph);
        let mut tasks: HashMap<NodeIndex, (Arc<Task>, usize)> = HashMap::new();

        while let Some(idx) = iter.next(&circuit.graph) {
            let mut deps = vec![];

            for e in circuit.graph.edges_directed(idx, Direction::Incoming) {
                let dep_idx = e.source();
                let (dep, count) = tasks.get(&dep_idx).unwrap();
                deps.push((dep.clone(), *e.weight()));

                let new_count = count - 1;

                // If we've visited all the dependents remove the entry. This will allow
                // the TaskHandle Arcs to dynamically free buffers when allowed.
                if new_count == 0 {
                    tasks.remove(&dep_idx);
                } else {
                    tasks.insert(dep_idx, (dep.clone(), new_count));
                }
            }

            let dep_count = circuit
                .graph
                .edges_directed(idx, Direction::Outgoing)
                .count();

            let op = circuit.graph.node_weight(idx).unwrap();

            // User graphs should never have Retire in them.
            if !matches!(op, FheOp::Retire) {
                let task = self.dispatch(flow_control, op.clone(), &deps, on_completion.clone());

                tasks.insert(idx, (task, dep_count));
            } else {
                // Another thread may have beaten us in erroring and that's okay.
                let _ = on_completion.error.set(RuntimeError::illegal_retire_op());
                break;
            }
        }

        // Dispatch a retire operation to indicate there will be no more operations
        // dispatched for this instruction.
        self.dispatch(flow_control, FheOp::Retire, &[], on_completion);
    }

    /// Dispatches the graph and blocks for its execution to complete.
    ///
    /// # Remarks
    /// This is a blocking wrapper of [`Self::spawn_graph`].
    ///
    /// # Panics
    /// The same correctness conditions hold as with [`Self::spawn_graph`].
    /// However, reading circuit outputs before they're ready is significantly harder
    /// to accidentally do because this operation blocks.
    ///
    /// # Incorrect behavior
    /// Passing a graph with a cycle will result in arbitrary behavior and may
    /// give an incorrect answer or result in an error. However, the behavior will
    /// comply with Rust soundness guarantees, won't panic, or leak memory.
    ///
    /// Furthermore, your input circuit must not contain any retire operations.
    pub fn run_graph_blocking(
        &mut self,
        circuit: &FheCircuit,
        flow_control: &Receiver<()>,
    ) -> Result<(), RuntimeError> {
        let (on_completion, done) = CompletionHandler::new_notify();

        self.spawn_graph(circuit, flow_control, Arc::new(on_completion));

        // Unwrap won't panic because both sides of the channel are alive.
        match done.recv().unwrap() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
