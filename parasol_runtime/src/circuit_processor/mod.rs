use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, sync_channel, Receiver, SyncSender},
        Arc,
    },
};

use concurrency::{AtomicRefCell, Spinlock};
use log::trace;
use petgraph::{
    graph::NodeIndex,
    visit::{EdgeRef, Topo},
    Direction,
};
use rayon::{spawn, ThreadPool};

use crate::{
    crypto::{
        ciphertext::Ciphertext, L0LweCiphertext, L1GgswCiphertext, L1GlevCiphertext,
        L1GlweCiphertext,
    },
    fhe_circuit::{FheCircuit, FheEdge, FheOp},
    Encryption, Evaluation,
};

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
/// tasks must pass the [`Receiver`] returned by [`UOpProcessor::new`] to the
/// [`Self::spawn_graph`] and [`Self::run_graph_blocking`] methods, which will block the
/// calling thread when the number of in-flight tasks exceeds the `flow_control` value passed to
/// [`UOpProcessor::new`].
///
/// The `thread_pool` argument is optional. When set, tasks will be scheduled on the specified
/// threadpool. Otherwise, the global rayon threadpool will be used.
pub struct UOpProcessor {
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

impl UOpProcessor {
    /// Create a new [`UOpProcessor`]. When `thread_pool` is [`None`], the global rayon threadpool
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

        // Cmux has the most inputs at 3.
        assert!(deps.len() <= 3);

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
            match dep.0.dependents.try_lock() {
                // If we acquire the lock, then add ourselves as a dependant and increase the
                // dependency count.
                Some(mut x) => {
                    new_task.num_deps.fetch_add(1, Ordering::Acquire);
                    x.push(new_task.clone());
                }
                // If we fail to acquire the lock, then the dependent task has already completed
                // and notified its subscribers. However, its data is immediately available for
                // use, so we don't update our dependency count.
                None => {}
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

    fn execute_task(uproc: &Arc<Self>, task: Arc<Task>, parent_op: Arc<CompletionHandler>) {
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

            Self::exec_op(&uproc_clone, &task);

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
                    Self::execute_task(&uproc_clone, dep, parent_op.clone());
                }
            }

            // When this instruction retires, keep the mutex locked so any future dependents
            // will just be able to immediately use our data.
            std::mem::forget(deps);

            uproc_clone.flow_control.send(()).unwrap();
            parent_op.retire();
        });
    }

    fn exec_op(proc: &UOpProcessor, task: &Task) {
        match &task.op {
            FheOp::InputLwe0(x) => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputLwe1(x) => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputGlwe1(x) => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputGgsw1(x) => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::InputGlev1(x) => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                let x = AtomicRefCell::borrow(x);

                *output = Some(x.clone().into());
            }
            FheOp::OutputLwe0(x) => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputLwe1(x) => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputGlwe1(x) => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputGgsw1(x) => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::OutputGlev1(x) => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let mut output = AtomicRefCell::borrow_mut(x);

                let input = AtomicRefCell::borrow(&task.inputs[0].0);

                *output = input.clone().unwrap().try_into().unwrap();
            }
            FheOp::CircuitBootstrap => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_lwe0();

                let mut res = proc.enc.allocate_ggsw_l1();

                proc.eval.circuit_bootstrap(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);

                *output = Some(res.into());
            }
            FheOp::Not => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_glwe1();

                let mut res = proc.enc.allocate_glwe_l1();

                proc.eval.not(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::GlweAdd => {
                assert_eq!(task.inputs.len(), 2);
                assert_eq!(
                    task.inputs
                        .iter()
                        .filter(|x| matches!(x.1, FheEdge::Left))
                        .count(),
                    1
                );
                assert_eq!(
                    task.inputs
                        .iter()
                        .filter(|x| matches!(x.1, FheEdge::Right))
                        .count(),
                    1
                );

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
                assert_eq!(task.inputs.len(), 2);

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
                assert_eq!(task.inputs.len(), 3);

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
                assert_eq!(task.inputs.len(), 3);

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
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_lwe1();

                let mut res = proc.enc.allocate_lwe_l0();

                proc.eval.keyswitch_lwe_l1_lwe_l0(&mut res, input);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::SampleExtract(idx) => {
                assert_eq!(task.inputs.len(), 1);
                assert!(matches!(task.inputs[0].1, FheEdge::Unary));

                let input = AtomicRefCell::borrow(&task.inputs[0].0);
                let input = input.as_ref().unwrap().borrow_glwe1();

                let mut res = proc.enc.allocate_lwe_l1();

                proc.eval.sample_extract_l1(&mut res, input, *idx);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(res.into());
            }
            FheOp::ZeroLwe0 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_lwe0.clone().into());
            }
            FheOp::OneLwe0 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_lwe0.clone().into());
            }
            FheOp::ZeroGlwe1 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_glwe1.clone().into());
            }
            FheOp::OneGlwe1 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_glwe1.clone().into());
            }
            FheOp::ZeroGgsw1 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_ggsw1.clone().into());
            }
            FheOp::OneGgsw1 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_ggsw1.clone().into());
            }
            FheOp::ZeroGlev1 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.zero_glev1.clone().into());
            }
            FheOp::OneGlev1 => {
                assert_eq!(task.inputs.len(), 0);

                let mut output = AtomicRefCell::borrow_mut(&task.output);
                *output = Some(proc.one_glev1.clone().into());
            }
            FheOp::MulXN(n) => {
                assert_eq!(task.inputs.len(), 1);

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
                assert_eq!(task.inputs.len(), 1);

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

            let task = self.dispatch(flow_control, op.clone(), &deps, on_completion.clone());

            tasks.insert(idx, (task, dep_count));
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
    pub fn run_graph_blocking(&mut self, circuit: &FheCircuit, flow_control: &Receiver<()>) {
        let (on_completion, done) = CompletionHandler::new_notify();

        self.spawn_graph(circuit, flow_control, Arc::new(on_completion));

        done.recv().unwrap()
    }
}

/// A callback that fires when all the operations in an [`FheCircuit`] passed to
/// [`UOpProcessor::spawn_graph`] or [`UOpProcessor::run_graph_blocking`] finish.
pub struct CompletionHandler {
    ops_remaining: AtomicUsize,
    callback: Box<dyn Fn() + 'static + Sync + Send>,
}

impl CompletionHandler {
    /// Create a [`CompletionHandler`] with the passed callback.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn() + Sync + Send + 'static,
    {
        Self {
            ops_remaining: AtomicUsize::new(1),
            callback: Box::new(callback),
        }
    }

    pub(crate) fn dispatch(&self) {
        self.ops_remaining.fetch_add(1, Ordering::Acquire);
    }

    pub(crate) fn retire(&self) {
        if self.ops_remaining.fetch_sub(1, Ordering::Release) == 1 {
            (self.callback)();
        }
    }

    /// Creates a new [`CompletionHandler`] that notifies the returned recv on completion
    pub fn new_notify() -> (Self, Receiver<()>) {
        let (send, recv) = mpsc::channel();

        (Self::new(move || send.send(()).unwrap()), recv)
    }
}

pub struct Task {
    task_id: usize,
    num_deps: AtomicUsize,
    op: FheOp,
    output: Arc<AtomicRefCell<Option<Ciphertext>>>,
    inputs: Vec<(Arc<AtomicRefCell<Option<Ciphertext>>>, FheEdge)>,

    /// Here we use [`Mutex`] rather than a spinlock because we don't need to forcibly
    /// unlock this object for reuse.
    dependents: Spinlock<Vec<Arc<Task>>>,

    #[cfg(feature = "debug")]
    deps: Vec<Weak<Task>>,
}
