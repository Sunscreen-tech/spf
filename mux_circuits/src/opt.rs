use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
};

use petgraph::{
    prelude::StableGraph,
    stable_graph::{EdgeReference, Edges, Neighbors, NodeIndex},
    visit::{EdgeRef, IntoNodeIdentifiers},
    Directed, Direction,
};

/**
 * A wrapper for ascertaining the structure of the underlying graph.
 * This type is used in [`forward_traverse`] and
 * [`reverse_traverse`] callbacks.
 */
pub struct GraphQuery<'a, N, E>(pub &'a StableGraph<N, E>);

impl<'a, N, E> GraphQuery<'a, N, E> {
    /**
     * Creates a new [`GraphQuery`] from a reference to a
     * [`StableGraph`].
     */
    pub fn new(ir: &'a StableGraph<N, E>) -> Self {
        Self(ir)
    }

    /**
     * Gets a node from its index.
     */
    pub fn get_node(&self, x: NodeIndex) -> Option<&N> {
        self.0.node_weight(x)
    }

    /**
     * Gets information about the immediate parent or child nodes of
     * the node at the given index.
     *
     * # Remarks
     * [`Direction::Outgoing`] gives children, while
     * [`Direction::Incoming`] gives parents.
     */
    pub fn neighbors_directed(&self, x: NodeIndex, direction: Direction) -> Neighbors<E> {
        self.0.neighbors_directed(x, direction)
    }

    /**
     * Gets edges pointing at the parent or child nodes of the node at
     * the given index.
     *
     * # Remarks
     * [`Direction::Outgoing`] gives children, while
     * [`Direction::Incoming`] gives parents.
     */
    pub fn edges_directed(&self, x: NodeIndex, direction: Direction) -> Edges<E, Directed> {
        self.0.edges_directed(x, direction)
    }
}

pub enum BinaryOperandInfo {
    Left,
    Right,
}

pub enum MuxOperandInfo {
    Low,
    High,
    Select,
}

pub trait EdgeOps {
    fn binary_operand_type(&self) -> Option<BinaryOperandInfo>;

    fn mux_operand_type(&self) -> Option<MuxOperandInfo>;
}

#[derive(Clone)]
/**
 * A request to transform the graph as appropriate.
 */
pub enum Transform<N, E> {
    /**
     * Add an edge between two nodes at the given edges.
     *
     * # Remarks
     * The tuple is of the form (from, to, edge).
     */
    AddEdge(TransformNodeIndex, TransformNodeIndex, E),

    /**
     * Add the given node to the compilation graph.
     */
    AddNode(N),

    /**
     * Remove the node at the given index. This will implicitly remove
     * any edges referencing the node.
     */
    RemoveNode(TransformNodeIndex),

    /**
     * Remove an edge between two nodes.
     *
     * # Remarks
     * The tuple is of the form (from, to)
     */
    RemoveEdge(TransformNodeIndex, TransformNodeIndex),
}

/**
 * The index type for referring to nodes in the current transform list
 * that have not yet been added to the graph.
 */
pub type DeferredIndex = usize;

#[derive(Clone, Copy)]
/**
 * The index of a graph node, either in the compilation graph or
 * resulting from a previous unapplied transformation.
 */
pub enum TransformNodeIndex {
    /**
     * Refers to the node in the compilation graph at the contained
     * index.
     */
    NodeIndex(NodeIndex),

    /**
     * Refers to the node resulting from a previous [`Transform::AddNode`]
     * transform.
     */
    DeferredIndex(DeferredIndex),
}

impl From<NodeIndex> for TransformNodeIndex {
    fn from(x: NodeIndex) -> Self {
        Self::NodeIndex(x)
    }
}

impl From<DeferredIndex> for TransformNodeIndex {
    fn from(x: DeferredIndex) -> Self {
        Self::DeferredIndex(x)
    }
}

#[derive(Clone)]
/**
 * A datastructure for holding a sequence of graph transformations.
 */
pub struct GraphTransforms<N, E> {
    transforms: Vec<Transform<N, E>>,
    inserted_node_ids: Vec<Option<NodeIndex>>,
}

impl<N, E> GraphTransforms<N, E> {
    /**
     * Creates a new [`GraphTransforms`].
     */
    pub fn new() -> Self {
        Self {
            transforms: vec![],
            inserted_node_ids: vec![],
        }
    }

    fn materialize_index(&self, id: TransformNodeIndex) -> NodeIndex {
        match id {
            TransformNodeIndex::NodeIndex(x) => x,
            TransformNodeIndex::DeferredIndex(x) => {
                self.inserted_node_ids[x].expect("Invalid transform node id.")
            }
        }
    }

    /**
     * Pushes a transform into the list and returns the index of the
     * pushed transform suitable for use in
     * [`TransformNodeIndex::DeferredIndex`].
     * This allows you to reference nodes that haven't yet been added to
     * the graph in subsequent transforms.
     *
     * # Remarks
     * It goes without saying, if the pushed transform isn't
     * [`Transform::AddNode`], you shouldn't attempt to use this index.
     */
    pub fn push(&mut self, t: Transform<N, E>) -> DeferredIndex {
        self.transforms.push(t);

        self.transforms.len() - 1
    }
}

impl<N, E> Default for GraphTransforms<N, E>
where
    N: Clone,
    E: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

/**
 * A list of transformations that should be applied to the graph.
 */
pub trait TransformList<N, E>
where
    N: Clone,
    E: Clone,
{
    /**
     * Apply the transformations and return any added nodes.
     *
     * # Remarks
     * This consumes the transform list.
     */
    fn apply(self, graph: &mut StableGraph<N, E>) -> Vec<NodeIndex>;
}

impl<N, E> TransformList<N, E> for GraphTransforms<N, E>
where
    N: Clone,
    E: Clone,
{
    fn apply(mut self, graph: &mut petgraph::stable_graph::StableGraph<N, E>) -> Vec<NodeIndex> {
        // Despite appearances, this is not redundant with
        // `self.inserted_node_ids`. `added_nodes` is a list
        // of added nodes, while latter is indexable by the
        // transform id and will have `None` elements for
        // transforms that don't add nodes.
        let mut added_nodes = vec![];

        for t in &self.transforms {
            let inserted_node = match t {
                Transform::AddNode(n) => Some(graph.add_node(n.clone())),
                Transform::AddEdge(start, end, info) => {
                    let start = self.materialize_index(*start);
                    let end = self.materialize_index(*end);

                    graph.add_edge(start, end, info.clone());

                    None
                }
                Transform::RemoveEdge(start, end) => {
                    let start = self.materialize_index(*start);
                    let end = self.materialize_index(*end);
                    let edge = graph.find_edge(start, end).expect("No such edge");

                    graph.remove_edge(edge);

                    None
                }
                Transform::RemoveNode(n) => {
                    let n = self.materialize_index(*n);
                    graph.remove_node(n);

                    None
                }
            };

            if let Some(node) = inserted_node {
                added_nodes.push(node);
            }

            self.inserted_node_ids.push(inserted_node);
        }

        added_nodes
    }
}

/**
 * A supertrait that concisely contains all the traits needed to serve
 * as an operation for [`NodeInfo`](crate::context::NodeInfo).
 *
 * Also provides functions that describe properties of an operation.
 */
pub trait Operation: Clone + std::fmt::Debug + std::hash::Hash + PartialEq + Eq {
    /**
     * Whether or not this operations is a mux
     */
    fn is_mux(&self) -> bool;

    /**
     * Whether or not this operation commutes.
     */
    fn is_commutative(&self) -> bool;

    /**
     * Whether or not this operation has 2 operands.
     */
    fn is_binary(&self) -> bool;

    /**
     * Whether or not this operation has 1 operand.
     */
    fn is_unary(&self) -> bool;

    /**
     * Whether or not this operation accepts an arbitrary number of
     * unordered operands.
     */
    fn is_unordered(&self) -> bool;

    /**
     * Whether or not this operation accepts an arbitrary number of
     * ordered operands.
     */
    fn is_ordered(&self) -> bool;
}

/**
 * For the given compilation graph, perform common subexpression
 * elimination (CSE).
 *
 * # Remarks
 * CSE is an optimization that collapses and reuses redundance
 * computations. For example:
 * ```ignore
 * a = b + c * d
 * e = c * d + 42
 * ```
 * The `c * d` subexpression can be computed once and shared between
 * the two expressions.
 */
pub fn common_subexpression_elimination<O: Operation, E: Clone + Copy + EdgeOps>(
    graph: &mut StableGraph<O, E>,
) {
    forward_traverse_mut(graph, |query, index| {
        let mut transforms: GraphTransforms<O, E> = GraphTransforms::new();

        // Key is left/unary+right operand and operation. Value is
        // the node that matches such a key.
        let mut visited_nodes =
            HashMap::<(NodeIndex, Option<NodeIndex>, Option<NodeIndex>, &O), NodeIndex>::new();

        // Look through out immediate children. If we find any of the
        // type that share an edge with another node, consolidate them into
        // one and fix up their outputs.
        for e in query.neighbors_directed(index, Direction::Outgoing) {
            // Unwrapping is okay because index e is a node in the graph.
            let child_node = query.get_node(e).unwrap();

            // Moves all the edges from removed_node to node_to_add and
            // deleted removed_node
            let mut move_edges = |node_to_add, removed_node| {
                let node_to_add = TransformNodeIndex::NodeIndex(node_to_add);

                for e in query.edges_directed(removed_node, Direction::Outgoing) {
                    let edge = TransformNodeIndex::NodeIndex(e.target());
                    let info = e.weight();

                    transforms.push(Transform::AddEdge(node_to_add, edge, *info));
                }

                transforms.push(Transform::RemoveNode(TransformNodeIndex::NodeIndex(
                    removed_node,
                )));
            };

            let child_op = child_node;

            let child_key = if child_op.is_binary() {
                let (left, right) = get_binary_operands(&query, e);

                Some((left, Some(right), None, child_op))
            } else if child_op.is_unary() {
                Some((index, None, None, child_op))
            } else if child_op.is_mux() {
                let (select, low, high) = get_mux_operands(&query, e);

                Some((select, Some(low), Some(high), child_op))
            } else {
                None
            };

            if let Some(child_key) = child_key {
                let equiv_node = visited_nodes.get(&child_key);

                match equiv_node {
                    Some(equiv_node) => {
                        // Only collapse distinct equivalent operations.
                        if *equiv_node != e {
                            move_edges(*equiv_node, e);
                        }
                    }
                    None => {
                        visited_nodes.insert(child_key, e);
                    }
                };
            };
        }

        Ok::<_, Infallible>(transforms)
    })
    .expect("Traverse closure should be infallible.");
}

/**
 * A specialized topological DAG traversal that allows the following graph
 * mutations during traversal:
 * * Delete the current node
 * * Insert nodes after current node
 * * Add new nodes with no dependencies
 *
 * Any other graph mutation will likely result in unvisited nodes.
 *
 * * `callback`: A closure that receives the current node index and an
 *   object allowing you to make graph queries. This closure returns a    
 *   transform list or an error.
 *   On success, [`reverse_traverse`] will apply these transformations
 *   before continuing the traversal. Errors will be propagated to the
 *   caller.
 */
pub fn forward_traverse_mut<N, E, F, T, Err>(
    graph: &mut StableGraph<N, E>,
    callback: F,
) -> Result<(), Err>
where
    N: Clone,
    E: Clone,
    T: TransformList<N, E>,
    F: FnMut(GraphQuery<N, E>, NodeIndex) -> Result<T, Err>,
{
    unsafe { traverse(graph, true, callback) }
}

/**
 * Internal traversal implementation that allows for mutable traversal.
 * If the callback always returns an empty transform list or (), then
 * graph won't be mutated.
 */
unsafe fn traverse<N, E, T, F, Err>(
    graph: *mut StableGraph<N, E>,
    forward: bool,
    mut callback: F,
) -> Result<(), Err>
where
    N: Clone,
    E: Clone,
    F: FnMut(GraphQuery<N, E>, NodeIndex) -> Result<T, Err>,
    T: TransformList<N, E>,
{
    // The one unsafe line in the function...
    let graph = &mut *graph;
    let mut ready: HashSet<NodeIndex> = HashSet::new();
    let mut visited: HashSet<NodeIndex> = HashSet::new();
    let prev_direction = if forward {
        Direction::Incoming
    } else {
        Direction::Outgoing
    };
    let next_direction = if forward {
        Direction::Outgoing
    } else {
        Direction::Incoming
    };

    let mut ready_nodes: Vec<NodeIndex> = graph
        .node_identifiers()
        .filter(|&x| graph.neighbors_directed(x, prev_direction).next().is_none())
        .collect();

    ready.extend(ready_nodes.iter());

    while let Some(n) = ready_nodes.pop() {
        visited.insert(n);

        // Remember the next nodes from the current node in case it gets deleted.
        let next_nodes: Vec<NodeIndex> = graph.neighbors_directed(n, next_direction).collect();

        // If the node was deleted by a transformation, skip it.
        if !graph.contains_node(n) {
            continue;
        }

        let transforms = callback(GraphQuery(graph), n)?;

        // Apply the transforms the callback produced
        let added_nodes = transforms.apply(graph);

        let node_ready = |n: NodeIndex| {
            graph
                .neighbors_directed(n, prev_direction)
                .all(|m| visited.contains(&m))
        };

        // If the node still exists, push all its ready dependents
        if graph.contains_node(n) {
            for i in graph.neighbors_directed(n, next_direction) {
                if !ready.contains(&i) && node_ready(i) {
                    ready.insert(i);
                    ready_nodes.push(i);
                }
            }
        }

        // Iterate through the next nodes that existed before visiting this node.
        for i in next_nodes {
            if !ready.contains(&i) && node_ready(i) {
                ready.insert(i);
                ready_nodes.push(i);
            }
        }

        // Check for and sources/sinks the callback may have added.
        for i in added_nodes {
            if graph.neighbors_directed(i, prev_direction).next().is_none() {
                ready.insert(i);
                ready_nodes.push(i);
            }
        }
    }

    Ok(())
}

/// Returns the select, low, and high inputs to a mux operation.
fn get_mux_operands<O: Operation, E: Clone + EdgeOps>(
    graph_query: &GraphQuery<O, E>,
    node_index: NodeIndex,
) -> (NodeIndex, NodeIndex, NodeIndex) {
    let edge_infos = graph_query
        .edges_directed(node_index, Direction::Incoming)
        .collect::<Vec<EdgeReference<E>>>();

    assert_eq!(edge_infos.len(), 3);

    let select_edge = edge_infos
        .iter()
        .filter_map(|x| {
            if matches!(x.weight().mux_operand_type(), Some(MuxOperandInfo::Select)) {
                Some(x.source())
            } else {
                None
            }
        })
        .next()
        .expect("Missing select input on mux");

    let low_edge = edge_infos
        .iter()
        .filter_map(|x| {
            if matches!(x.weight().mux_operand_type(), Some(MuxOperandInfo::Low)) {
                Some(x.source())
            } else {
                None
            }
        })
        .next()
        .expect("Missing low input on mux");

    let high_edge = edge_infos
        .iter()
        .filter_map(|x| {
            if matches!(x.weight().mux_operand_type(), Some(MuxOperandInfo::High)) {
                Some(x.source())
            } else {
                None
            }
        })
        .next()
        .expect("Missing high input on mux");

    (select_edge, low_edge, high_edge)
}

fn get_binary_operands<O: Operation, E: Clone + EdgeOps>(
    graph_query: &GraphQuery<O, E>,
    node_index: NodeIndex,
) -> (NodeIndex, NodeIndex) {
    let edge_infos = graph_query
        .edges_directed(node_index, Direction::Incoming)
        .collect::<Vec<EdgeReference<_>>>();

    assert_eq!(edge_infos.len(), 2);

    match edge_infos[0].weight().binary_operand_type().unwrap() {
        BinaryOperandInfo::Left => {
            assert!(matches!(
                edge_infos[1].weight().binary_operand_type(),
                Some(BinaryOperandInfo::Right)
            ));

            let left_edge = edge_infos[0].source();
            let right_edge = edge_infos[1].source();

            (left_edge, right_edge)
        }
        BinaryOperandInfo::Right => {
            assert!(matches!(
                edge_infos[1].weight().binary_operand_type(),
                Some(BinaryOperandInfo::Left)
            ));

            let left_edge = edge_infos[1].source();
            let right_edge = edge_infos[0].source();

            (left_edge, right_edge)
        }
    }
}
