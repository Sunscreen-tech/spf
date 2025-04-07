use std::{collections::HashSet, ops::Deref};

use petgraph::{
    prelude::StableGraph, stable_graph::NodeIndex, visit::IntoNodeIdentifiers, Direction,
};

use crate::opt::GraphQuery;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
/// A bit containing the value true or false.
pub struct Bit(pub bool);

impl Deref for Bit {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<bool> for Bit {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl<'a, N, E> From<&'a StableGraph<N, E>> for GraphQuery<'a, N, E> {
    fn from(x: &'a StableGraph<N, E>) -> Self {
        Self(x)
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

// Make a surrogate implementation of the trait for traversal functions
// that don't mutate the graph.
impl<N, E> TransformList<N, E> for ()
where
    N: Clone,
    E: Clone,
{
    fn apply(self, _graph: &mut StableGraph<N, E>) -> Vec<NodeIndex> {
        vec![]
    }
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

pub fn forward_traverse<N, E, F, Err>(graph: &StableGraph<N, E>, callback: F) -> Result<(), Err>
where
    N: Clone,
    E: Clone,
    F: FnMut(GraphQuery<N, E>, NodeIndex) -> Result<(), Err>,
{
    let graph: *const StableGraph<N, E> = graph;

    // Traverse won't mutate the graph since F returns ().
    unsafe { traverse(graph as *mut StableGraph<N, E>, true, callback) }
}
