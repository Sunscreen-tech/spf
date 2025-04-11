use std::{
    marker::PhantomData,
    ops::Deref,
    sync::{Arc, atomic::AtomicUsize},
};

use parasol_concurrency::{AtomicRefCell, Spinlock};

#[derive(Debug, Eq)]
pub struct ScoreboardEntryId<I> {
    id: usize,
    _phantom: PhantomData<I>,
}

impl<I> Deref for ScoreboardEntryId<I> {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl<I> PartialEq for ScoreboardEntryId<I> {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}

impl<I> std::fmt::Display for ScoreboardEntryId<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl<I> ScoreboardEntryId<I> {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            _phantom: PhantomData,
        }
    }
}

impl<I> Clone for ScoreboardEntryId<I> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I> Copy for ScoreboardEntryId<I> {}

#[derive(Clone)]
pub struct ScoreboardEntryRef<I>
where
    I: Clone,
{
    entry: Arc<ScoreboardEntry<I>>,
}

impl<I> ScoreboardEntryRef<I>
where
    I: Clone,
{
    pub(crate) fn new(entry: &Arc<ScoreboardEntry<I>>) -> Self {
        Self {
            entry: entry.clone(),
        }
    }
}

impl<I: Clone> Deref for ScoreboardEntryRef<I> {
    type Target = ScoreboardEntry<I>;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

pub struct ScoreboardEntry<I>
where
    I: Clone,
{
    pub id: ScoreboardEntryId<I>,
    pub deps: AtomicUsize,
    pub dependents: Spinlock<Vec<ScoreboardEntryRef<I>>>,
    pub instruction: AtomicRefCell<Option<I>>,
    pub pc: usize,
}

impl<I> ScoreboardEntry<I>
where
    I: Clone,
{
    pub fn new(id: ScoreboardEntryId<I>, pc: usize) -> Self {
        Self {
            id,
            deps: AtomicUsize::new(0),
            dependents: Spinlock::new(vec![]),
            instruction: AtomicRefCell::new(None),
            pc,
        }
    }

    /// Sets the insstruction on this scoreboard entry.
    ///
    /// # Panics
    /// The instruction gets set through an immutable borrow of self.
    /// Internally, an [`AtomicRefCell`] guards mutability and will panic
    /// if this function called twice at the same time
    pub fn set_instruction(&self, instruction: &I) {
        *self.instruction.borrow_mut() = Some(instruction.to_owned());
    }
}
