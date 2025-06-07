use std::{
    cell::RefCell,
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use log::{debug, log_enabled};

use crate::{Error, Result, unwrap_registers};

use super::scoreboard::ScoreboardEntryRef;

pub(crate) struct RegisterFile<T, I>
where
    T: Default + Debug + 'static,
    I: 'static + Clone,
{
    pub rename: Vec<RefCell<Rename<T, I>>>,
}

impl<T, I> RegisterFile<T, I>
where
    T: Default + Debug + 'static,
    I: 'static + Clone,
{
    pub fn new(num_registers: usize) -> Self {
        let rename = (0..num_registers)
            .map(|_| RefCell::<Rename<T, I>>::new(Rename::new()))
            .collect::<Vec<_>>();

        Self { rename }
    }

    /// Rename a register through an immutable reference.
    ///
    /// # Remarks
    /// By using an immutable reference and interior mutability, elements in the owned ROB can be
    /// mutably borrowed across different threads without having a mutable reference on this thread.
    ///
    /// # Safety
    /// The entry referred to by the passed [`ScoreboardEntryRef`] must outlive
    /// this object.
    ///
    /// # Panics
    /// If the given `register_name` exceeds the total number of registers.
    pub fn rename(
        &self,
        register_name: RegisterName<T>,
        scoreboard_entry: Option<&ScoreboardEntryRef<I>>,
    ) -> RobEntryRef<T> where {
        let mut rename = self.rename[register_name.name].borrow_mut();

        // Explicitly drop the existing rob_ref (if any) so it can be ref counted to zero and dropped.
        rename.rob_ref = None;

        let rob_entry_ref = RobEntryRef::new_mut(&Arc::new(RwLock::new(RobEntry::<T>::new())));

        // Since the entry points to a location in this object, we can store it
        // indefinitely
        rename.rob_ref = Some(rob_entry_ref.clone());
        rename.producer_id = scoreboard_entry.cloned();

        rob_entry_ref
    }

    /// Returns the current ROB entry (if any for this register. See [`RobEntry`] for more details.
    ///
    /// # Panics
    /// If the given `register_name` exceeds the total number of registers
    pub fn map_entry(&self, register_name: RegisterName<T>) -> Option<RobEntryRef<T>> {
        let rename = self.rename[register_name.name].borrow_mut();
        rename.rob_ref.clone()
    }

    /// Returns the [`ScoreboardEntryRef`] for the last instruction to write to the register
    /// with the given `register_name`.
    ///
    /// # Panics
    /// If the given `register_name` exceeds the total number of registers.
    pub fn get_instruction(&self, register_name: RegisterName<T>) -> Option<ScoreboardEntryRef<I>> {
        self.rename[register_name.name].borrow().producer_id.clone()
    }

    /// Dumps the register file's contents when LOG_LEVEL=trace.
    pub fn trace_dump(&self) {
        if log_enabled!(log::Level::Debug) {
            debug!("Register state:");
            for (i, r) in self.rename.iter().enumerate() {
                let r = r.borrow().rob_ref.clone();

                let contents = if let Some(r) = r {
                    unwrap_registers!((r));

                    format!("{r:#?}")
                } else {
                    "None".to_owned()
                };

                debug!("\tr{i}: {contents}");
            }
        }
    }
}

pub struct IdRobEntry<T>
where
    T: Default,
{
    pub(crate) register: Arc<RwLock<RobEntry<T>>>,
}

impl<T> IdRobEntry<T>
where
    T: Default,
{
    /// Get a reference to the underlying register.
    ///
    /// # Panics
    /// If the entry is currently borrowed as writable.
    pub fn entry(&self) -> RwLockReadGuard<'_, RobEntry<T>> {
        self.register.try_read().unwrap()
    }

    /// Get a mutable reference to the underlying register.
    ///
    /// # Panics
    /// If the entry is currently borrowed.
    pub fn entry_mut(&self) -> RwLockWriteGuard<'_, RobEntry<T>> {
        self.register.try_write().unwrap()
    }
}

pub enum RobEntryRef<T>
where
    T: Default,
{
    Id(IdRobEntry<T>),
    IdMut(IdRobEntry<T>),
}

impl<T> RobEntryRef<T>
where
    T: Default,
{
    fn new_mut(register: &Arc<RwLock<RobEntry<T>>>) -> Self {
        Self::IdMut(IdRobEntry {
            register: register.clone(),
        })
    }

    /// Create an immutable reference to this register.
    pub fn clone_immutable(&self) -> Self {
        match self {
            Self::Id(entry) => Self::Id(IdRobEntry {
                register: entry.register.clone(),
            }),
            Self::IdMut(entry) => Self::Id(IdRobEntry {
                register: entry.register.clone(),
            }),
        }
    }

    pub fn entry(&self) -> RwLockReadGuard<RobEntry<T>> {
        match self {
            Self::Id(entry) => entry.entry(),
            Self::IdMut(entry) => entry.entry(),
        }
    }

    pub fn entry_mut(&self) -> Result<RwLockWriteGuard<RobEntry<T>>> {
        match self {
            Self::Id(_) => Err(Error::RegisterMutabilityViolation),
            Self::IdMut(entry) => Ok(entry.entry_mut()),
        }
    }

    pub fn entry_force_mut(&self) -> RwLockWriteGuard<RobEntry<T>> {
        match self {
            Self::Id(entry) => entry.entry_mut(),
            Self::IdMut(entry) => entry.entry_mut(),
        }
    }
}

impl<T> Clone for RobEntryRef<T>
where
    T: Default,
{
    fn clone(&self) -> Self {
        match self {
            Self::Id(entry) => Self::Id(IdRobEntry {
                register: entry.register.clone(),
            }),
            Self::IdMut(entry) => Self::IdMut(IdRobEntry {
                register: entry.register.clone(),
            }),
        }
    }
}

pub struct RegisterName<T> {
    pub name: usize,
    _phantom: PhantomData<T>,
}

impl<T> std::fmt::Debug for RegisterName<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegisterName {{ {} }}", self.name)
    }
}

impl<T> RegisterName<T> {
    pub const fn new(name: usize) -> Self {
        Self {
            name,
            _phantom: PhantomData,
        }
    }
}

impl<T> Clone for RegisterName<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RegisterName<T> {}

impl<T> PartialEq for RegisterName<T> {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl<T> Eq for RegisterName<T> {}

#[derive(Debug, PartialEq, Eq)]
pub struct RobId<T> {
    pub id: usize,
    _phantom: PhantomData<T>,
}

impl<T> Clone for RobId<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RobId<T> {}

impl<T> RobId<T> {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            _phantom: PhantomData,
        }
    }
}

pub struct Rename<T, I>
where
    T: Default + 'static,
    I: 'static + Clone,
{
    pub rob_ref: Option<RobEntryRef<T>>,
    pub producer_id: Option<ScoreboardEntryRef<I>>,
}

impl<T, I> Default for Rename<T, I>
where
    T: Default,
    I: 'static + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, I> Rename<T, I>
where
    T: Default,
    I: 'static + Clone,
{
    pub fn new() -> Self {
        Self {
            rob_ref: None,
            producer_id: None,
        }
    }
}

pub struct RobEntry<T: Default> {
    reg: T,
}

impl<T> Default for RobEntry<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RobEntry<T>
where
    T: Default,
{
    pub fn new() -> Self {
        Self { reg: T::default() }
    }
}

impl<T: Default> Deref for RobEntry<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.reg
    }
}

impl<T: Default> DerefMut for RobEntry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reg
    }
}
