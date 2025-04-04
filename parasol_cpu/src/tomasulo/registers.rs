use std::{
    cell::RefCell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use parasol_runtime::{Encryption, TrivialOne, TrivialZero};

use super::scoreboard::ScoreboardEntryRef;

pub struct RegisterFile<T, I>
where
    T: TrivialOne + TrivialZero + 'static,
    I: 'static + Clone,
{
    pub rename: Vec<RefCell<Rename<T, I>>>,
    enc: Encryption,
}

impl<T, I> RegisterFile<T, I>
where
    T: TrivialOne + TrivialZero + 'static,
    I: 'static + Clone,
{
    pub fn new(num_registers: usize, enc: &Encryption) -> Self {
        let rename = (0..num_registers)
            .map(|_| RefCell::<Rename<T, I>>::new(Rename::new()))
            .collect::<Vec<_>>();

        Self {
            rename,
            enc: enc.to_owned(),
        }
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
    pub fn rename(
        &self,
        register_name: RegisterName<T>,
        scoreboard_entry: &ScoreboardEntryRef<I>,
    ) -> RobEntryRef<T> where {
        // Explicitly drop the current RobEntryRef, as it may go into the free list.
        let mut rename = self.rename[register_name.unwrap_named()].borrow_mut();
        rename.rob_ref = None;

        let rob_entry_ref =
            RobEntryRef::new_mut(&Arc::new(RwLock::new(RobEntry::<T>::new(&self.enc))));

        // Since the entry points to a location in this object, we can store it
        // indefinitely
        rename.rob_ref = Some(rob_entry_ref.clone());
        rename.producer_id = Some(scoreboard_entry.clone());

        rob_entry_ref
    }

    pub fn map_entry(&self, register_name: RegisterName<T>) -> Option<RobEntryRef<T>> {
        match register_name {
            RegisterName::<T>::Named(name, _) => {
                let rename = self.rename[name].borrow_mut();

                rename.rob_ref.clone()
            }
            RegisterName::<T>::One => Some(RobEntryRef::One),
            RegisterName::<T>::Zero => Some(RobEntryRef::Zero),
        }
    }

    pub fn get_instruction(&self, register_name: RegisterName<T>) -> Option<ScoreboardEntryRef<I>> {
        match register_name {
            RegisterName::Named(x, _) => self.rename[x].borrow().producer_id.clone(),
            _ => None,
        }
    }
}

pub struct IdRobEntry<T>
where
    T: TrivialZero + TrivialOne,
{
    register: Arc<RwLock<RobEntry<T>>>,
}

impl<T> IdRobEntry<T>
where
    T: TrivialZero + TrivialOne,
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
    T: TrivialZero + TrivialOne,
{
    Id(IdRobEntry<T>),
    IdMut(IdRobEntry<T>),
    One,
    Zero,
}

impl<T> RobEntryRef<T>
where
    T: TrivialZero + TrivialOne,
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
            Self::One => Self::One,
            Self::Zero => Self::Zero,
        }
    }

    pub fn unwrap_id(&self) -> &IdRobEntry<T> {
        match self {
            Self::Id(entry) => entry,
            Self::IdMut(entry) => entry,
            _ => panic!("RobEntryRef was not Id"),
        }
    }
}

impl<T> Clone for RobEntryRef<T>
where
    T: TrivialZero + TrivialOne,
{
    fn clone(&self) -> Self {
        match self {
            Self::Id(entry) => Self::Id(IdRobEntry {
                register: entry.register.clone(),
            }),
            Self::IdMut(entry) => Self::IdMut(IdRobEntry {
                register: entry.register.clone(),
            }),
            Self::One => Self::One,
            Self::Zero => Self::Zero,
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum RegisterName<T> {
    Named(usize, PhantomData<T>),
    One,
    Zero,
}

impl<T> std::fmt::Debug for RegisterName<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(x, _) => write!(f, "RegisterName::Named({x})"),
            Self::One => write!(f, "RegisterName::One"),
            Self::Zero => write!(f, "RegisterName::Zero"),
        }
    }
}

impl<T> RegisterName<T> {
    pub fn named(name: usize) -> Self {
        Self::Named(name, PhantomData)
    }

    pub fn unwrap_named(&self) -> usize {
        match self {
            Self::Named(x, _) => *x,
            _ => panic!("RegisterName was not Named"),
        }
    }
}

impl<T> Clone for RegisterName<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RegisterName<T> {}

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
    T: TrivialZero + TrivialOne + 'static,
    I: 'static + Clone,
{
    pub rob_ref: Option<RobEntryRef<T>>,
    pub producer_id: Option<ScoreboardEntryRef<I>>,
}

impl<T, I> Default for Rename<T, I>
where
    T: TrivialZero + TrivialOne,
    I: 'static + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, I> Rename<T, I>
where
    T: TrivialZero + TrivialOne,
    I: 'static + Clone,
{
    pub fn new() -> Self {
        Self {
            rob_ref: None,
            producer_id: None,
        }
    }
}

pub struct RobEntry<T: TrivialZero> {
    reg: T,
}

impl<T> RobEntry<T>
where
    T: TrivialZero,
{
    pub fn new(enc: &Encryption) -> Self {
        Self {
            reg: T::trivial_zero(enc),
        }
    }
}

impl<T: TrivialZero> Deref for RobEntry<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.reg
    }
}

impl<T: TrivialZero> DerefMut for RobEntry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reg
    }
}
