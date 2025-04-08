#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! Contains primitives for synchronizing and safely managing concurrency.

use std::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use serde::{Deserialize, Serialize};

/// Similar to [std::cell::RefCell], but works in a concurrent setting.
///
/// # Remarks
/// As with [std::cell::RefCell] call [`Self::borrow_mut`] to get a mutable borrow
/// and [`Self::borrow`] to get an immutable borrow to the underlying `T`. Both of these methods
/// only require an immutable borrow of self.
pub struct AtomicRefCell<T> {
    val: UnsafeCell<T>,
    state: AtomicUsize,
}

impl<T> Serialize for AtomicRefCell<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        T::serialize(&*self.borrow(), serializer)
    }
}

impl<'de, T> Deserialize<'de> for AtomicRefCell<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::new(T::deserialize(deserializer)?))
    }
}

impl<T> Clone for AtomicRefCell<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            val: UnsafeCell::new(self.borrow().clone()),
            state: AtomicUsize::new(1),
        }
    }
}

unsafe impl<T> Sync for AtomicRefCell<T> where T: Sync {}

impl<T> AtomicRefCell<T> {
    /// Create a new [`AtomicRefCell`] wrapping the given `val`.
    pub fn new(val: T) -> Self {
        Self {
            val: UnsafeCell::new(val),
            state: AtomicUsize::new(1),
        }
    }

    /// Get an immutable borrow to the underlying `T`.
    ///
    /// # Panics
    /// If the underlying value is already mutably borrowed.
    pub fn borrow(&self) -> Ref<T> {
        let old = self.state.fetch_add(1, Ordering::Acquire);

        if old == 0 {
            panic!("AtomicRefCell already borrowed as mut");
        }

        if old >= usize::MAX / 2 {
            self.state.fetch_sub(1, Ordering::Acquire);
            panic!("AtomicRefCell says I think you have enough references, buddy.");
        }

        Ref {
            val: unsafe { self.val.get().as_ref().unwrap() },
            count: &self.state,
        }
    }

    /// Get a mutable borrow to the underlying `T`.
    ///
    /// # Panics
    /// If the underlying value is already borrowed (any type).
    pub fn borrow_mut(&self) -> RefMut<T> {
        if let Err(e) = self
            .state
            .compare_exchange(1, 0, Ordering::Acquire, Ordering::Relaxed)
        {
            if e == 0 {
                panic!("AtomicRefCell is already mutably borrowed")
            } else {
                panic!("AtomicRefCell is already borrowed")
            }
        }

        RefMut {
            val: unsafe { self.val.get().as_mut().unwrap() },
            count: &self.state,
        }
    }
}

/// An immutable borrow returned by [`AtomicRefCell`].
pub struct Ref<'a, T> {
    val: &'a T,
    count: &'a AtomicUsize,
}

impl<T> Drop for Ref<'_, T> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Release);
    }
}

impl<T> Deref for Ref<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.val
    }
}

/// A mutable borrow returned by [`AtomicRefCell`].
pub struct RefMut<'a, T> {
    val: &'a mut T,
    count: &'a AtomicUsize,
}

impl<T> Drop for RefMut<'_, T> {
    fn drop(&mut self) {
        self.count.store(1, Ordering::Release)
    }
}

impl<T> Deref for RefMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.val
    }
}

impl<T> DerefMut for RefMut<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.val
    }
}

/// The use of Spinlocks in user processes is a contentious topic. However,
/// they allow for some unconventional patterns, such as permanantly locking
/// objects and dropping locked locks.
///
/// Using [`Mutex`](std::sync::Mutex) in this manner can leak resources on
/// systems that use pthread instead of Futex (i.e. MacOS).
pub struct Spinlock<T> {
    lock: AtomicBool,
    val: UnsafeCell<T>,
}

unsafe impl<T> Sync for Spinlock<T> {}
unsafe impl<T> Send for Spinlock<T> {}

impl<T> Spinlock<T> {
    /// Create a new [`Spinlock`].
    pub fn new(val: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            val: UnsafeCell::new(val),
        }
    }

    /// Acquire a mutable borrow to the underlying `T`.
    ///
    /// # Remarks
    /// Semantically, this behaves the same as [`std::sync::Mutex::lock`], except that one can
    /// call [`std::mem::forget`] on the returned [`SpinLockHandle`] without leaking OS resources.
    pub fn lock(&self) -> SpinlockHandle<'_, T> {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {}

        SpinlockHandle { lock: self }
    }

    /// Attempts to acquire a mutable borrow to the underlying `T`. On failure, returns [`None`].
    ///
    /// # Remarks
    /// Semantically, this behaves the same as [`std::sync::Mutex::try_lock`], except that one can
    /// call [`std::mem::forget`] on the returned [`SpinLockHandle`] without leaking OS resources.
    pub fn try_lock(&self) -> Option<SpinlockHandle<T>> {
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinlockHandle { lock: self })
        } else {
            None
        }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

/// Semantically similar to [`std::sync::MutexGuard`]. Allows you to mutably access the underlying
/// `T` and unlocks the parent lock when dropped.
pub struct SpinlockHandle<'a, T> {
    lock: &'a Spinlock<T>,
}

impl<T> SpinlockHandle<'_, T> {
    /// Drop this handle, keeping the spinlock locked.
    pub fn keep_locked(self) {
        std::mem::forget(self)
    }
}

impl<T> Drop for SpinlockHandle<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

impl<T> Deref for SpinlockHandle<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.lock.val.get().as_ref().unwrap() }
    }
}

impl<T> DerefMut for SpinlockHandle<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.lock.val.get().as_mut().unwrap() }
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    #[test]
    fn spinlock_lock() {
        let lock = Spinlock::new(());
        let in_crit = AtomicBool::new(false);
        let test_done = AtomicBool::new(false);

        thread::scope(|s| {
            s.spawn(|| {
                while !test_done.load(Ordering::Relaxed) {
                    let handle = lock.lock();

                    in_crit.store(true, Ordering::Relaxed);

                    thread::sleep(Duration::from_micros(1));

                    in_crit.store(false, Ordering::Relaxed);

                    std::mem::drop(handle);
                }
            });

            for _ in 0..10 {
                thread::sleep(Duration::from_micros(1));

                let handle = lock.lock();

                if in_crit.load(Ordering::Relaxed) {
                    lock.unlock();
                    test_done.store(true, Ordering::Relaxed);
                    panic!("Lock violated");
                }

                std::mem::drop(handle);
            }

            test_done.store(true, Ordering::Relaxed);
        });
    }

    #[test]
    fn spinlock_try_lock() {
        let lock = Spinlock::new(());

        let handle = lock.try_lock();

        assert!(handle.is_some());

        let handle2 = lock.try_lock();

        assert!(handle2.is_none());

        std::mem::drop(handle);
    }

    #[test]
    fn atomic_ref_cell_borrow() {
        let x = AtomicRefCell::new(7u64);
        let a = x.borrow();
        let b = x.borrow();

        assert_eq!(*a, 7);
        assert_eq!(*b, 7);
    }

    #[test]
    fn atomic_ref_cell_borrow_mut() {
        let x = AtomicRefCell::new(7u64);
        let mut a = x.borrow_mut();

        *a = 8;

        std::mem::drop(a);

        assert_eq!(*x.borrow(), 8);
    }

    #[test]
    #[should_panic]
    fn cant_borrow_mut_twice() {
        let x = AtomicRefCell::new(7u64);
        let _a = x.borrow_mut();
        let _b = x.borrow_mut();
    }

    #[test]
    #[should_panic]
    fn cant_borrow_mut_and_immut() {
        let x = AtomicRefCell::new(7u64);
        let _a = x.borrow_mut();
        let _b = x.borrow();
    }

    #[test]
    #[should_panic]
    fn panic_on_ridiculous_ref_count() {
        let x = AtomicRefCell::new(8);
        x.state.store(usize::MAX / 2, Ordering::Relaxed);
        x.borrow();
    }
}
