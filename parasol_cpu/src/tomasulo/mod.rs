use crate::error::Result;

use self::scoreboard::ScoreboardEntryRef;

pub mod registers;
pub mod scoreboard;
pub mod tomasulo_processor;

pub(crate) trait ToDispatchedOp<'a>
where
    Self: Sized,
{
    type DispatchedOp: Sized + Clone;
    type RobEntrySrcs: 'a;
    type FreeLists: 'a;

    fn to_dispatched_op(
        &self,
        srcs: Self::RobEntrySrcs,
        scoreboard_entry: ScoreboardEntryRef<Self::DispatchedOp>,
        instruction_id: usize,
        pc: usize,
    ) -> Result<Self::DispatchedOp>;
}

pub(crate) trait GetDeps<'a>
where
    Self: Sized,
{
    type DispatchedOp: Sized + Clone;
    type RenameSet: Copy + 'a;

    fn instruction_dep_idx(
        &self,
        rename_set: Self::RenameSet,
        idx: usize,
    ) -> Option<ScoreboardEntryRef<Self::DispatchedOp>>;

    fn num_deps(&self) -> usize;

    fn deps(
        &'a self,
        rename_set: Self::RenameSet,
    ) -> Deps<'a, Self, Self::DispatchedOp, Self::RenameSet> {
        Deps {
            idx: 0,
            instruction: self,
            rename_set,
        }
    }
}

pub(crate) struct Deps<'a, T, U, V>
where
    T: GetDeps<'a, DispatchedOp = U, RenameSet = V>,
    V: Copy,
{
    instruction: &'a T,
    idx: usize,
    rename_set: V,
}

impl<'a, T, U, V> Iterator for Deps<'a, T, U, V>
where
    T: GetDeps<'a, DispatchedOp = U, RenameSet = V>,
    U: Clone,
    V: Copy,
{
    type Item = Option<ScoreboardEntryRef<U>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.instruction.num_deps() {
            return None;
        }

        let result = self
            .instruction
            .instruction_dep_idx(self.rename_set, self.idx);

        self.idx += 1;

        Some(result)
    }
}

/// Return an expression that evaluates to `$idx_ident`'s index in `$($src_name)*`.
#[macro_export]
macro_rules! dep_idx {
    ($idx_ident:ident, $($src_name:ident)*) => {
        $crate::dep_idx! { @start $idx_ident, $($src_name,)*}
    };

    (@start $idx_ident:ident,) => {
        None
    };

    (@start $idx_ident:ident, $src_name:ident, $($tail:ident,)*) => {
        if 0usize == $idx_ident {
            return $src_name;
        } else {
            $crate::dep_idx!{@elif 1usize, $idx_ident, $($tail,)*}
        }
    };

    (@elif $idx:expr, $idx_ident:ident, $src_name:ident, $($tail:ident,)*) => {
        if $idx == $idx_ident {
            return $src_name;
        } else {
            $crate::dep_idx!{@elif $idx + 1usize, $idx_ident, $($tail,)*}
        }
    };

    (@elif $idx:expr, $idx_ident:ident,) => {
        return None;
    };
}

/// Emit an expression that evaluates to the length of a macro rep expression.
#[macro_export]
macro_rules! rep_len {
    () => {
        0usize
    };

    ($head:ident $($x:ident)*) => {
        1usize + $crate::rep_len! {$($x)* }
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn rep_len_gives_correct_size() {
        assert_eq!(rep_len!(), 0);
        assert_eq!(rep_len!(a), 1);
        assert_eq!(rep_len!(a b), 2);
        assert_eq!(rep_len!(a b c), 3);
        assert_eq!(rep_len!(a b c d), 4);
    }
}
