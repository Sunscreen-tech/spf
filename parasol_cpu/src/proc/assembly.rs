use crate::{PtrRegister, Register};

/// Define the list of opcodes for the processors ISA.
#[macro_export]
macro_rules! define_op {
    (
        $inst_name:ident,
        $dispatch_name:ident,
        ($($reg_kind:ty),*),
        $([
            $op_name:ident
            $((dst $dst_name:ident, $dst_type_id:tt, $dst_type:ty))*
            $((src $src_name:ident, $src_type_id:tt, $src_type:ty))*
            $((meta $meta_name:ident $meta_type:ty))*
        ]),* $(,)?
    ) => {
        paste::paste! {
            mod [<$inst_name:snake _internal>] {
                use $crate::{
                    Result, Error,
                    tomasulo::{
                        registers::{RegisterName, RegisterFile, RobEntryRef, RobId},
                        GetDeps,
                        ToDispatchedOp,
                        scoreboard::{
                            ScoreboardEntryRef,
                        },
                    }
                };

                use std::sync::mpsc::Receiver;
                use super::*;

                #[derive(Debug, Clone)]
                pub enum $inst_name {
                    $(
                        $op_name
                        (
                            $(RegisterName<$dst_type>,)*
                            $(RegisterName<$src_type>,)*
                            $($meta_type,)*
                        )
                    ),*
                }

                impl $inst_name {
                    pub fn validate(&self, inst_id: usize, pc: usize) -> Result<()> {
                        // TODO: Validate register names are in bounds.
                        #[allow(unused)]
                        match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)*) => {
                                    $(if !matches!($dst_name, _) {
                                        return Err(Error::IllegalOperands { inst_id, pc });
                                    })*
                                },
                            )*
                        }

                        Ok(())
                    }
                }

                impl<'a> GetDeps<'a> for $inst_name {
                    type DispatchedOp = $dispatch_name;
                    type RenameSet = ($(&'a RegisterFile<$reg_kind, $dispatch_name>,)*());

                    fn instruction_dep_idx(
                        &self,
                        rename_set: Self::RenameSet,
                        idx: usize,
                    ) -> Option<ScoreboardEntryRef<Self::DispatchedOp>> {
                        #[allow(unused)]
                        match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)*) => {
                                    $(let $src_name = rename_set.$src_type_id.get_instruction(*$src_name);)*

                                    $crate::dep_idx! {idx, $($src_name)*}
                                },
                            )*
                        }
                    }

                    fn num_deps(
                        &self
                    ) -> usize {
                        #[allow(unused)]
                        match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)*) => {
                                    $crate::rep_len!($($src_name)*)
                                }
                            )*
                        }
                    }
                }

                #[derive(Clone)]
                pub enum $dispatch_name {
                    $(
                        $op_name
                        (
                            $(RobEntryRef<$dst_type>,)*
                            $(RobEntryRef<$src_type>,)*
                            $($meta_type,)*
                        )
                    ),*
                }

                impl std::fmt::Debug for $dispatch_name {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
                        match self {
                            $(Self:: $op_name(..) => write!(f, stringify!($op_name))),*
                        }
                    }
                }

                impl<'a> ToDispatchedOp<'a> for $inst_name {
                    type DispatchedOp = $dispatch_name;
                    type RobEntrySrcs = ($(&'a RegisterFile<$reg_kind, $dispatch_name>,)*());
                    type FreeLists = ($(&'a Receiver<RobId<$reg_kind>>,)*());

                    fn to_dispatched_op(
                        &self,
                        srcs: Self::RobEntrySrcs,
                        scoreboard_entry: ScoreboardEntryRef< $dispatch_name>,
                        instruction_id: usize,
                        pc: usize
                    ) -> $crate::error::Result<Self::DispatchedOp> {
                        let disp_op = match self {
                            $(
                                Self::$op_name($($dst_name,)* $($src_name,)* $($meta_name,)*) => {
                                    // It's important we capture the srcs first, as they should not be renamed.
                                    $(let $src_name = srcs.$src_type_id.map_entry(*$src_name).map(|x| x.clone_immutable()).ok_or(Error::IllegalOperands { inst_id: instruction_id, pc })?;)*
                                    $(let $dst_name =
                                        srcs.$dst_type_id.rename(*$dst_name, &scoreboard_entry);
                                    )*

                                    Self::DispatchedOp::$op_name($($dst_name,)* $($src_name,)* $($meta_name.clone(),)*)
                                },
                            )*
                        };

                        Ok(disp_op)
                    }
                }
            }

            pub use [<$inst_name:snake _internal>]::*;
        }
    };
}

define_op! {
    IsaOp,
    DispatchIsaOp,
    (Register, PtrRegister),

    // Bind input
    [BindReadOnly (dst dst, 1, PtrRegister) (meta id usize) (meta encrypted bool)],

    // Bind output
    [BindReadWrite (dst dst, 1, PtrRegister) (meta id usize) (meta encrypted bool)],

    // Load
    [Load (dst dst, 0, Register) (src src, 1, PtrRegister) (meta width u32)],

    // Load immediate
    [LoadI (dst dst, 0, Register) (meta imm u128) (meta width u32)],

    // Store
    [Store (src dst, 1, PtrRegister) (src src, 0, Register) (meta width u32)],

    // And
    [And (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Or
    [Or (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Multiply a * b and produce the low word of the product.
    [Mul (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Add
    [Add (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Not
    [Not (dst dst, 0, Register) (src src, 0, Register)],

    // Xor
    [Xor (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Bitshift right
    [Shr (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Arithmetic shift right
    [Shra (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Bitshift left
    [Shl (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Rotate right
    [Rotr (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Rotate left
    [Rotl (dst dst, 0, Register) (src src, 0, Register) (src shift, 0, Register)],

    // Add with carry
    [AddC (dst dst, 0, Register) (dst carry_out, 0, Register) (src a, 0, Register) (src b, 0, Register) (src carry_in, 0, Register)],

    // Compute effective address
    [Cea (dst dst, 1, PtrRegister) (src base, 1, PtrRegister) (src offset, 0, Register)],

    // Compute effective address (immediate)
    [Ceai (dst dst, 1, PtrRegister) (src base, 1, PtrRegister) (meta offset u64)],

    // Subtract
    [Sub (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Subract and borrow
    [SubB (dst dst, 0, Register) (dst borrow_out, 0, Register) (src a, 0, Register) (src b, 0, Register) (src borrow_in, 0, Register)],

    // Negate
    [Neg (dst dst, 0, Register) (src src, 0, Register)],

    // Compare equal
    [CmpEq (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than
    [CmpGt (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare greater than or equal
    [CmpGe (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than
    [CmpLt (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Compare less than or equal
    [CmpLe (dst dst, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Casting operations
    [Zext (dst dst, 0, Register) (src src, 0, Register) (meta width u32)],
    [Trunc (dst dst, 0, Register) (src src, 0, Register) (meta width u32)],

    // Branch
    [BranchNonZero (src cond, 0, Register) (meta target u64)],
    [BranchZero (src cond, 0, Register) (meta target u64)],

    // Raw cmux
    [Cmux (dst dst, 0, Register) (src cond, 0, Register) (src a, 0, Register) (src b, 0, Register)],

    // Return
    [Ret]
}
